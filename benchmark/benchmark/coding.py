"""Pure-Python selection of bulk WAVID block size; no Rust process or network.

Model: all-honest, all n dealers, full service of every sampled recovery edge.
Counts exclude local delivery and include bincode envelopes, framing and app ACKs,
but exclude retries, TCP/IP headers and the b-independent WRBC/WRA/Gather/BinAA.
"""
import argparse
import copy
import json
from fractions import Fraction
from functools import lru_cache
from pathlib import Path

from benchmark.config import ConfigError, Policy, NodeParameters, integer, write_json

MODEL = 'honest-full-service-sdc731e-v1'
MIN_BLOCK, MAX_BLOCK = 32, 4096
CHUNK_BYTES = 32768
MAX_FILE_BYTES = 512 * 1024 * 1024


def block_size(value, allow_auto=False):
    if allow_auto and value == 'auto':
        return value
    value = integer(value, 'bulk_block_bytes', MIN_BLOCK, MAX_BLOCK)
    if value % 2:
        raise ConfigError('bulk_block_bytes must be even')
    return value


@lru_cache(maxsize=128)
def circuit_geometry(weights, threshold):
    """Mirror WCSS's Batcher odd-even builder, hash-consing and backward pruning."""
    n, base = len(weights), len(weights) + 2
    total = sum(weights)
    if not 2 <= n <= 512 or min(weights) <= 0 or not 1 <= threshold <= total // 3:
        raise ConfigError('Invalid coding membership/threshold')
    layers = total.bit_length()
    if layers > 4096:
        raise ConfigError('WCSS weight bit layer limit')
    gates, intern = [], {}

    def gate(op, a, b):
        a, b = min(a, b), max(a, b)
        if a == b:
            return a
        if a < 2:
            return (0 if a == 0 else b) if op == 0 else (b if a == 0 else 1)
        key = (op, a, b)
        if key not in intern:
            if len(gates) >= 4_000_000:
                raise ConfigError('WCSS gate limit')
            intern[key] = base + len(gates)
            gates.append((a, b))
        return intern[key]

    @lru_cache(maxsize=None)
    def comparators(width):
        out = []
        def merge(start, size, stride):
            double = 2 * stride
            if double < size:
                merge(start, size, double)
                merge(start + stride, size, double)
                out.extend((i, i + stride) for i in range(start + stride, start + size - stride, double))
            else:
                out.append((start, start + stride))
        def sort(start, size):
            if size > 1:
                sort(start, size // 2)
                sort(start + size // 2, size // 2)
                merge(start, size, 1)
        sort(0, width)
        return out

    offset, carry = (1 << layers) - threshold, []
    for bit in range(layers):
        refs = [i + 2 for i, w in enumerate(weights) if w >> bit & 1] + carry
        if offset >> bit & 1:
            refs.append(1)
        if len(refs) > 1:
            for i, j in comparators(1 << (len(refs) - 1).bit_length()):
                if j < len(refs):
                    a, b = refs[i], refs[j]
                    refs[i], refs[j] = gate(0, a, b), gate(1, a, b)
        carry = refs[-2::-2]
    live = bytearray(base + len(gates))
    live[carry[0] if carry else 0] = 1
    count = 0
    for j in range(len(gates) - 1, -1, -1):
        if live[base + j]:
            a, b = gates[j]
            live[a] = live[b] = 1
            count += 1
    length = 360 + 64 * n + 96 * count
    if length > MAX_FILE_BYTES:
        raise ConfigError('WAVID file size limit')
    return dict(gates=count, nodes=base + count, public_bytes=length)


def log_ratio_upper(n, d):
    z = Fraction(n - d, n + d)
    z2, power, value = z*z, z, Fraction(0)
    for j in range(64):
        value += power / (2*j + 1)
        power *= z2
    return 2 * (value + power / ((1-z2)*129))


@lru_cache(maxsize=128)
def sampling_quotas(weights, threshold, bits):
    n, total = len(weights), sum(weights)
    bits = integer(bits, 'coverage_bits', 1, 256)
    q = n.bit_length() - 1
    x = (log_ratio_upper(2, 1)*(bits+q) + log_ratio_upper(n, 1 << q))*Fraction(3, 2)
    a = (x.numerator + x.denominator - 1) // x.denominator
    quotas = [min(n, (a*n*w + total-1)//total) for w in weights]
    if len(set(weights)) == 1:
        honest = n - (threshold-1)//weights[0]
        rhs = n**honest
        d = next(d for d in range(1, n+1) if (n*(n-d)**honest << bits) <= rhs)
        quotas = [d]*n
    return a, tuple(quotas)


def frontier_count(count, start, length):
    width = 1 << max(1, (count-1).bit_length())
    active, count_out = set(range(width+start, width+start+length)), 0
    while 1 not in active:
        count_out += sum((p ^ 1) not in active for p in active)
        active = {p//2 for p in active}
    return count_out


def proof_bytes(leaves):
    depth = max(1, (leaves-1).bit_length())
    # Proof { lemma: Vec<[u8;32]>, path: Vec<bool> }; leaf and root in lemma.
    return 16 + 32*(depth+2) + depth


def evidence_transport_bound(n, b):
    """Conservative bound for any permitted bulk length and membership of size n."""
    q = (MAX_FILE_BYTES+n*b-1)//(n*b)
    pm,pq = proof_bytes(4*n),proof_bytes(q)
    source = 56+b+pm+pq
    coding = 88+pq+n*(16+b+pm)
    semantic = 121+13*source
    return max(coding,semantic)+61  # sealed receipt/packet envelope (conservative)


def geometry(weights, threshold, coverage_bits):
    weights = tuple(weights)
    c = circuit_geometry(weights, threshold)
    n, total = len(weights), sum(weights)
    counts = [(3*n*w + total-1)//total for w in weights]
    m, start, frontier = sum(counts), 0, []
    for count in counts:
        frontier.append(frontier_count(m, start, count))
        start += count
    a, quotas = sampling_quotas(weights, threshold, coverage_bits)
    return dict(c, parties=n, counts=counts, coded_coordinates=m,
                frontier=frontier, sampling_a=a, quotas=list(quotas))


def cost(g, b):
    b = block_size(b)
    n, m, length = g['parties'], g['coded_coordinates'], g['public_bytes']
    q = (length+n*b-1)//(n*b)
    bundles = [17 + q*(48 + count*b + 32*h) for count, h in zip(g['counts'], g['frontier'])]
    # ProtMsg: InstanceId(Some)=25; Kind tag=4; chunk index=4; Vec length=8.
    # Weighted transport adds 100 B/frame and a 32 B authenticated ACK.
    packets = [v + 173*((v+CHUNK_BYTES-1)//CHUNK_BYTES) for v in bundles]
    opening = 56 + b + proof_bytes(q) + proof_bytes(m)
    receipts = []
    for i in range(n):
        ranges = [(0,72),(104+32*i,32),(104+32*(n+i+2),32)]
        blocks = {block for start,size in ranges for block in range(start//b,(start+size+b-1)//b)}
        receipts.append(120 + len(blocks)*opening)
    d = sum(g['quotas'])
    disperse = (n-1)*sum(packets)
    retrieve = sum((d-quota)*packet for quota,packet in zip(g['quotas'],packets))
    # Private Packet + AES-GCM sealed wrapper + frame/ACK = 193 bytes.
    private = (n-1)*sum(r+193 for r in receipts)
    edges = (n-1)*d
    fixed = dict(retrieve_requests=193*edges, recovery_tokens=261*edges, success_terminals=257*edges)
    components = dict(bulk_disperse=disperse, bulk_retrieve=retrieve, private_receipts=private, **fixed)
    return dict(block_bytes=b, stripes=q, bundle_bytes=bundles, receipt_bytes=receipts,
                source_opening_bytes=opening, components=components,
                modeled_bytes=sum(components.values()))


def select(weights, threshold, coverage_bits=40, candidates=None):
    g = geometry(tuple(weights), threshold, coverage_bits)
    candidates = list(range(MIN_BLOCK, MAX_BLOCK+1, 2)) if candidates is None else list(candidates)
    if not candidates:
        raise ConfigError('Empty block-size candidate set')
    candidates = sorted(set(block_size(b) for b in candidates))
    requested_count = len(candidates)
    candidates = [b for b in candidates if evidence_transport_bound(g['parties'],b) <= 1024*1024-256]
    if not candidates:
        raise ConfigError('No candidate can transport all required fault evidence')
    best = min((cost(g,b) for b in candidates), key=lambda c:(c['modeled_bytes'],c['block_bytes']))
    baseline = cost(g,32)
    return dict(model=MODEL, objective='honest-full-service',
                metric='selected-services TCP payload plus app ACKs, no retransmissions',
                excluded=['local delivery','TCP/IP headers','retransmissions','synchronizer',
                          'WRBC/WRA/WGather/WBinAA (independent of bulk block size)'],
                assumptions=['all parties honest','all n dealers complete',
                             'all sampled retrieval edges fully served; no STOP truncation',
                             'control WRBC block size remains 32 bytes'],
                optimality='global minimum of this static model over the listed even candidate range; ties choose smaller block',
                candidate_count=len(candidates), rejected_transport_candidates=requested_count-len(candidates),
                admissibility='even 32..4096; bounded honest fault evidence fits SDC frame', candidates=candidates, geometry=g,
                selected=best, baseline_32=baseline,
                modeled_reduction_percent=100*(baseline['modeled_bytes']-best['modeled_bytes'])/baseline['modeled_bytes'])


def resolve_parameters(bench, node):
    params = copy.deepcopy(node.json)
    spec = bench.json.get('bulk_block_bytes')
    spec = params['bulk_block_bytes'] if spec is None else spec
    report = None
    if spec == 'auto':
        report = select(bench.weights, bench.threshold, params['coverage_bits'])
        spec = report['selected']['block_bytes']
    params['bulk_block_bytes'] = block_size(spec)
    if evidence_transport_bound(bench.nodes[0], params['bulk_block_bytes']) > 1024*1024-256:
        raise ConfigError('bulk_block_bytes makes fault evidence exceed transport frame limit')
    return NodeParameters(params), report


def optimize_policy(policy, output, report=None):
    policies = Policy(policy)
    data = copy.deepcopy(policies.json)
    reports = []
    for raw,case in zip(data['cases'],policies.cases):
        result = select(case.weights,case.threshold,policies.node_parameters.json['coverage_bits'])
        raw['bulk_block_bytes'] = result['selected']['block_bytes']
        reports.append(dict(name=case.name, **result))
    report = Path(report) if report else Path(output).with_suffix('.coding.json')
    if Path(output).resolve() in (Path(policy).resolve(), report.resolve()) or report.resolve() == Path(policy).resolve():
        raise ConfigError('Input policy, output policy and report must be distinct files')
    write_json(output,data)
    write_json(report,dict(model=MODEL,source_policy=str(Path(policy).resolve()),cases=reports))
    return dict(policy=str(Path(output).resolve()),report=str(report.resolve()),
                selections=[dict(name=r['name'],block_bytes=r['selected']['block_bytes'],modeled_reduction_percent=r['modeled_reduction_percent']) for r in reports])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--report')
    args=parser.parse_args()
    print(json.dumps(optimize_policy(args.policy,args.output,args.report),indent=2))

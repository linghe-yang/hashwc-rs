"""Offline, reproducible policies derived from a pinned Aptos validator snapshot.

No live network reads occur when generating policies or running benchmarks.
"""
import argparse
import hashlib
import json
import math
import subprocess
import tempfile
from fractions import Fraction
from functools import reduce
from pathlib import Path

from benchmark.config import LocalCommittee, Policy, write_json
from benchmark.utils import PathMaker

NODES = [4, 16, 31, 46, 64]
DEFAULT_SNAPSHOT = 'data/aptos-mainnet-v7479751174'
SEED = 20261004
NORMALIZED_MEAN = 3_000_000


def load_snapshot(directory):
    directory = Path(directory)
    manifest = json.loads((directory/'snapshot.json').read_text())
    raw = (directory/'validator-set.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest['sha256']:
        raise ValueError('Validator snapshot digest mismatch')
    resource = json.loads(raw)
    ledger = json.loads((directory/'ledger-info.json').read_text())
    reconfiguration = json.loads((directory/'reconfiguration.json').read_text())
    if (manifest['network'] != 'mainnet' or manifest['chain_id'] != 1 or ledger['chain_id'] != 1
            or ledger['ledger_version'] != manifest['ledger_version']
            or ledger['epoch'] != manifest['epoch']
            or reconfiguration['data']['epoch'] != manifest['epoch']
            or resource['type'] != '0x1::stake::ValidatorSet'):
        raise ValueError('Inconsistent snapshot network/version/epoch')
    data = resource['data']
    # A pending departure still votes this epoch; a pending join does not.
    entries = data['active_validators'] + data['pending_inactive']
    validators = sorted(
        [dict(address='0x'+x['addr'][2:].zfill(64),
              weight=int(x['voting_power'])) for x in entries],
        key=lambda x: (x['weight'], x['address']))
    if (len({x['address'] for x in validators}) != len(validators)
            or not validators or any(x['weight'] <= 0 for x in validators)
            or len(validators) != manifest['validator_count']
            or sum(x['weight'] for x in validators) != int(data['total_voting_power'])
            or data['total_voting_power'] != manifest['total_voting_power']):
        raise ValueError('Invalid validator identities/weights/total')
    return manifest, validators


def quantile_masses(weights, n):
    """Integrate the empirical quantile function over n equal rank intervals.

    Integer overlap lengths avoid floats, random sampling, and lost tail mass.
    The returned masses sum to n * sum(source weights).
    """
    if n < 2 or not weights or any(type(w) is not int or w <= 0 for w in weights):
        raise ValueError('Positive source weights and n >= 2 required')
    weights = sorted(weights)
    m = len(weights)
    return [sum(max(0, min((i+1)*m, (j+1)*n)-max(i*m, j*n))*w
                for j, w in enumerate(weights)) for i in range(n)]


def apportion(masses, total):
    """Hamilton largest remainder, ties by party ID; exact positive total."""
    if not masses or any(type(x) is not int or x <= 0 for x in masses) or total < len(masses):
        raise ValueError('Invalid apportionment')
    denominator = sum(masses)
    divided = [divmod(x*total, denominator) for x in masses]
    weights = [x[0] for x in divided]
    missing = total-sum(weights)
    for i in sorted(range(len(weights)), key=lambda i: (-divided[i][1], i))[:missing]:
        weights[i] += 1
    if min(weights) < 1:
        raise ValueError('Total is too small to preserve the distribution without zero weights')
    return weights


def dense_weights(n, total, seed=SEED):
    # Independent 512-bit scores in [2^511, 2^512); no repeated common multiplier.
    scores = [(1 << 511) + (int.from_bytes(hashlib.shake_256(
        'whcc/dense-weight/v1/{}/{}/{}'.format(seed, n, i).encode()).digest(64), 'big') >> 1)
              for i in range(n)]
    weights = apportion(scores, total)
    # Prevent an accidental shared divisor from defining a trivial scaled policy.
    for _ in range(1024):
        if reduce(math.gcd, weights) == 1:
            return weights
        if weights[1] <= 1:
            break
        weights[0] += 1
        weights[1] -= 1
    raise ValueError('Could not construct coprime dense weights')


def stress_ids(weights, budget):
    """Maximum affordable identity count, then deterministic improving swaps.

    The lightest-prefix count is globally optimal. Weight is only one-swap
    locally optimal; this is NOT the NP-hard maximum-weight subset claim.
    """
    order = sorted(range(len(weights)), key=lambda i: (weights[i], i))
    chosen, total = set(), 0
    for i in order:
        if total + weights[i] > budget:
            break
        chosen.add(i)
        total += weights[i]
    while chosen:
        swaps = [(weights[j]-weights[i], i, j)
                 for i in sorted(chosen) for j in range(len(weights)) if j not in chosen
                 and 0 < weights[j]-weights[i] <= budget-total]
        if not swaps:
            break
        gain, old, new = min(swaps, key=lambda item: (-item[0], item[1], item[2]))
        chosen.remove(old)
        chosen.add(new)
        total += gain
    return sorted(chosen)


def distribution(weights):
    n, total = len(weights), sum(weights)
    ordered = sorted(weights)
    gini = Fraction(sum((2*i-n-1)*w for i, w in enumerate(ordered, 1)), n*total)
    return dict(total_weight=str(total), weight_bits=total.bit_length(),
                min_weight=str(min(weights)), max_weight=str(max(weights)),
                max_share=float(Fraction(max(weights), total)), gini=float(gini),
                gcd=str(reduce(math.gcd, weights)), set_bits=sum(bin(w).count('1') for w in weights))


def build_policies(manifest, validators):
    source = [x['weight'] for x in validators]
    snapshot = {k: manifest[k] for k in ['network', 'epoch', 'ledger_version', 'timestamp', 'sha256', 'source']}
    # Within <3 octa of the empirical mean; ensures T/W is exactly 1/3 for all n.
    native_mean = 3*(sum(source)//(3*len(source)))
    families, report = {}, dict(snapshot=snapshot, source=distribution(source),
                               source_count=len(source), native_mean=str(native_mean), cases=[])
    for family in ['aptos-native', 'aptos-normalized', 'npow']:
        cases = []
        profiles = ['uniform-npow', 'dense-npow', 'aptos-npow'] if family == 'npow' else ['aptos-quantile']
        experiment = '{}-v{}-v1'.format(family, manifest['ledger_version'])
        for profile in profiles:
            for n in NODES:
                total = n**n if family == 'npow' else n*(native_mean if family == 'aptos-native' else NORMALIZED_MEAN)
                if profile == 'uniform-npow':
                    weights = [total//n]*n
                    method, source_snapshot = 'equal-npow', {}
                elif profile == 'dense-npow':
                    weights = dense_weights(n, total)
                    method, source_snapshot = 'shake256-dense-npow', dict(seed=SEED)
                else:
                    weights = apportion(quantile_masses(source, n), total)
                    method, source_snapshot = 'aptos-quantile-integral-hamilton', dict(snapshot=snapshot)
                parameters = dict(total_rule='n^n' if family == 'npow' else 'fixed-mean',
                                  threshold_rule='floor(W/3)', rounding='largest-remainder-party-id')
                if family != 'npow':
                    parameters['mean_weight'] = str(total//n)
                if profile.startswith('aptos'):
                    parameters['source_sha256'] = manifest['sha256']
                    parameters['rank_bins'] = 'equal-width-quantile-integrals'
                if profile == 'dense-npow':
                    parameters['score_bits'] = 512
                    parameters['seed'] = SEED
                threshold, budget = total//3, total//3-1
                adversaries = stress_ids(weights, budget)
                if not adversaries:
                    raise ValueError('No affordable Byzantine party')
                for stress in [False, True]:
                    ids = adversaries if stress else []
                    name = '{}-n{}-{}'.format(profile if family == 'npow' else family, n, 'stress' if stress else 'honest')
                    selected = sum(weights[i] for i in ids)
                    case = dict(name=name, nodes=n, weights=[str(w) for w in weights],
                                threshold=str(threshold), fault_weight_threshold=str(budget), byzantine_nodes=ids,
                                metadata=dict(weight_profile=dict(id=profile, parameters=parameters), weight_scale=1,
                                    generation=dict(method=method, version=1, **source_snapshot,
                                        input=dict(nodes=n, target_total=str(total), source_count=len(source) if profile.startswith('aptos') else None)),
                                    fault_selection=dict(method='max-count-one-swap-v1' if stress else 'none',
                                        budget=str(budget), selected_weight=str(selected), selected_count=len(ids),
                                        ties='weight-then-id; greatest-positive-swap; ascending-old-new-id')))
                    cases.append(case)
                    report['cases'].append(dict(policy=family, name=name, nodes=n, profile=profile,
                        **distribution(weights), threshold=str(threshold), fault_budget=str(budget),
                        corrupted_weight=str(selected), corrupted_count=len(ids), byzantine_nodes=ids,
                        budget_gap=str(budget-selected), corrupt_fraction=float(Fraction(selected, total))))
        families[family] = dict(metadata=dict(experiment_id=experiment, experiment_axis='nodes'),
            bench_params=dict(protocol='whcc', faults=0, runs=3, duration=1800, startup_timeout=600),
            node_params=dict(output_bits=128, rounding_bits=64, coverage_bits=40), cases=cases)
    return families, report


def plot_config(family, policy):
    return dict(results=['results'],
        filters=dict(experiment_id=[policy['metadata']['experiment_id']], protocol=['whcc'],
                     weight_profile=sorted({c['metadata']['weight_profile']['id'] for c in policy['cases']}),
                     fault_case=['honest', 'recovery-stress'], output_bits=[128], rounding_bits=[64], coverage_bits=[40]),
        series=['weight_profile', 'fault_case'], metrics=['latency_ms', 'avg_sent_bytes_per_honest_party'],
        min_runs=3, error_bar='min_max', formats=['pdf', 'svg', 'png'], output='plots/weights-'+family,
        charts=[dict(name='weights-'+family, x='nodes', values=NODES,
                     weight_control='n_pow_n' if family == 'npow' else 'fixed_mean')])


def check_rust(paths, binary):
    """Prepare real external Node JSON and inspect circuits; never bind sockets."""
    checked = {}
    for path in paths:
        policy = Policy(path)
        for bench in policy.cases:
            key = (tuple(bench.weights), bench.threshold)
            if key not in checked:
                with tempfile.TemporaryDirectory(prefix='whcc-weight-check-') as temporary:
                    LocalCommittee(bench, policy.node_parameters).print(temporary)
                    result = subprocess.run([str(binary), 'check-config',
                        '--config', str(Path(temporary)/PathMaker.key_file(0)),
                        '--parameters', str(Path(temporary)/PathMaker.parameters_file())],
                        check=True, capture_output=True, text=True, timeout=180)
                    checked[key] = json.loads(result.stdout)
            yield bench.name, checked[key]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', default=DEFAULT_SNAPSHOT, help='Snapshot directory relative to benchmark/')
    parser.add_argument('--check-rust', type=Path, help='Optional compiled node binary, validates circuits without a distributed run')
    args = parser.parse_args()
    base = PathMaker.BENCHMARK
    manifest, validators = load_snapshot(base/args.snapshot)
    families, report = build_policies(manifest, validators)
    paths = []
    for family, policy in families.items():
        path = base/'policies'/('weights-'+family+'.json')
        write_json(path, policy)
        write_json(base/'plot-configs'/('weights-'+family+'.json'), plot_config(family, policy))
        Policy(path)  # Validate numbers, bounds, fault weights, IDs, and all ports.
        paths.append(path)
    if args.check_rust:
        binary = args.check_rust.resolve()
        inspections = dict(check_rust(paths, binary))
        for row in report['cases']:
            row['rust_check'] = inspections[row['name']]
        report['rust_binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        source = base.parent/'consensus/wcss/src/protocol/circuit.rs'
        report['circuit_source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
    write_json(base/'data/weight-study-report.json', report)
    print('Generated {} policies / {} cases; no distributed experiments launched.'.format(len(paths), len(report['cases'])))
    for path in paths:
        print(path)


if __name__ == '__main__':
    main()

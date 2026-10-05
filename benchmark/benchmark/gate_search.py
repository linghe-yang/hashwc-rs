"""Search W=n^n policies against the production Rust circuit builder, offline."""
import argparse
import copy
import hashlib
import json
import platform
import random
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from benchmark.config import Policy, write_json
from benchmark.utils import PathMaker
from benchmark.weight_policies import NODES, distribution, stress_ids

SEED = 20261005
DENSITIES = [25, 40, 50, 60, 70, 80, 85, 90, 93, 95, 97, 99]


def weight_id(weights):
    return hashlib.sha256(','.join(map(str, weights)).encode()).hexdigest()


def column_weights(n, total, density, rng):
    """Choose binary column populations while preserving the exact integer sum.

    If the remaining target is R, the column population c must have R's parity;
    the remaining target for the next column becomes (R-c)//2.
    """
    weights, remainder, bit = [0]*n, total, 0
    while remainder:
        wanted = sum(rng.randrange(100) < density for _ in range(n))
        choices = range(remainder & 1, min(n, remainder)+1, 2)
        count = min(choices, key=lambda c: (abs(c-wanted), c))
        for i in rng.sample(range(n), count):
            weights[i] |= 1 << bit
        remainder = (remainder-count)//2
        bit += 1
    return weights


def mutate(weights, rng, iteration):
    """Sum-preserving transfers, bit exchanges, and changes to party ordering."""
    out = weights[:]
    n = len(out)
    mode = iteration % 4
    if mode == 0:
        if rng.randrange(3) == 0:
            rng.shuffle(out)
        else:
            i, j = rng.sample(range(n), 2)
            out[i], out[j] = out[j], out[i]
    elif mode == 1:
        # Swap selected unequal bits; preserves each column's population.
        for _ in range(rng.choice([1, 2, 4, 8])):
            i, j = rng.sample(range(n), 2)
            different = out[i] ^ out[j]
            if not different:
                continue
            if rng.randrange(2):
                positions = [b for b in range(different.bit_length()) if (different >> b) & 1]
                mask = 1 << rng.choice(positions)
            else:
                mask = different & rng.getrandbits(different.bit_length())
            a, b = out[i] ^ mask, out[j] ^ mask
            if a > 0 and b > 0:
                out[i], out[j] = a, b
    else:
        # Changes column populations, including carry/borrow patterns.
        for _ in range(rng.choice([1, 2, 4])):
            i, j = rng.sample(range(n), 2)
            if out[j] <= 1:
                continue
            bit = rng.randrange((out[j]-1).bit_length())
            amount = (1 << bit) if mode == 2 else rng.randrange(1, min(out[j], (1 << bit)+1))
            if amount < out[j]:
                out[i] += amount
                out[j] -= amount
    return out


class Oracle:
    def __init__(self, binary):
        self.process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        text=True, bufsize=1)
    def count(self, weights, threshold):
        self.process.stdin.write(' '.join(map(str, [threshold]+weights))+'\n')
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError('Rust circuit oracle stopped')
        return json.loads(line)
    def close(self):
        self.process.stdin.close()
        self.process.stdout.close()
        if self.process.wait(timeout=30) != 0:
            raise RuntimeError('Rust circuit oracle failed')


def search(n, binary, baseline_cases, samples, steps, seed, output, threshold=None):
    rng = random.Random(seed+n*1009)
    total = n**n
    threshold = total//3 if threshold is None else threshold
    if type(threshold) is not int or not 0 < threshold <= total//3:
        raise ValueError('Require 0 < T <= W/3')
    oracle, cache, elite, improvements, baselines = Oracle(binary), {}, [], [], {}
    trace = output/('n{}.jsonl'.format(n))
    started = time.monotonic()
    with trace.open('w') as log:
        def evaluate(weights, origin):
            if len(weights) != n or min(weights) <= 0 or sum(weights) != total:
                return None
            identity = weight_id(weights)
            if identity in cache:
                return cache[identity]
            score = oracle.count(weights, threshold)
            row = dict(evaluation=len(cache)+1, origin=origin, weight_sha256=identity, **score)
            log.write(json.dumps(row, sort_keys=True)+'\n')
            log.flush()
            candidate = dict(row, weights=weights[:])
            cache[identity] = candidate
            if not elite or score['gates'] > elite[0]['gates']:
                improvements.append(dict(candidate, weights=[str(w) for w in weights]))
            elite.append(candidate)
            elite.sort(key=lambda c: (-c['gates'], c['weight_sha256']))
            del elite[12:]
            if len(cache) % 32 == 0:
                print('n={} evaluated={} best={} elapsed={:.1f}s'.format(
                    n, len(cache), elite[0]['gates'], time.monotonic()-started), flush=True)
            return candidate

        try:
            for case in baseline_cases:
                if case['nodes'] == n and not case['byzantine_nodes']:
                    weights = list(map(int, case['weights']))
                    name = case['metadata']['weight_profile']['id']
                    baselines[name] = evaluate(weights, 'baseline/'+name)['gates']
            for i in range(samples):
                density = DENSITIES[i % len(DENSITIES)]
                weights = column_weights(n, total, density, rng)
                evaluate(weights, 'columns/density={}/sample={}'.format(density, i))
            # Multi-start elitist search. Occasional lower-ranked parents preserve diversity.
            for i in range(steps):
                parent = elite[0] if i % 3 else rng.choice(elite)
                weights = mutate(parent['weights'], rng, i)
                evaluate(weights, 'mutate/{}/parent={}'.format(i, parent['weight_sha256']))
            best = elite[0]
            result = dict(nodes=n, total_weight=str(total), threshold=str(threshold), seed=seed+n*1009,
                evaluated=len(cache), proposed_samples=samples, proposed_mutations=steps,
                elapsed_seconds=time.monotonic()-started, baselines=baselines,
                gates=best['gates'], and_gates=best['and_gates'], or_gates=best['or_gates'],
                weight_sha256=best['weight_sha256'], weights=[str(w) for w in best['weights']],
                distribution=distribution(best['weights']), best_origin=best['origin'],
                improvements=improvements, trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest())
            write_json(output/('n{}-best.json'.format(n)), result)
            print('DONE n={} gates={} evaluated={}'.format(n, best['gates'], len(cache)), flush=True)
            return result
        finally:
            oracle.close()


def make_policy(results, provenance):
    cases = []
    parameters = dict(total_rule='n^n', threshold_rule='floor(W/3)', objective='production-pruned-gate-count',
                      algorithm='binary-column-elite-v1', seed=SEED, search_provenance=provenance)
    for row in sorted(results, key=lambda r: r['nodes']):
        n, weights = row['nodes'], list(map(int, row['weights']))
        total, threshold = sum(weights), int(row['threshold'])
        budget = threshold-1
        for stress in [False, True]:
            ids = stress_ids(weights, budget) if stress else []
            cases.append(dict(name='gate-search-n{}-{}'.format(n, 'stress' if stress else 'honest'),
                nodes=n, weights=row['weights'], threshold=str(threshold),
                fault_weight_threshold=str(budget), byzantine_nodes=ids,
                metadata=dict(weight_profile=dict(id='gate-search-npow', parameters=parameters),
                    weight_scale=1, generation=dict(method='binary-column-elite', version=1, seed=SEED,
                        input=dict(nodes=n, target_total=str(total), evaluated=row['evaluated'],
                                   weight_sha256=row['weight_sha256'], gates=row['gates'],
                                   best_origin=row['best_origin'])),
                    fault_selection=dict(method='max-count-one-swap-v1' if stress else 'none',
                        budget=str(budget), selected_weight=str(sum(weights[i] for i in ids)),
                        selected_count=len(ids), ties='weight-then-id; greatest-positive-swap; ascending-old-new-id'))))
    return dict(metadata=dict(experiment_id='gate-search-npow-20261005-v1', experiment_axis='nodes'),
        bench_params=dict(protocol='whcc', faults=0, runs=3, duration=1800, startup_timeout=600),
        node_params=dict(output_bits=128, rounding_bits=64, coverage_bits=40), cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle', type=Path, default=PathMaker.BENCHMARK.parent/'target/release/examples/count_gates')
    parser.add_argument('--nodes', type=int, nargs='+', default=NODES)
    parser.add_argument('--samples', type=int, default=480)
    parser.add_argument('--steps', type=int, default=4096)
    parser.add_argument('--workers', type=int, default=3)
    parser.add_argument('--output', type=Path, default=PathMaker.BENCHMARK/'data/gate-search')
    args = parser.parse_args()
    if not args.nodes or len(set(args.nodes)) != len(args.nodes) or any(n not in NODES for n in args.nodes):
        parser.error('nodes must be distinct members of {}'.format(NODES))
    if args.samples < 1 or args.steps < 0 or args.workers < 1:
        parser.error('invalid search budget')
    base = PathMaker.BENCHMARK
    args.output.mkdir(parents=True, exist_ok=True)
    baseline_path = base/'policies/weights-npow.json'
    baselines = json.loads(baseline_path.read_text())['cases']
    files = [Path(__file__), base.parent/'consensus/wcss/src/protocol/circuit.rs',
             base.parent/'consensus/wcss/examples/count_gates.rs', baseline_path, args.oracle.resolve()]
    provenance = {str(p.resolve().relative_to(base.parent)) if base.parent in p.resolve().parents else str(p):
                  hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(search, n, args.oracle.resolve(), baselines, args.samples, args.steps, SEED, args.output)
                   for n in args.nodes]
        results = [f.result() for f in futures]
    report = dict(schema_version=1, objective='maximize gates after production simplification and pruning',
                  constraints='positive integer weights; W=n^n; T=floor(W/3)',
                  optimality='heuristic best found, no global optimality claim',
                  seed=SEED, python=platform.python_version(), samples=args.samples, steps=args.steps,
                  provenance=provenance, results=results)
    write_json(args.output/'report.json', report)
    policy = make_policy(results, provenance)
    path = base/'policies/weights-gate-search.json'
    write_json(path, policy)
    Policy(path)
    for n in args.nodes:
        single = copy.deepcopy(policy)
        single['cases'] = [c for c in single['cases'] if c['nodes'] == n]
        write_json(base/'policies/gate-search'/('n{}.json'.format(n)), single)
    plot = dict(results=['results'], filters=dict(experiment_id=[policy['metadata']['experiment_id']],
        protocol=['whcc'], weight_profile=['gate-search-npow'], fault_case=['honest', 'recovery-stress']),
        series=['weight_profile', 'fault_case'], metrics=['latency_ms','avg_sent_bytes_per_honest_party'],
        min_runs=3, error_bar='min_max', formats=['pdf','svg','png'], output='plots/weights-gate-search',
        charts=[dict(name='gate-search', x='nodes', values=sorted(args.nodes), weight_control='n_pow_n')])
    write_json(base/'plot-configs/weights-gate-search.json', plot)
    print('Saved {}. No distributed benchmark was started.'.format(path), flush=True)


if __name__ == '__main__':
    main()

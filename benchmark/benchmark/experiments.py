"""Reproducible, small scalability matrix; no network snapshot is fabricated."""
from benchmark.config import write_json
from benchmark.utils import PathMaker


def max_corruption(weights, budget):
    """Exact subset sum: maximum weight, then most IDs, then lexicographic IDs."""
    if len(weights) > 20:
        raise ValueError('Exact selector limited to 20 parties; provide a researched policy for larger cases')
    states = {0: ()}
    for party, weight in enumerate(weights):
        for total, ids in list(states.items()):
            new_total, candidate = total + weight, ids + (party,)
            if new_total > budget:
                continue
            previous = states.get(new_total)
            if previous is None or len(candidate) > len(previous) or (len(candidate) == len(previous) and candidate < previous):
                states[new_total] = candidate
    total = max(states)
    return list(states[total])


def scalability_policy():
    cases = []
    for n in [4, 10, 16]:
        for profile in ['uniform', 'bimodal']:
            base = [6]*n if profile == 'uniform' else [3]*(n//2)+[9]*(n//2)
            for scale in [1, 10, 100]:
                weights = [w*scale for w in base]
                threshold, budget = 2*n*scale, (2*n-1)*scale
                for adversarial in [False, True]:
                    ids = max_corruption(weights, budget) if adversarial else []
                    cases.append(dict(name='{}-n{}-s{}-{}'.format(profile, n, scale, 'stress' if adversarial else 'honest'),
                        nodes=n, weights=weights, threshold=threshold, fault_weight_threshold=budget, byzantine_nodes=ids,
                        metadata=dict(weight_profile=dict(id=profile, parameters=dict(base_mean=6,
                            relative_weights=[1] if profile == 'uniform' else [0.5, 1.5], proportions=[1] if profile == 'uniform' else [0.5, 0.5])),
                            weight_scale=scale, generation=dict(method='fixed-profile', version=1, input=dict(base_weights=base, scale=scale)),
                            fault_selection=dict(method='max-weight-then-count-v1' if adversarial else 'none',
                                budget=str(budget), selected_weight=str(sum(weights[i] for i in ids)), selected_count=len(ids),
                                ties='lexicographically-smallest'))))
    return dict(metadata=dict(experiment_id='scalability-20261004-v1'),
                bench_params=dict(protocol='whcc', faults=0, runs=3, duration=180, startup_timeout=60),
                node_params=dict(output_bits=128, rounding_bits=64, coverage_bits=40), cases=cases)


def plot_config():
    return dict(results=['results'], filters=dict(experiment_id=['scalability-20261004-v1'], protocol=['whcc'],
                    weight_profile=['uniform', 'bimodal'], fault_case=['honest', 'recovery-stress'], output_bits=[128],
                    rounding_bits=[64], coverage_bits=[40]),
                series=['weight_profile', 'fault_case'], metrics=['latency_ms', 'avg_sent_bytes_per_honest_party'],
                error_bar='min_max', min_runs=3, formats=['pdf', 'svg', 'png'], output='plots/scalability',
                charts=[dict(name='party-scalability', x='nodes', values=[4,10,16], filters=dict(weight_scale=[1]), xscale='linear')]+
                       [dict(name='weight-scalability-n{}'.format(n), x='weight_scale', values=[1,10,100],
                             filters=dict(nodes=[n]), xscale='log') for n in [4,10,16]])


if __name__ == '__main__':
    write_json(PathMaker.BENCHMARK/'policies/scalability.json', scalability_policy())
    write_json(PathMaker.BENCHMARK/'plot-configs/scalability.json', plot_config())

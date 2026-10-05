"""Controlled party/weight scalability matrix, independent of protocol execution."""
import copy
from pathlib import Path

from benchmark.config import ConfigError, Policy, integer, write_json
from benchmark.generate import read_pool
from benchmark.utils import PathMaker
from benchmark.weight_policies import apportion, distribution, quantile_masses, stress_ids

PROFILES = ['uniform', 'near-uniform', 'heavy-tail', 'aptos']
DEFAULT_NODES = [4, 16, 31, 46, 64]
DEFAULT_SCALES = [1, 10, 100]


def integers(value, name, minimum=1):
    values = value.split(',') if isinstance(value, str) else value
    if not isinstance(values, list) or not values:
        raise ConfigError(name+' needs a nonempty list')
    values = [integer(v, name, minimum) for v in values]
    if len(set(values)) != len(values):
        raise ConfigError(name+' must be distinct')
    return sorted(values)


def matrix(nodes=DEFAULT_NODES, scales=DEFAULT_SCALES, mean_weight=300, runs=3,
           fault_case='both', snapshot='data/aptos-mainnet-v7479751174',
           experiment_id='controlled-20261005-v1', profiles=PROFILES):
    nodes, scales = integers(nodes, 'nodes', 4), integers(scales, 'scales')
    if max(nodes) > 512:
        raise ConfigError('At most 512 parties')
    mean_weight, runs = integer(mean_weight, 'mean_weight', 6), integer(runs, 'runs', 1)
    if mean_weight % 6:
        raise ConfigError('mean_weight must be a multiple of 6 (fixed T/W and coprime near-uniform base)')
    profiles = profiles.split(',') if isinstance(profiles, str) else list(profiles)
    if not profiles or len(set(profiles)) != len(profiles) or any(p not in PROFILES for p in profiles):
        raise ConfigError('Unknown or repeated weight profile')
    if fault_case not in ('honest', 'stress', 'both'):
        raise ConfigError('fault_case must be honest, stress, or both')
    if not isinstance(experiment_id, str) or not experiment_id.strip():
        raise ConfigError('experiment_id is required')
    roles = [False, True] if fault_case == 'both' else [fault_case == 'stress']
    base = PathMaker.BENCHMARK
    pool, pool_info, snapshot_info, _ = read_pool(base/snapshot) if 'aptos' in profiles else (None, None, None, None)
    references = dict(uniform=[1], **{'near-uniform': [mean_weight-1, mean_weight+1],
                                   'heavy-tail': [10]*99+[110], 'aptos': pool})
    cases, diagnostics = [], []
    for n in nodes:
        for profile in profiles:
            reference = references[profile]
            weights = apportion(quantile_masses(reference, n), mean_weight*n)
            threshold, budget = mean_weight*n//3, mean_weight*n//3-1
            if profile == 'heavy-tail' and max(weights) > budget:
                raise ConfigError('Heavy-tail profile violates the single-party fault budget')
            ids = stress_ids(weights, budget) if True in roles else []
            if True in roles and not ids:
                raise ConfigError('No affordable Byzantine party')
            params = dict(base_mean=mean_weight, sampling='quantile-integral-hamilton',
                          reference_weights=reference if profile != 'aptos' else None)
            if profile == 'aptos':
                params['pool_sha256'] = pool_info['sha256']
            for scale in scales:
                current, t, f = [w*scale for w in weights], threshold*scale, budget*scale
                facts = distribution(current)
                for stress in roles:
                    byz = ids if stress else []
                    generation = dict(method='controlled-quantile-scale', version=1,
                        input=dict(base_weights=list(map(str, weights)), scale=scale, total_cap=str(mean_weight*n*scale),
                                   base_threshold=str(threshold), base_fault_budget=str(budget),
                                   pool=pool_info if profile == 'aptos' else None))
                    if profile == 'aptos' and snapshot_info:
                        generation['snapshot'] = snapshot_info
                    name = '{}-n{}-s{}-{}'.format(profile, n, scale, 'stress' if stress else 'honest')
                    cases.append(dict(name=name, nodes=n, weights=list(map(str, current)),
                        threshold=str(t), fault_weight_threshold=str(f), byzantine_nodes=byz,
                        metadata=dict(weight_profile=dict(id=profile, parameters=params), weight_scale=scale,
                            generation=generation,
                            fault_selection=dict(method='max-count-one-swap-v1' if stress else 'none',
                                budget=str(f), selected_weight=str(sum(current[i] for i in byz)),
                                selected_count=len(byz), ties='weight-then-id; greatest-positive-swap; ascending-old-new-id'))))
                    diagnostics.append(dict(name=name, nodes=n, scale=scale, profile=profile, **facts,
                        threshold=str(t), fault_budget=str(f), corrupted_weight=str(sum(current[i] for i in byz)),
                        byzantine_nodes=byz, weights=list(map(str, current))))
    policy = dict(metadata=dict(experiment_id=experiment_id),
        bench_params=dict(protocol='whcc', faults=0, runs=runs, duration=1800, startup_timeout=600),
        node_params=dict(output_bits=128, rounding_bits=64, coverage_bits=40), cases=cases)
    plot = dict(results=['results'], filters=dict(experiment_id=[experiment_id], protocol=['whcc'],
        weight_profile=profiles, fault_case=['recovery-stress' if s else 'honest' for s in roles],
        output_bits=[128], rounding_bits=[64], coverage_bits=[40]),
        series=['weight_profile', 'fault_case'], metrics=['latency_ms', 'avg_sent_bytes_per_honest_party'],
        min_runs=runs, error_bar='min_max', formats=['pdf','svg','png'], output='plots/controlled-scalability',
        charts=[dict(name='party-scale-{}'.format(s), x='nodes', values=nodes, filters=dict(weight_scale=[s]), yscale='log')
                for s in scales]+
               [dict(name='weight-n{}'.format(n), x='total_weight', values=[mean_weight*n*s for s in scales],
                     filters=dict(nodes=[n]), xscale='log') for n in nodes])
    report = dict(experiment_id=experiment_id, nodes=nodes, scales=scales, mean_weight=mean_weight,
                  runs=runs, cases=len(cases), total_runs=len(cases)*runs, profiles=profiles,
                  total_cap_rule='W = mean_weight * nodes * scale',
                  fault_budget_rule='F = (mean_weight * nodes / 3 - 1) * scale',
                  note='gcd=1 applies only to the near-uniform base; scaled weights retain exact ratios',
                  configurations=diagnostics)
    return policy, plot, report


def write_matrix(output='policies/controlled-scalability.json', plot_output='plot-configs/controlled-scalability.json', **kwargs):
    policy, plot, report = matrix(**kwargs)
    output, plot_output = Path(output), Path(plot_output)
    write_json(output, policy)
    Policy(output)
    from benchmark.plot import Ploter
    Ploter.validate(plot)
    write_json(plot_output, plot)
    write_json(output.with_suffix('.matrix.json'), report)
    for n in report['nodes']:
        single = copy.deepcopy(policy)
        single['cases'] = [c for c in single['cases'] if c['nodes'] == n]
        write_json(output.parent/output.stem/('n{}.json'.format(n)), single)
    return dict(policy=str(output.resolve()), plot=str(plot_output.resolve()),
                cases=report['cases'], runs=report['total_runs'])

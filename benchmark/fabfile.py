# Copyright(C) Facebook, Inc. and its affiliates.
from fabric import task
from invoke.exceptions import Exit

from benchmark.config import Policy, ConfigError
from benchmark.local import LocalBench
from benchmark.logs import LogParser, ParseError
from benchmark.utils import Print, BenchError


@task
def local(ctx, policy='policies/local-4.json', debug=False, output='console', results=None, runs=None):
    """Run policy cases locally. --output=console or --output=file (text + JSON)."""
    try:
        policies = Policy(policy, runs=runs)
        for case in policies.cases:
            ret = LocalBench(case.json, policies.node_parameters.json,
                             policy_source=policies.source, output=output, results=results).run(debug)
            print(ret.result())
    except (BenchError, ConfigError, OSError) as e:
        Print.error(e)
        raise Exit(code=1)


@task
def logs(ctx, directory, output='console'):
    """Reparse an existing case directory, including all its runs."""
    try:
        ret = LogParser.process(directory)
        if output == 'file':
            from pathlib import Path
            from benchmark.utils import PathMaker
            ret.print(Path(directory)/PathMaker.result_file('whcc', ret.faults, ret.committee_size))
        elif output != 'console':
            raise ParseError('output must be console or file')
        print(ret.result())
    except (ParseError, OSError) as e:
        Print.error(e)
        raise Exit(code=1)


@task
def plot(ctx, config='plot-configs/scalability.json'):
    """Plot saved results selected by a JSON file; never starts an experiment."""
    from benchmark.plot import Ploter, PlotError
    try:
        result = Ploter.plot(Ploter.read_config(config))
        print('Generated {figures} figures from {selected_results} results: {directory}'.format(**result))
        print('Excluded results: {excluded}; recorded failed experiments: {failed}'.format(**result))
    except (PlotError, OSError, KeyError, TypeError) as e:
        Print.error(e)
        raise Exit(code=1)

@task(auto_shortflags=False, help={
    'nodes': 'Party count (2..512).',
    'total_weight': 'Exact integer total W, or n^n. Optional only for distribution 4.',
    'distribution': '1=uniform, 2=near-uniform gcd=1, 3=few heavy parties, 4=max-gate search at W=n^n.',
    'pool': 'JSON weights, Aptos ValidatorSet file, or pinned snapshot directory; exclusive with distribution.',
    'output': 'Policy JSON path; relative to the current directory.',
    'threshold': 'Protocol threshold T (default floor(W/3)).',
    'fault_weight_threshold': 'Inclusive fault budget F<T (default T-1); also the per-party cap for distribution 3.',
    'heavy_count': 'Number of heavy parties for distribution 3 (default min(3,(n-1)//2)).',
    'heavy_share': 'Target share of the heavy group (default 0.8); capped by feasibility.',
    'fault_case': 'honest (default), stress, or both.',
    'samples': 'Initial proposals for distribution 4 (default 480).',
    'steps': 'Mutation proposals for distribution 4 (default 4096).',
    'overwrite': 'Replace the existing policy and its generated companion artifacts.',
})
def policy(ctx, nodes, total_weight=None, distribution=None, pool=None, output=None,
           threshold='auto', fault_weight_threshold=None, runs=1, seed=20261005,
           heavy_count=None, heavy_share=None, fault_case='honest', output_bits=128,
           samples=480, steps=4096, experiment_id=None, overwrite=False):
    """Generate a policy offline from a distribution enum or a weight pool."""
    import subprocess
    from benchmark.generate import generate
    try:
        result = generate(nodes=nodes, total_weight=total_weight, distribution=distribution, pool=pool,
            output=output, threshold=threshold, fault_weight_threshold=fault_weight_threshold,
            runs=runs, seed=seed, heavy_count=heavy_count, heavy_share=heavy_share,
            fault_case=fault_case, output_bits=output_bits, samples=samples, steps=steps,
            experiment_id=experiment_id, overwrite=overwrite)
        print('Policy: {policy}\nReport: {report}'.format(**result))
        print('n={nodes}, W={total_weight}, T={threshold}, F={fault_budget}, gcd={gcd}, weights={min_weight}..{max_weight}'.format(**result))
        print('Cases: {cases}; runs/case: {runs}; corrupted weights: {corrupted_weights}'.format(**result))
        if result['details']:
            print('Details:', result['details'])
        print('No distributed benchmark was started.')
    except (ConfigError, OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as e:
        Print.error(e)
        raise Exit(code=1)

@task(auto_shortflags=False)
def matrix(ctx, nodes='4,16,31,46,64', scales='1,10,100', mean_weight=300, runs=3,
           fault_case='both', snapshot='data/aptos-mainnet-v7479751174',
           profiles='uniform,near-uniform,heavy-tail,aptos', experiment_id='controlled-20261005-v1',
           output='policies/controlled-scalability.json', plot_output='plot-configs/controlled-scalability.json'):
    """Generate a controlled party/weight matrix and matching plot configuration."""
    from benchmark.matrix import write_matrix
    try:
        result = write_matrix(output=output, plot_output=plot_output, nodes=nodes, scales=scales,
            mean_weight=mean_weight, runs=runs, fault_case=fault_case, snapshot=snapshot,
            profiles=profiles, experiment_id=experiment_id)
        print(result)
    except (ConfigError, OSError, ValueError, KeyError) as e:
        Print.error(e)
        raise Exit(code=1)

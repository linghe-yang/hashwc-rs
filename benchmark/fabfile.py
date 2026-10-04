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

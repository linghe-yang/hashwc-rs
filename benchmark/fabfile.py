# Copyright(C) Facebook, Inc. and its affiliates.
from fabric import task
from invoke.exceptions import Exit

from benchmark.config import Policy, ConfigError
from benchmark.local import LocalBench
from benchmark.logs import LogParser, ParseError
from benchmark.utils import Print, BenchError


@task
def local(ctx, policy='policies/local-4.json', debug=False, output='console', results=None):
    """Run policy cases locally. --output=console or --output=file (text + JSON)."""
    try:
        policies = Policy(policy)
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
            ret.print(Path(directory)/PathMaker.result_file('commoncoin', ret.faults, ret.committee_size))
        elif output != 'console':
            raise ParseError('output must be console or file')
        print(ret.result())
    except (ParseError, OSError) as e:
        Print.error(e)
        raise Exit(code=1)

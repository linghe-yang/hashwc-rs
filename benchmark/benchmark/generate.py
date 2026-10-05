"""Generate a runnable WHCC policy from an enum or an immutable JSON weight pool."""
import hashlib
import json
import math
import shutil
import subprocess
import tempfile
from enum import IntEnum
from fractions import Fraction
from functools import reduce
from pathlib import Path

from benchmark.config import ConfigError, NodeParameters, Policy, integer, write_json
from benchmark.metadata import fingerprint
from benchmark.utils import PathMaker
from benchmark.weight_policies import (
    apportion, distribution as distribution_stats, load_snapshot, quantile_masses, stress_ids,
)


class Distribution(IntEnum):
    UNIFORM = 1
    COPRIME = 2
    HEAVY = 3
    MAX_GATES = 4


LABELS = {Distribution.UNIFORM: 'uniform', Distribution.COPRIME: 'coprime',
          Distribution.HEAVY: 'heavy', Distribution.MAX_GATES: 'max-gates'}


def balanced(n, total):
    q, r = divmod(total, n)
    if q < 1:
        raise ConfigError('Total weight must be at least the party count')
    return [q+1]*r + [q]*(n-r)


def coprime_weights(n, total):
    weights = balanced(n, total)
    if reduce(math.gcd, weights) != 1:
        # Nondivisible totals already contain consecutive integers.
        q = total//n
        delta = 2 if n == 2 and q % 2 else 1
        weights[0] -= delta
        weights[1] += delta
    assert min(weights) > 0 and sum(weights) == total and reduce(math.gcd, weights) == 1
    return weights


def heavy_weights(n, total, cap, count=None, share='0.8'):
    if n < 4 or n*cap < total:
        raise ConfigError('Heavy distribution infeasible: need n>=4 and W<=n*F for positive weights <=F')
    k = min(3, (n-1)//2) if count is None else integer(count, 'heavy_count', 1, (n-1)//2)
    try:
        fraction = Fraction(str(share))
    except (ValueError, ZeroDivisionError):
        raise ConfigError('heavy_share must be a rational number between 0 and 1')
    if not 0 < fraction < 1:
        raise ConfigError('heavy_share must be between 0 and 1')
    requested = total*fraction.numerator//fraction.denominator
    low, high = max(k, total-(n-k)*cap), min(k*cap, total-(n-k))
    allocated = min(high, max(low, requested))
    heavy, light = balanced(k, allocated), balanced(n-k, total-allocated)
    if min(heavy) <= max(light):
        raise ConfigError('No separated heavy group for these parameters; increase W/F/share or change heavy_count')
    weights = heavy+light
    assert sum(weights) == total and max(weights) <= cap
    return weights, dict(heavy_count=k, requested_share=str(fraction),
                         achieved_share=str(Fraction(allocated, total)), capped=allocated != requested,
                         per_party_cap=str(cap))


def read_pool(path):
    path = Path(path).resolve()
    snapshot = None
    if path.is_dir():
        manifest, validators = load_snapshot(path)
        weights = [v['weight'] for v in validators]
        snapshot = {k: manifest[k] for k in ['network', 'epoch', 'ledger_version', 'timestamp', 'sha256', 'source']}
        files = {name: (path/name).read_bytes() for name in
                 ['snapshot.json', 'validator-set.json', 'ledger-info.json', 'reconfiguration.json']}
        digest = manifest['sha256']
        kind = 'aptos-pinned-snapshot'
    else:
        raw = path.read_bytes()
        data = json.loads(raw)
        files, digest = {'pool.json': raw}, hashlib.sha256(raw).hexdigest()
        kind = 'json-weights'
        if isinstance(data, list):
            weights = data
        elif isinstance(data, dict) and data.get('type') == '0x1::stake::ValidatorSet':
            state = data['data']
            entries = state['active_validators']+state['pending_inactive']
            addresses = [int(v['addr'], 16) for v in entries]
            weights = [integer(v['voting_power'], 'pool weight', 1) for v in entries]
            if len(set(addresses)) != len(addresses) or sum(weights) != integer(state['total_voting_power'], 'pool total', 1):
                raise ConfigError('Invalid Aptos validator identities or total voting power')
            kind = 'aptos-validator-set-without-ledger-metadata'
        elif isinstance(data, dict) and set(data) == {'weights'}:
            weights = data['weights']
        else:
            raise ConfigError('Pool must be a JSON array, {"weights":[...]}, Aptos ValidatorSet, or pinned snapshot directory')
    if not isinstance(weights, list) or not weights:
        raise ConfigError('Weight pool must be a nonempty list')
    weights = [integer(w, 'pool weight', 1) for w in weights]
    return weights, dict(kind=kind, sha256=digest, source_count=len(weights)), snapshot, files


def compile_oracle():
    cargo = shutil.which('cargo') or str(Path.home()/'.cargo/bin/cargo')
    subprocess.run([cargo, 'build', '--release', '--locked', '-p', 'wcss', '--example', 'count_gates'],
                   cwd=str(PathMaker.BENCHMARK.parent), check=True)
    return PathMaker.BENCHMARK.parent/'target/release/examples/count_gates'


def search_baselines(n, threshold):
    total = n**n
    baselines = [dict(nodes=n, weights=[str(total//n)]*n, byzantine_nodes=[],
                     metadata=dict(weight_profile=dict(id='uniform-initial')))]
    sources = {}
    for filename in ['weights-npow.json', 'weights-gate-search.json']:
        path = PathMaker.BENCHMARK/'policies'/filename
        if not path.exists():
            continue
        raw = path.read_bytes()
        sources[filename] = hashlib.sha256(raw).hexdigest()
        for case in json.loads(raw)['cases']:
            if case['nodes'] != n or case.get('byzantine_nodes') or int(case['threshold']) != threshold:
                continue
            weights = [integer(w, 'baseline weight', 1) for w in case['weights']]
            if len(weights) != n or sum(weights) != total:
                raise ConfigError('Invalid saved search baseline: '+filename)
            baselines.append(case)
    return baselines, sources


def generate(nodes, total_weight=None, distribution=None, pool=None, output=None, threshold='auto',
             fault_weight_threshold=None, runs=1, seed=20261005, heavy_count=None, heavy_share=None,
             fault_case='honest', output_bits=128, samples=480, steps=4096,
             experiment_id=None, overwrite=False):
    """Return output paths and a summary. Only MAX_GATES compiles/runs a Rust oracle."""
    n = integer(nodes, 'nodes', 2, 512)
    if (distribution is None) == (pool is None):
        raise ConfigError('Choose exactly one of --distribution=1..4 or --pool=PATH')
    try:
        kind = None if distribution is None else Distribution(integer(distribution, 'distribution', 1, 4))
    except ValueError:
        raise ConfigError('distribution must be 1, 2, 3, or 4')
    if total_weight is None and kind != Distribution.MAX_GATES:
        raise ConfigError('--total-weight is required for distributions 1/2/3 and weight pools')
    total = n**n if total_weight in (None, 'n^n') else integer(total_weight, 'total_weight', n)
    if total < n or total.bit_length() > 4096:
        raise ConfigError('Require W>=n and at most 4096 weight bits')
    if kind == Distribution.MAX_GATES and total != n**n:
        raise ConfigError('Distribution 4 requires W=n^n; omit --total-weight or use --total-weight=n^n')
    t = total//3 if threshold == 'auto' else integer(threshold, 'threshold', 1)
    if t < 1 or 3*t > total:
        raise ConfigError('Require 0 < T <= W/3')
    cap = t-1 if fault_weight_threshold is None else integer(fault_weight_threshold, 'fault_weight_threshold', 0, t-1)
    runs, seed = integer(runs, 'runs', 1), integer(seed, 'seed')
    samples, steps = integer(samples, 'samples', 1), integer(steps, 'steps', 0)
    if fault_case not in ('honest', 'stress', 'both'):
        raise ConfigError('fault_case must be honest, stress, or both')
    if fault_case != 'honest' and cap == 0:
        raise ConfigError('Positive-weight Byzantine parties require F>0')
    if kind != Distribution.HEAVY and (heavy_count is not None or heavy_share is not None):
        raise ConfigError('heavy_count/heavy_share are only valid for distribution 3')
    node = NodeParameters(dict(output_bits=output_bits, rounding_bits=64, coverage_bits=40))
    pool_info, snapshot, source_files = None, None, {}
    parameters, details, weights = {}, {}, None
    if pool is not None:
        source, pool_info, snapshot, source_files = read_pool(pool)
        weights = apportion(quantile_masses(source, n), total)
        label, method = 'pool', 'quantile-integral-hamilton'
        parameters = dict(pool_sha256=pool_info['sha256'], mapping=method)
    else:
        label, method = LABELS[kind], 'enum-'+LABELS[kind]
        if kind == Distribution.UNIFORM:
            if total % n:
                raise ConfigError('Exactly uniform weights require W divisible by n; use distribution 2 otherwise')
            weights = [total//n]*n
        elif kind == Distribution.COPRIME:
            weights = coprime_weights(n, total)
            parameters = dict(irreducible='gcd-of-weights-equals-one')
        elif kind == Distribution.HEAVY:
            share = '0.8' if heavy_share is None else str(heavy_share)
            weights, details = heavy_weights(n, total, cap, heavy_count, share)
            parameters = dict(heavy_count_rule=heavy_count if heavy_count is not None else 'min(3,(n-1)//2)',
                              target_share=str(Fraction(share)), cap='F')
        else:
            parameters = dict(total_rule='n^n', objective='production-pruned-gate-count',
                              samples=samples, steps=steps)
    request = dict(nodes=n, total_weight=str(total), distribution=int(kind) if kind else None,
                   pool=pool_info, threshold=str(t), fault_weight_threshold=str(cap), runs=runs,
                   seed=seed, heavy_count=heavy_count, heavy_share=heavy_share, fault_case=fault_case,
                   output_bits=node.json['output_bits'], samples=samples if kind == Distribution.MAX_GATES else None,
                   steps=steps if kind == Distribution.MAX_GATES else None, experiment_id=experiment_id)
    tag = fingerprint(request)[:12]
    path = Path(output) if output else Path('policies')/('generated-{}-n{}-{}.json'.format(label, n, tag))
    path = path.resolve()
    if path.suffix.lower() != '.json':
        raise ConfigError('Output policy must have a .json extension')
    artifacts = path.with_suffix('.generation')
    if pool is not None:
        source_path = Path(pool).resolve()
        if path == source_path or artifacts == source_path or source_path in artifacts.parents or artifacts in source_path.parents:
            raise ConfigError('Output must not overwrite the input pool')
    if artifacts.is_symlink() or (artifacts.exists() and not artifacts.is_dir()) or path.is_dir():
        raise ConfigError('Output paths must be a policy file and a real companion directory')
    if (path.exists() or artifacts.exists()) and not overwrite:
        raise ConfigError('Output exists; choose another --output or explicitly use --overwrite')
    if experiment_id is not None and (not isinstance(experiment_id, str) or not experiment_id.strip()):
        raise ConfigError('experiment_id must be a nonempty string')
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.policy-', dir=str(path.parent)) as temporary:
        staging = Path(temporary)
        report = dict(schema_version=1, request=request, details=details, pool=pool_info)
        if kind == Distribution.MAX_GATES:
            from benchmark.gate_search import search
            binary = compile_oracle()
            baselines, sources = search_baselines(n, t)
            write_json(staging/'search-baselines.json', baselines)
            result = search(n, binary, baselines, samples, steps, seed, staging, threshold=t)
            weights = list(map(int, result['weights']))
            report['search'] = result
            report['baseline_sources'] = sources
            report['oracle_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
            parameters['oracle_sha256'] = report['oracle_sha256']
            details.update(gates=result['gates'], evaluated=result['evaluated'],
                           optimality='heuristic best found; not proven optimal')
        assert len(weights) == n and sum(weights) == total and min(weights) > 0
        stats = distribution_stats(weights)
        report['weights'], report['distribution'] = list(map(str, weights)), stats
        report['provenance'] = {str(p.relative_to(PathMaker.BENCHMARK.parent)):
            hashlib.sha256(p.read_bytes()).hexdigest() for p in
            [Path(__file__).resolve(), PathMaker.BENCHMARK/'benchmark/weight_policies.py',
             PathMaker.BENCHMARK/'benchmark/gate_search.py',
             PathMaker.BENCHMARK.parent/'consensus/wcss/src/protocol/circuit.rs']}
        generation = dict(method=method, version=1, seed=seed,
            input=dict(request=request, details=details, weights_sha256=fingerprint(list(map(str, weights))),
                       source_sha256=report['provenance']))
        if snapshot:
            generation['snapshot'] = snapshot
        cases = []
        for stress in ([False, True] if fault_case == 'both' else [fault_case == 'stress']):
            ids = stress_ids(weights, cap) if stress else []
            if stress and not ids:
                raise ConfigError('No party fits the requested Byzantine budget F')
            cases.append(dict(name='generated-{}-n{}-{}-{}'.format(label, n, tag, 'stress' if stress else 'honest'),
                nodes=n, weights=list(map(str, weights)), threshold=str(t),
                fault_weight_threshold=str(cap), byzantine_nodes=ids,
                metadata=dict(weight_profile=dict(id='generated-'+label, parameters=parameters), weight_scale=1,
                    generation=generation, fault_selection=dict(method='max-count-one-swap-v1' if stress else 'none',
                    budget=str(cap), selected_weight=str(sum(weights[i] for i in ids)), selected_count=len(ids),
                    ties='weight-then-id; greatest-positive-swap; ascending-old-new-id'))))
        policy = dict(metadata=dict(experiment_id=experiment_id or 'generated-weights-v1'),
            bench_params=dict(protocol='whcc', faults=0, runs=runs, duration=1800, startup_timeout=600),
            node_params=node.json, cases=cases)
        write_json(staging/'policy.json', policy)
        Policy(staging/'policy.json')  # Validate the same parser used by fab local, including ports.
        for name, raw in source_files.items():
            (staging/'source').mkdir(exist_ok=True)
            (staging/'source'/name).write_bytes(raw)
        report['policy_sha256'] = hashlib.sha256((staging/'policy.json').read_bytes()).hexdigest()
        write_json(staging/'report.json', report)
        # Publish only after successful generation and validation.
        bundle = staging/'bundle'
        bundle.mkdir()
        for entry in list(staging.iterdir()):
            if entry.name not in ('policy.json', 'bundle'):
                entry.rename(bundle/entry.name)
        old_bundle, old_policy = staging/'previous-bundle', staging/'previous-policy'
        try:
            if artifacts.exists():
                artifacts.rename(old_bundle)
            if path.exists():
                path.rename(old_policy)
            bundle.rename(artifacts)
            (staging/'policy.json').rename(path)
        except OSError:
            if artifacts.exists() and not bundle.exists():
                artifacts.rename(bundle)
            if old_bundle.exists():
                old_bundle.rename(artifacts)
            if old_policy.exists():
                old_policy.rename(path)
            raise
    return dict(policy=str(path), report=str(artifacts/'report.json'), nodes=n, total_weight=str(total),
                threshold=str(t), fault_budget=str(cap), cases=len(cases), runs=runs,
                **dict((k, stats[k]) for k in ['min_weight', 'max_weight', 'gcd']),
                details=details, corrupted_weights=[c['metadata']['fault_selection']['selected_weight'] for c in cases])

"""Experiment labels and reproducible facts, independent of plotting."""
import copy
import hashlib
import json
import os
import platform
from pathlib import Path


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def normalize_metadata(data, weight_spec):
    # Local import avoids a cycle while keeping all policy errors uniform.
    from benchmark.config import ConfigError, integer, keys
    keys(data, ['experiment_id', 'experiment_axis', 'weight_profile', 'weight_scale', 'generation', 'fault_selection'], 'metadata')
    data = copy.deepcopy(data)
    for field in ['experiment_id', 'experiment_axis']:
        if data.get(field) is not None and (not isinstance(data[field], str) or not data[field].strip()):
            raise ConfigError('metadata.{} must be a nonempty string or null'.format(field))
    if data.get('experiment_axis') not in (None, 'nodes', 'weight_scale', 'weight_skew', 'smoke'):
        raise ConfigError('Unknown metadata.experiment_axis')
    spec = weight_spec if isinstance(weight_spec, dict) else {}
    kind = spec.get('distribution', 'uniform') if isinstance(weight_spec, dict) else 'explicit'
    profile = data.get('weight_profile', dict(id=kind, parameters={
        key: spec.get(key, default) for key, default in
        ({'weight': 1} if kind == 'uniform' else {'start': 1, 'step': 1} if kind == 'linear' else {}).items()}))
    keys(profile, ['id', 'parameters'], 'metadata.weight_profile')
    if not isinstance(profile.get('id'), str) or not profile['id'].strip() or not isinstance(profile.get('parameters', {}), dict):
        raise ConfigError('weight_profile needs an id and object parameters')
    profile.setdefault('parameters', {})
    data['weight_profile'] = profile
    # An explicit array has no recoverable scale provenance: never guess one.
    scale = data.get('weight_scale', spec.get('scale', 1) if kind != 'explicit' else None)
    data['weight_scale'] = None if scale is None else integer(scale, 'metadata.weight_scale', 1)
    if kind == 'linear' and data['weight_scale'] != integer(spec.get('scale', 1), 'scale', 1):
        raise ConfigError('metadata.weight_scale disagrees with linear scale')
    generation = data.get('generation', dict(method='builtin-' + kind if kind != 'explicit' else 'explicit',
                                             version=1, input=weight_spec))
    keys(generation, ['method', 'version', 'input', 'seed', 'snapshot'], 'metadata.generation')
    if not isinstance(generation.get('method'), str) or not generation['method'].strip():
        raise ConfigError('generation.method must be a nonempty string')
    if type(generation.get('version')) not in (int, str) or not str(generation['version']).strip():
        raise ConfigError('generation.version is required')
    if generation.get('seed') is not None:
        generation['seed'] = integer(generation['seed'], 'generation.seed')
    if 'snapshot' in generation:
        snapshot = generation['snapshot']
        keys(snapshot, ['network', 'epoch', 'ledger_version', 'timestamp', 'sha256', 'source'], 'generation.snapshot')
        for key, value in snapshot.items():
            if type(value) not in (str, int) or not str(value).strip():
                raise ConfigError('Invalid snapshot.{}'.format(key))
        digest = snapshot.get('sha256')
        if digest is not None and (not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest)):
            raise ConfigError('snapshot.sha256 must be a lowercase SHA-256 digest')
    if 'fault_selection' in data:
        selection = data['fault_selection']
        keys(selection, ['method', 'budget', 'selected_weight', 'selected_count', 'ties'], 'metadata.fault_selection')
        if not isinstance(selection.get('method'), str) or not selection['method']:
            raise ConfigError('fault_selection.method is required')
        for key in ['budget', 'selected_weight', 'selected_count']:
            if key in selection:
                integer(selection[key], 'fault_selection.' + key)
    data['generation'] = generation
    data.setdefault('experiment_id', None)
    data.setdefault('experiment_axis', None)
    try:
        json.dumps(data, allow_nan=False)
    except (ValueError, TypeError) as e:
        raise ConfigError('Metadata must contain finite JSON values: {}'.format(e))
    return data


def fault_metadata(bench):
    from benchmark.config import ConfigError, integer
    weights, threshold = bench['weights'], bench['threshold']
    n = len(weights)
    silent = bench['faulty_nodes']
    byzantine = bench.get('byzantine_nodes', [])
    if not isinstance(byzantine, list) or not isinstance(silent, list):
        raise ConfigError('Fault identities must be lists')
    silent = [integer(i, 'silent identity', 0, n-1) for i in silent]
    byzantine = [integer(i, 'Byzantine identity', 0, n-1) for i in byzantine]
    if len(set(silent + byzantine)) != len(silent + byzantine):
        raise ConfigError('Fault identities overlap or repeat')
    raw_limit = bench.get('fault_weight_threshold')
    limit = integer(threshold-1 if raw_limit is None else raw_limit, 'fault_weight_threshold', 0, threshold-1)
    b = sum(weights[i] for i in silent + byzantine)
    if b > limit or threshold*3 > sum(weights):
        raise ConfigError('Require B <= F < T <= W/3')
    behavior = bench.get('byzantine_behavior', 'recovery-stress')
    if behavior != 'recovery-stress':
        raise ConfigError('Unknown Byzantine behavior')
    return dict(total_weight=str(sum(weights)), protocol_threshold=str(threshold),
                fault_weight_threshold=str(limit), corrupted_weight=str(b),
                silent_weight=str(sum(weights[i] for i in silent)),
                byzantine_weight=str(sum(weights[i] for i in byzantine)),
                silent_nodes=silent, byzantine_nodes=byzantine,
                honest_nodes=[i for i in range(n) if i not in silent + byzantine],
                byzantine_behavior=behavior if byzantine else None)


def policy_metadata(bench, node):
    weights, threshold = bench['weights'], bench['threshold']
    total = sum(weights)
    faults = fault_metadata(bench)
    faulty = faults['silent_nodes'] + faults['byzantine_nodes']
    # Decimal strings keep identifiers independent of JSON large-number consumers.
    instance = dict(weights=[str(w) for w in weights], threshold=str(threshold))
    configuration = dict(instance, faulty_nodes=sorted(faulty),
                         output_bits=node.get('output_bits', 1), rounding_bits=node['rounding_bits'],
                         coverage_bits=node['coverage_bits'])
    # Preserve old honest/silent configuration IDs for schema-1 manifests.
    if faults['byzantine_nodes'] or int(faults['fault_weight_threshold']) != threshold-1:
        configuration.update(byzantine_nodes=sorted(faults['byzantine_nodes']),
                             byzantine_behavior=faults['byzantine_behavior'],
                             fault_weight_threshold=faults['fault_weight_threshold'])
    shares = [w / total for w in weights]
    ordered = sorted(weights)
    n = len(weights)
    return dict(copy.deepcopy(bench.get('metadata', {})),
                weight_instance_id=fingerprint(instance), configuration_id=fingerprint(configuration), fault_model=faults,
                policy=dict(weights_decimal=instance['weights'], threshold_decimal=str(threshold),
                            total_weight_decimal=str(total), nodes=n,
                            total_weight_bits=total.bit_length(), max_weight_bits=max(weights).bit_length(),
                            min_weight_decimal=str(min(weights)), max_weight_decimal=str(max(weights)),
                            mean_weight_decimal_ratio=[str(total), str(n)],
                            threshold_mode=bench.get('threshold_mode', 'unknown'),
                            threshold_ratio=threshold / total, faulty_weight_decimal=str(sum(weights[i] for i in faulty)),
                            faulty_weight_ratio=sum(weights[i] for i in faulty) / total,
                            largest_weight_share=max(shares),
                            coefficient_of_variation=(sum((n*s-1)**2 for s in shares)/n)**0.5,
                            gini=sum((2*i-n-1)*w for i, w in enumerate(ordered, 1)) / (n*total),
                            faulty_nodes=faulty, output_bits=node.get('output_bits', 1),
                            rounding_bits=node['rounding_bits'], coverage_bits=node['coverage_bits']))


def environment_metadata(debug):
    def read(path):
        try:
            return Path(path).read_text(encoding='utf8')
        except OSError:
            return ''
    cpu = next((line.split(':', 1)[1].strip() for line in read('/proc/cpuinfo').splitlines()
                if line.startswith('model name')), platform.processor())
    memory = next((int(line.split()[1])*1024 for line in read('/proc/meminfo').splitlines()
                   if line.startswith('MemTotal:')), None)
    return dict(os=platform.system(), kernel=platform.release(), architecture=platform.machine(),
                hostname=platform.node(), cpu_model=cpu, logical_cpus=os.cpu_count(),
                cpu_affinity=sorted(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else None,
                memory_bytes=memory, python=platform.python_version(), network='linux-loopback',
                deployment='local-multiprocess', tokio_worker_threads=os.environ.get('TOKIO_WORKER_THREADS', '2'),
                debug=debug)

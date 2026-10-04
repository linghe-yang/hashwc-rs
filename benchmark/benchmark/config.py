# Copyright(C) Facebook, Inc. and its affiliates.
# Adapted for upstream config::Node (no legacy committee/client/worker schema).
import argparse
import copy
import json
import math
import re
import secrets
from pathlib import Path

from benchmark.utils import PathMaker
from benchmark.metadata import normalize_metadata


class ConfigError(ValueError):
    pass


def integer(value, name, minimum=0, maximum=None):
    if isinstance(value, str):
        try:
            value = int(value, 16 if value.startswith('0x') else 10)
        except ValueError:
            raise ConfigError('{} must be an integer'.format(name))
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ConfigError('Invalid {}'.format(name))
    return value


def number(value, name, minimum=0, strict=False):
    if type(value) not in (int, float) or not math.isfinite(value) or value < minimum or (strict and value == minimum):
        raise ConfigError('Invalid {}'.format(name))
    return value


def keys(data, allowed, name):
    if not isinstance(data, dict):
        raise ConfigError('{} must be an object'.format(name))
    unknown = set(data) - set(allowed)
    if unknown:
        raise ConfigError('Unknown {} fields: {}'.format(name, sorted(unknown)))


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf8')


class NodeParameters:
    def __init__(self, data):
        defaults = dict(epoch=0, coverage_bits=40, rounding_bits=64, output_bits=1, port_stride=None)
        keys(data, defaults, 'node_params')
        self.json = dict(defaults, **data)
        for key, low, high in [('epoch', 0, 2**64-1), ('coverage_bits', 1, 256), ('rounding_bits', 1, 252), ('output_bits', 1, 252)]:
            self.json[key] = integer(self.json[key], key, low, high)
        if self.json['rounding_bits'] + self.json['output_bits'] + 1 > 254:
            raise ConfigError('AX capacity: rounding_bits + output_bits + 1 must be <= 254')
        if self.json['port_stride'] is not None:
            self.json['port_stride'] = integer(self.json['port_stride'], 'port_stride', 1, 65535)

    def print(self, filename):
        write_json(filename, self.json)


class BenchParameters:
    def __init__(self, data):
        defaults = dict(protocol='whcc', faults=0, duration=60, runs=1,
                        base_port=20000, startup_timeout=30, settle_time=0, sync_port=None,
                        byzantine_nodes=[], byzantine_behavior='recovery-stress', fault_weight_threshold=None)
        keys(data, set(defaults) | {'name', 'nodes', 'weights', 'threshold', 'faulty_nodes', 'metadata', 'threshold_mode'}, 'bench_params/case')
        self.json = dict(defaults, **copy.deepcopy(data))
        if self.json['protocol'] == 'commoncoin':
            self.json['protocol'] = 'whcc'
        if self.json['protocol'] != 'whcc':
            raise ConfigError('Only whcc is currently supported')
        self.protocol = self.json['protocol']
        n = integer(data.get('nodes'), 'nodes', 2, 512)
        self.nodes = [n]  # Keep the legacy list-shaped attribute.
        name = data.get('name', 'coin-{}'.format(n))
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', name):
            raise ConfigError('name must contain only letters, digits, hyphens or underscores')
        self.name = name
        spec = data.get('weights', {'distribution': 'uniform', 'weight': 1})
        if isinstance(spec, list):
            weights = [integer(w, 'weight', 1) for w in spec]
        elif isinstance(spec, dict):
            distribution = spec.get('distribution', 'uniform')
            if distribution == 'uniform':
                keys(spec, ['distribution', 'weight'], 'weights')
                weights = [integer(spec.get('weight', 1), 'weight', 1)] * n
            elif distribution == 'linear':
                keys(spec, ['distribution', 'start', 'step', 'scale'], 'weights')
                first = integer(spec.get('start', 1), 'start', 1)
                step = integer(spec.get('step', 1), 'step', 0)
                scale = integer(spec.get('scale', 1), 'scale', 1)
                weights = [(first + i * step) * scale for i in range(n)]
            else:
                raise ConfigError('Unknown weight distribution: {}'.format(distribution))
        else:
            raise ConfigError('weights must be a list or a distribution object')
        if len(weights) != n:
            raise ConfigError('weights length must equal nodes')
        self.metadata = normalize_metadata(data.get('metadata', {}), spec)
        self.weights = weights
        self.total_weight = sum(weights)
        if self.total_weight.bit_length() > 4096:
            raise ConfigError('Weight bit length exceeds WCSS limit')
        threshold = data.get('threshold', 'auto')
        threshold_mode = data.get('threshold_mode', 'auto' if threshold == 'auto' else 'explicit')
        if threshold_mode not in ('auto', 'explicit'):
            raise ConfigError('Invalid threshold_mode')
        self.threshold = integer(self.total_weight // 3 if threshold == 'auto' else threshold, 'threshold', 1)
        if self.threshold * 3 > self.total_weight:
            raise ConfigError('Require T <= total weight / 3')
        self.faults = integer(self.json['faults'], 'faults', 0, n-1)
        faulty = data.get('faulty_nodes', list(range(n-self.faults, n)))
        if not isinstance(faulty, list):
            raise ConfigError('faulty_nodes must be a list')
        self.faulty_nodes = [integer(i, 'faulty node', 0, n-1) for i in faulty]
        if len(set(self.faulty_nodes)) != len(self.faulty_nodes) or len(self.faulty_nodes) != self.faults:
            raise ConfigError('faulty_nodes must contain exactly faults distinct parties')
        byzantine = self.json['byzantine_nodes']
        if not isinstance(byzantine, list):
            raise ConfigError('byzantine_nodes must be a list')
        self.byzantine_nodes = [integer(i, 'Byzantine node', 0, n-1) for i in byzantine]
        if len(set(self.byzantine_nodes)) != len(self.byzantine_nodes) or set(self.byzantine_nodes) & set(self.faulty_nodes):
            raise ConfigError('Byzantine identities must be unique and disjoint from silent faulty_nodes')
        self.byzantine_behavior = self.json['byzantine_behavior']
        if self.byzantine_behavior != 'recovery-stress':
            raise ConfigError('Supported Byzantine behavior: recovery-stress')
        limit = self.json['fault_weight_threshold']
        self.fault_weight_threshold = integer(self.threshold-1 if limit is None else limit, 'fault_weight_threshold', 0, self.threshold-1)
        self.corrupted_weight = sum(weights[i] for i in self.faulty_nodes + self.byzantine_nodes)
        if self.corrupted_weight > self.fault_weight_threshold:
            raise ConfigError('Require corrupted weight B <= fault_weight_threshold F < protocol threshold T')
        self.duration = number(self.json['duration'], 'duration', strict=True)
        self.startup_timeout = number(self.json['startup_timeout'], 'startup_timeout', strict=True)
        self.settle_time = number(self.json['settle_time'], 'settle_time')
        self.runs = integer(self.json['runs'], 'runs', 1)
        self.base_port = integer(self.json['base_port'], 'base_port', 1024, 65535)
        self.sync_port = None if self.json['sync_port'] is None else integer(self.json['sync_port'], 'sync_port', 1024, 65535)
        self.json.update(name=name, nodes=n, weights=weights, threshold=self.threshold,
                         metadata=self.metadata, threshold_mode=threshold_mode,
                         byzantine_nodes=self.byzantine_nodes, fault_weight_threshold=self.fault_weight_threshold,
                         faults=self.faults, faulty_nodes=self.faulty_nodes, runs=self.runs, base_port=self.base_port)

    def ports(self, node_params):
        stride = node_params.json['port_stride'] or self.nodes[0]
        ports = {}
        for service_id, service in enumerate(['wrbc', 'wra', 'wgather', 'wbinaa', 'private', 'recovery']):
            for party in range(self.nodes[0]):
                port = self.base_port + service_id * stride + party
                if port > 65535 or port in ports:
                    raise ConfigError('Protocol ports overlap or exceed 65535')
                ports[port] = {'service': service, 'party': party}
        sync_port = self.sync_port or (self.base_port + 6 * stride)
        if sync_port > 65535 or sync_port in ports:
            raise ConfigError('Synchronizer port overlaps or exceeds 65535')
        return ports

    def synchronizer_port(self, node_params):
        self.ports(node_params)
        return self.sync_port or (self.base_port + 6 * (node_params.json['port_stride'] or self.nodes[0]))


class Policy:
    def __init__(self, filename, runs=None):
        self.filename = Path(filename).resolve()
        try:
            self.source = self.filename.read_text(encoding='utf8')
            self.json = json.loads(self.source)
        except (OSError, ValueError) as e:
            raise ConfigError('Cannot read policy: {}'.format(e))
        keys(self.json, ['bench_params', 'node_params', 'cases', 'metadata'], 'policy')
        self.node_parameters = NodeParameters(self.json.get('node_params', {}))
        base = self.json.get('bench_params', {})
        keys(base, ['protocol', 'faults', 'duration', 'runs', 'base_port', 'startup_timeout', 'settle_time', 'sync_port', 'byzantine_nodes', 'byzantine_behavior', 'fault_weight_threshold'], 'bench_params')
        cases = self.json.get('cases')
        if not isinstance(cases, list) or not cases:
            raise ConfigError('Policy needs at least one case')
        self.cases = []
        for case in cases:
            keys(case, ['name', 'nodes', 'weights', 'threshold', 'faults', 'faulty_nodes', 'runs', 'metadata', 'byzantine_nodes', 'byzantine_behavior', 'fault_weight_threshold'], 'case')
            metadata = self.json.get('metadata', {})
            keys(metadata, ['experiment_id', 'experiment_axis', 'weight_profile', 'weight_scale', 'generation', 'fault_selection'], 'metadata')
            case_metadata = case.get('metadata', {})
            keys(case_metadata, ['experiment_id', 'experiment_axis', 'weight_profile', 'weight_scale', 'generation', 'fault_selection'], 'case.metadata')
            combined = dict(base, **case)
            combined['metadata'] = dict(metadata, **case_metadata)
            if runs is not None:
                combined['runs'] = integer(runs, 'runs', 1)
            bench = BenchParameters(combined)
            bench.ports(self.node_parameters)
            self.cases.append(bench)
        if len({c.name for c in self.cases}) != len(self.cases):
            raise ConfigError('Case names must be unique')
        if self.node_parameters.json['epoch'] + max(c.runs for c in self.cases) > 2**64:
            raise ConfigError('Repeated runs overflow epoch')


class LocalCommittee:
    """Generate JSON consumed directly by external config::Node."""
    def __init__(self, bench_parameters, node_parameters):
        self.bench = bench_parameters
        self.parameters = node_parameters
        self.ports = self.bench.ports(self.parameters)
        self.session_id = list(secrets.token_bytes(32))

    def print(self, directory):
        directory = Path(directory)
        n = self.bench.nodes[0]
        pair_keys = {(i, j): list(secrets.token_bytes(32)) for i in range(n) for j in range(i, n)}
        control_keys = {str(i): list(secrets.token_bytes(32)) for i in range(n)}
        sync_addr = '127.0.0.1:{}'.format(self.bench.synchronizer_port(self.parameters))
        net_map = {str(i): '127.0.0.1:{}'.format(self.bench.base_port+i) for i in range(n)}
        net_map[str(n)] = sync_addr
        for i in range(n):
            node = dict(weights=[hex(w) for w in self.bench.weights], weight_threshold=hex(self.bench.threshold),
                        session_id=self.session_id, net_map=net_map, id=i, num_nodes=n, num_faults=self.bench.faults+len(self.bench.byzantine_nodes),
                        delta=50, block_size=0, client_port=0, client_addr=sync_addr, payload=0,
                        prot_payload='whcc', crypto_alg='NOPKI', pk_map={}, secret_key_bytes=[],
                        sk_map={str(j): pair_keys[min(i,j), max(i,j)] for j in range(n)},
                        my_cert=[], my_cert_key=[], root_cert=[])
            node['sk_map'][str(n)] = control_keys[str(i)]
            filename = directory / PathMaker.key_file(i)
            write_json(filename, node)
            filename.chmod(0o600)
        sync_node = dict(node, id=0, sk_map=control_keys)
        write_json(directory/'.synchronizer.json', sync_node)
        (directory/'.synchronizer.json').chmod(0o600)
        self.parameters.print(directory / PathMaker.parameters_file())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--policy', required=True, help='Resolved single-case policy')
    parser.add_argument('--target', required=True)
    args = parser.parse_args()
    data = json.loads(Path(args.policy).read_text(encoding='utf8'))
    LocalCommittee(BenchParameters(data['bench_params']), NodeParameters(data['node_params'])).print(args.target)

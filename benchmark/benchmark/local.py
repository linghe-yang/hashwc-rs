# Copyright(C) Facebook, Inc. and its affiliates.
# Keep the local compile -> configure -> run -> parse -> result workflow.
import copy
import datetime
import json
import hashlib
import os
import secrets
import signal
import socket
import subprocess
import time
from pathlib import Path

from benchmark.bandwidth import BandwidthMeter
from benchmark.commands import CommandMaker
from benchmark.config import BenchParameters, NodeParameters, ConfigError, write_json
from benchmark.logs import LogParser, ParseError
from benchmark.metadata import environment_metadata, policy_metadata, fingerprint
from benchmark.utils import Print, BenchError, PathMaker


class LocalBench:
    BASE_PORT = 20000

    def __init__(self, bench_parameters_dict, node_parameters_dict, policy_source=None,
                 output='console', results=None):
        try:
            self.bench_parameters = BenchParameters(bench_parameters_dict)
            from benchmark.coding import resolve_parameters
            self.node_parameters, self.coding_report = resolve_parameters(
                self.bench_parameters, NodeParameters(node_parameters_dict))
            # Persist the resolved integer so later configuration generation never reselects.
            self.bench_parameters.json['bulk_block_bytes'] = self.node_parameters.json['bulk_block_bytes']
            self.bench_parameters.ports(self.node_parameters)
            if output not in ('console', 'file'):
                raise ConfigError('output must be console or file')
        except ConfigError as e:
            raise BenchError('Invalid nodes or bench parameters', e)
        self.policy_source = policy_source
        self.output = output
        self.results = Path(results).resolve() if results else PathMaker.results_path()
        self.processes = []

    def __getattr__(self, attr):
        return getattr(self.bench_parameters, attr)

    def _background_run(self, command, log_file):
        handle = Path(log_file).open('wb')
        environment = dict(os.environ)
        # Local CPU contention must not create one runtime thread per host CPU per node.
        environment.setdefault('TOKIO_WORKER_THREADS', '2')
        environment['RUST_LOG'] = 'debug' if self.debug else 'info'
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=handle,
                                       stderr=subprocess.STDOUT, env=environment,
                                       cwd=PathMaker.BENCHMARK)
        except BaseException:
            handle.close()
            raise
        self.processes.append(dict(process=process, handle=handle, log=Path(log_file),
                                   offset=0, pending=b'', events=[]))
        return self.processes[-1]

    def _kill_nodes(self):
        # Only terminate processes owned by this run; do not kill a global tmux server.
        errors = []
        for child in self.processes:
            if child['process'].poll() is None:
                child['process'].send_signal(signal.SIGINT)
        for child in self.processes:
            process = child['process']
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                errors.append('forced termination: {}'.format(child['log']))
            if process.returncode != 0:
                errors.append('{} exited with {}'.format(child['log'], process.returncode))
            if process.stdin:
                process.stdin.close()
            child['handle'].close()
        self.processes = []
        return errors

    def _wait_for(self, kind, timeout, children=None):
        children = self.processes if children is None else children
        deadline = time.monotonic() + timeout
        while True:
            complete = True
            for child in self.processes:
                if child['process'].poll() not in (None, 0):
                    raise BenchError('Node failed: {}'.format(child['log']))
            for child in children:
                if child['process'].poll() is not None:
                    raise BenchError('Node exited before {}: {}'.format(kind, child['log']))
                with child['log'].open('rb') as stream:
                    stream.seek(child['offset'])
                    data = stream.read()
                    child['offset'] = stream.tell()
                parts = (child['pending'] + data).split(b'\n')
                child['pending'] = parts.pop()
                for line in parts:
                    if line.startswith(b'{'):
                        event = json.loads(line)
                        if event.get('protocol') == 'whcc':
                            child['events'].append(event)
                matches = [e for e in child['events'] if e.get('kind') == kind]
                if len(matches) > 1:
                    raise BenchError('Duplicate {}: {}'.format(kind, child['log']))
                complete = complete and bool(matches)
            if complete:
                return
            if time.monotonic() >= deadline:
                raise BenchError('Timed out waiting for {}; incomplete experiment (no fallback coin)'.format(kind))
            time.sleep(0.01)

    def _check_ports(self):
        # Bind all advertised service ports simultaneously, then release them just before launch.
        probes = []
        try:
            all_ports = list(self.bench_parameters.ports(self.node_parameters)) + [self.bench_parameters.synchronizer_port(self.node_parameters)]
            for port in all_ports:
                probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                probes.append(probe)
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(('0.0.0.0', port))
                probe.listen(1)
        except OSError as e:
            raise BenchError('Benchmark port unavailable: {}'.format(port), e)
        finally:
            for probe in probes:
                probe.close()

    def _run_once(self, directory, index, build):
        directory.mkdir()
        (directory/'logs').mkdir()
        params = copy.deepcopy(self.node_parameters.json)
        params['epoch'] += index-1
        resolved = dict(bench_params=self.bench_parameters.json, node_params=params)
        write_json(directory/'resolved-policy.json', resolved)
        subprocess.run(CommandMaker.generate_confs(directory/'resolved-policy.json', directory),
                       check=True, cwd=PathMaker.BENCHMARK)
        config = json.loads((directory/PathMaker.key_file(0)).read_text(encoding='utf8'))
        active = [i for i in range(self.nodes[0]) if i not in self.faulty_nodes]
        checks = []
        for i in range(self.nodes[0]):
            check = json.loads(subprocess.check_output(
                CommandMaker.check_config(directory/PathMaker.key_file(i), directory/PathMaker.parameters_file()),
                text=True))
            if check['status'] != 'valid' or check['party'] != i or check['parties'] != self.nodes[0]:
                raise BenchError('Invalid node configuration diagnostic')
            checks.append(check)
        circuit = dict(gates=checks[0]['gates'], public_bytes=checks[0]['public_bytes'])
        from benchmark.coding import geometry, cost
        layout = geometry(tuple(self.weights), self.threshold, params['coverage_bits'])
        prediction = cost(layout, params['bulk_block_bytes'])
        if circuit != {k: layout[k] for k in circuit}:
            raise BenchError('Python/Rust circuit geometry mismatch')
        if any(c.get('bulk_block_bytes') != params['bulk_block_bytes'] or c.get('control_block_bytes') != 32
               or c.get('sampling_quotas') != layout['quotas'] or c.get('storage_bundle_bytes') != prediction['bundle_bytes']
               for c in checks):
            raise BenchError('Python/Rust coding geometry mismatch')
        if any(c['gates'] != circuit['gates'] or c['public_bytes'] != circuit['public_bytes'] for c in checks):
            raise BenchError('Parties disagree on circuit dimensions')
        write_json(directory/'run.json', dict(schema_version=2, session=bytes(config['session_id']).hex(), epoch=params['epoch'],
                                            configuration_id=policy_metadata(self.bench_parameters.json, params)['configuration_id'],
                                            circuit=circuit, environment=self.environment,
                                            byzantine_nodes=self.byzantine_nodes,
                                            byzantine_behavior=self.byzantine_behavior,
                                            active_parties=active, build=build,
                                            tokio_worker_threads=os.environ.get('TOKIO_WORKER_THREADS', '2')))
        self._check_ports()
        meter = BandwidthMeter(self.bench_parameters.ports(self.node_parameters), active, directory)
        meter.start()
        try:
            sync = self._background_run(CommandMaker.run_synchronizer(directory/'.synchronizer.json',
                                        directory/PathMaker.parameters_file(), self.debug), directory/'logs'/'synchronizer.log')
            self._wait_for('sync_ready', self.startup_timeout, [sync])
            parties = []
            for i in active:
                parties.append(self._background_run(CommandMaker.run_primary(directory/PathMaker.key_file(i),
                               directory/PathMaker.parameters_file(), self.debug,
                               self.byzantine_behavior if i in self.byzantine_nodes else 'honest'), directory/PathMaker.primary_log_file(i)))
            self._wait_for('sync_start', self.startup_timeout, [sync])
            self._wait_for('sync_result', self.duration, [sync])
            # STOP, not local coin output, terminates each party. Slow PREPARE is abortable.
            for child in parties:
                try:
                    code = child['process'].wait(timeout=self.startup_timeout)
                except subprocess.TimeoutExpired as e:
                    raise BenchError('Party did not exit on STOP: {}'.format(child['log']), e)
                if code != 0:
                    raise BenchError('Party failed on STOP: {}'.format(child['log']))
            bandwidth = meter.stop()
            write_json(directory/'bandwidth.json', bandwidth)
            # Persist measured per-sender counters in that party's log. These are
            # collector records, not estimates or protocol-generated counters.
            for i in active:
                totals = bandwidth['per_party_sent_bytes'][i]
                event = dict(protocol='whcc', output_bits=params['output_bits'], kind='bandwidth', source='linux-af-packet-collector',
                             session=bytes(config['session_id']).hex(), epoch=params['epoch'], party=i,
                             total_sent_bytes=sum(totals.values()), per_service_sent_bytes=totals)
                with (directory/PathMaker.primary_log_file(i)).open('a', encoding='utf8') as logfile:
                    logfile.write(json.dumps(event, sort_keys=True)+'\n')
        finally:
            try:
                if meter.thread is not None:
                    meter.stop()
            finally:
                errors = self._kill_nodes()
        if errors:
            raise BenchError('Node shutdown failed: {}'.format('; '.join(errors)))

    def run(self, debug=False, update_params_only=False):
        if update_params_only:
            raise BenchError('Each coin needs a fresh session and pair keys; partial config reuse is unsupported')
        if type(debug) is not bool:
            raise BenchError('debug must be a boolean')
        self.debug = debug
        self.environment = environment_metadata(debug)
        if self.settle_time:
            Print.warn('settle_time is ignored: STOP now terminates parties immediately')
        Print.heading('Starting local benchmark: {}'.format(self.name))
        base = self.results if self.output == 'file' else PathMaker.logs_path()
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%SZ')
        name = '{}-{}-n{}-w{}-t{}-l{}-{}-{}'.format(self.protocol, self.name, self.nodes[0],
                    # Keep path components bounded for large integer policies.
                    str(self.total_weight) if self.total_weight.bit_length() < 64 else 'bits{}'.format(self.total_weight.bit_length()),
                    str(self.threshold) if self.threshold.bit_length() < 64 else 'bits{}'.format(self.threshold.bit_length()),
                    self.node_parameters.json['output_bits'], stamp, secrets.token_hex(4))
        directory = base/name
        directory.mkdir(parents=True)
        Print.info('Artifacts: {}'.format(directory))
        resolved = dict(bench_params=self.bench_parameters.json, node_params=self.node_parameters.json)
        write_json(directory/'resolved-policy.json', resolved)
        if self.coding_report is not None:
            write_json(directory/'coding-selection.json', self.coding_report)
        (directory/'policy.json').write_text(self.policy_source or json.dumps(resolved, indent=2)+'\n', encoding='utf8')
        try:
            Print.info('Compiling node (release, shared executable)...')
            with (directory/'build.log').open('wb') as output:
                subprocess.run(CommandMaker.compile(self.protocol), check=True,
                               cwd=PathMaker.node_crate_path(), stdout=output, stderr=subprocess.STDOUT)
            build = dict(profile='release', rustc=subprocess.check_output(['rustc', '--version'], text=True).strip())
            build['binary_sha256'] = hashlib.sha256((PathMaker.binary_path()/'node').read_bytes()).hexdigest()
            build['cargo_lock_sha256'] = hashlib.sha256((PathMaker.ROOT/'Cargo.lock').read_bytes()).hexdigest()
            build['implementation'] = 'compact-header-striped-wavid-v4-coding'
            build['transport'] = 'sdc-util-windowed-compact-v3'
            build['coding_block_bytes'] = self.node_parameters.json['bulk_block_bytes']
            build['control_coding_block_bytes'] = 32
            packages = json.loads(subprocess.check_output(
                ['cargo', 'metadata', '--locked', '--format-version', '1'],
                cwd=PathMaker.ROOT, text=True))['packages']
            transport = next(p for p in packages if p['name'] == 'util' and
                             (p.get('source') or '').startswith(
                                 'git+https://github.com/linghe-yang/Secure-Distributed-Computing-Protocols.git'))
            build['sdc_source'] = transport['source']
            build['sdc_revision'] = transport['source'].rsplit('#', 1)[1]
            transport_root = Path(transport['manifest_path']).parent
            build['transport_source_sha256'] = fingerprint({
                prefix + '/' + str(p.relative_to(folder)): hashlib.sha256(p.read_bytes()).hexdigest()
                for prefix, folder in [('sdc-util', transport_root), ('network', PathMaker.ROOT/'network')]
                for p in sorted((folder/'src').rglob('*.rs'))})
            build['benchmark_source_sha256'] = fingerprint({
                str(p.relative_to(PathMaker.BENCHMARK)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted((PathMaker.BENCHMARK/'benchmark').glob('*.py'))})
            try:
                build['git_revision'] = subprocess.check_output(
                    ['git', 'rev-parse', 'HEAD'], cwd=PathMaker.ROOT, text=True, stderr=subprocess.DEVNULL).strip()
                build['git_dirty'] = bool(subprocess.check_output(
                    ['git', 'status', '--porcelain'], cwd=PathMaker.ROOT, text=True, stderr=subprocess.DEVNULL).strip())
            except (OSError, subprocess.SubprocessError):
                build.update(git_revision=None, git_dirty=None)
            for index in range(1, self.runs+1):
                Print.info('Running {}/{}: {} active parties, {} silent, {} Byzantine...'.format(index, self.runs, self.nodes[0]-self.faults, self.faults, len(self.byzantine_nodes)))
                self._run_once(directory/'run-{:03}'.format(index), index, build)
            Print.info('Parsing logs...')
            logger = LogParser.process(directory, faults=self.faults)
            if self.output == 'file':
                logger.print(directory/PathMaker.result_file(self.protocol, self.faults, self.nodes[0]))
            return logger
        except (OSError, ValueError, subprocess.SubprocessError, BenchError) as e:
            write_json(directory/'failure.json', dict(status='failed', reason=str(e)))
            raise BenchError('Failed to run benchmark; artifacts: {}'.format(directory), e)

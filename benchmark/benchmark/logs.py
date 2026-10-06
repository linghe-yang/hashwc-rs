# Copyright(C) Facebook, Inc. and its affiliates.
# Single-coin latency and bandwidth results; deliberately no throughput fields.
import json
import copy
import statistics
import re
import math
from pathlib import Path

from benchmark.config import write_json
from benchmark.metadata import policy_metadata, fault_metadata


class ParseError(ValueError):
    pass


def records(path):
    result = []
    for line in Path(path).read_text(encoding='utf8').splitlines():
        if line.startswith('{'):
            try:
                value = json.loads(line)
            except ValueError as e:
                raise ParseError('Invalid structured log in {}: {}'.format(path, e))
            if isinstance(value, dict) and value.get('protocol') in ('whcc', 'commoncoin'):
                if value['protocol'] != 'whcc':
                    value['source_protocol'] = value['protocol']
                    value['protocol'] = 'whcc'
                result.append(value)
    return result


def valid_coin(value, bits):
    if bits == 1:
        return type(value) is int and value in (0, 1)
    return (isinstance(value, str) and re.fullmatch(r'0x[0-9a-f]{' + str((bits+3)//4) + '}', value) is not None
            and int(value, 16) < (1 << bits))


def stats(values):
    if not values or any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in values):
        raise ParseError('Statistics require nonempty finite nonnegative measurements')
    mean, low, high = statistics.mean(values), min(values), max(values)
    deviation = statistics.stdev(values) if len(values) > 1 else None
    return dict(count=len(values), mean=mean, median=statistics.median(values), min=low, max=high,
                stdev=deviation, standard_error=deviation / math.sqrt(len(values)) if deviation is not None else None,
                error_bar=dict(method='min_max', lower=low, upper=high,
                               minus=mean-low, plus=high-mean),
                variability_estimated=len(values) > 1)


class LogParser:
    def __init__(self, config, runs, directory):
        source_protocol = config['bench_params'].get('protocol', 'commoncoin')
        if source_protocol not in ('whcc', 'commoncoin'):
            raise ParseError('Unsupported protocol: {}'.format(source_protocol))
        config = copy.deepcopy(config)
        config['bench_params']['protocol'] = 'whcc'
        self.configs = config
        self.runs = runs
        self.directory = str(Path(directory).resolve())
        self.faults = config['bench_params']['faults']
        self.committee_size = config['bench_params']['nodes']
        if not runs or len(runs) != config['bench_params']['runs']:
            raise ParseError('Incomplete runs: refusing a successful aggregate')
        for key in ['build', 'environment', 'circuit']:
            if any(r.get(key) != runs[0].get(key) for r in runs):
                raise ParseError('Cannot aggregate runs with different {}'.format(key))
        metadata = policy_metadata(config['bench_params'], config['node_params'])
        for key in ['experiment_id', 'experiment_axis', 'weight_profile', 'weight_scale', 'generation']:
            metadata.setdefault(key, None)
        metadata.update(build=runs[0]['build'], environment=runs[0].get('environment'),
                        circuit=runs[0].get('circuit'),
                        provenance_status='recorded' if runs[0].get('environment') is not None else 'legacy-partial')
        work_summary = None
        if all(r.get('work') is not None for r in runs):
            work_summary = {key: stats([r['work'][key] for r in runs]) for key in runs[0]['work']}
        self.data = dict(schema_version=5, metadata=metadata, fault_model=metadata['fault_model'], protocol='whcc', source_protocol=source_protocol, status='ok',
                         output_bits=config['node_params'].get('output_bits', 1), config=config, runs=runs, summary=dict(
                             count=len(runs), requested_runs=config['bench_params']['runs'], sample_unit='run',
                             error_bar_method='min_max', work=work_summary, latency_ms=stats([r['latency_ms'] for r in runs]),
                             total_sent_bytes=stats([r['total_sent_bytes'] for r in runs]),
                             avg_sent_bytes_per_active_party=stats([r['avg_sent_bytes'] for r in runs]),
                             avg_sent_bytes_per_honest_party=stats([r['avg_honest_sent_bytes'] for r in runs]),
                             honest_sent_bytes=stats([r['honest_sent_bytes'] for r in runs]),
                             byzantine_sent_bytes=stats([r['byzantine_sent_bytes'] for r in runs])),
                         measurement=dict(latency='synchronizer monotonic START to same-coin FINISH weight > T',
                                          prepare='distinct PREPAREOK weight > W-T',
                                          bandwidth='mean of per-party log counters for every active party, including parties aborted before output',
                                          bandwidth_window='PREPARE through STOP receipt and party process exit; control channel excluded',
                                          termination='quorum completion, not all-party completion',
                                          implementation=('full public-record WRBC baseline'
                                                          if runs[0]['build'].get('implementation', 'full-public-record-wrbc-v1') == 'full-public-record-wrbc-v1'
                                                          else runs[0]['build']['implementation'])),
                         artifacts=self.directory)

    @staticmethod
    def _one(events, kind, optional=False):
        found = [e for e in events if e.get('kind') == kind]
        if len(found) != 1 and not (optional and not found):
            raise ParseError('Expected {} {}'.format('at most one' if optional else 'one', kind))
        return found[0] if found else None

    @classmethod
    def process(cls, directory, faults=None):
        directory = Path(directory)
        try:
            config = json.loads((directory/'resolved-policy.json').read_text(encoding='utf8'))
            bench = config['bench_params']
            if type(bench['runs']) is not int or bench['runs'] < 1:
                raise ParseError('runs must be a positive integer')
            if faults is not None and faults != bench['faults']:
                raise ParseError('Fault count does not match saved policy')
            faults_info = fault_metadata(bench)
            byzantine = faults_info['byzantine_nodes']
            honest = faults_info['honest_nodes']
            active = sorted(set(range(bench['nodes'])) - set(bench['faulty_nodes']))
            weights, threshold = bench['weights'], bench['threshold']
            output_bits = config['node_params'].get('output_bits', 1)
            if type(output_bits) is not int or not 1 <= output_bits <= 252 or config['node_params']['rounding_bits'] + output_bits + 1 > 254:
                raise ParseError('Invalid output bit width')
            services = {'wrbc', 'wra', 'wgather', 'wbinaa', 'private', 'recovery'}
            runs, sessions = [], set()
            for index in range(1, bench['runs']+1):
                run_path = directory/'run-{:03}'.format(index)
                manifest = json.loads((run_path/'run.json').read_text(encoding='utf8'))
                services = {'wrbc', 'wra', 'wgather', 'wbinaa', 'private', 'recovery'}
                if manifest['build'].get('implementation') in ('compact-header-striped-wavid-v1', 'compact-header-striped-wavid-v2', 'compact-header-striped-wavid-v3-cpu', 'compact-header-striped-wavid-v4-coding', 'compact-header-striped-wavid-v5-reuse'):
                    services.add('wavid')
                if manifest['build'].get('implementation') in ('compact-header-striped-wavid-v4-coding', 'compact-header-striped-wavid-v5-reuse'):
                    block = config['node_params'].get('bulk_block_bytes', 32)
                    if (type(block) is not int or not 32 <= block <= 4096 or block % 2
                            or manifest['build'].get('coding_block_bytes') != block
                            or manifest['build'].get('control_coding_block_bytes') != 32):
                        raise ParseError('Invalid or inconsistent coding parameters')
                session = manifest['session']
                epoch = config['node_params']['epoch'] + index-1
                if session in sessions or manifest['epoch'] != epoch or manifest['active_parties'] != active:
                    raise ParseError('Duplicate session or mismatched run manifest')
                sessions.add(session)
                if byzantine and manifest.get('schema_version') != 2:
                    raise ParseError('Byzantine benchmark requires role-aware run manifest')
                if manifest.get('schema_version') == 2 and (manifest.get('byzantine_nodes') != byzantine
                        or manifest.get('byzantine_behavior') != bench.get('byzantine_behavior', 'recovery-stress')):
                    raise ParseError('Byzantine role manifest mismatch')
                if manifest.get('schema_version') in (1, 2):
                    expected_id = policy_metadata(bench, config['node_params'])['configuration_id']
                    if manifest.get('configuration_id') != expected_id:
                        raise ParseError('Run configuration differs from saved policy')
                    circuit = manifest.get('circuit', {})
                    if (set(circuit) != {'gates', 'public_bytes'} or
                            any(type(v) is not int or v < 0 for v in circuit.values()) or
                            not isinstance(manifest.get('environment'), dict)):
                        raise ParseError('Missing or invalid run metadata')
                elif manifest.get('schema_version') is not None:
                    raise ParseError('Unsupported run manifest schema')
                sync = records(run_path/'logs'/'synchronizer.log')
                if any(e.get('session') != session or e.get('epoch') != epoch or e.get('output_bits', 1) != output_bits for e in sync):
                    raise ParseError('Synchronizer session/epoch mismatch')
                start = cls._one(sync, 'sync_start')
                result = cls._one(sync, 'sync_result')
                prepared = start['prepared']
                if (not isinstance(prepared, list) or any(type(i) is not int or i not in active for i in prepared)
                        or len(set(prepared)) != len(prepared)):
                    raise ParseError('Invalid PREPAREOK identity set')
                prepared_weight = sum(weights[i] for i in prepared)
                if prepared_weight <= sum(weights)-threshold or int(start['prepared_weight']) != prepared_weight:
                    raise ParseError('PREPAREOK weight must be strictly > W-T')
                if not valid_coin(result.get('coin'), output_bits):
                    raise ParseError('Invalid synchronizer coin')
                if type(result.get('latency_us')) is not int or result['latency_us'] < 0 or result['started_us'] != start['started_us']:
                    raise ParseError('Invalid synchronizer timing')
                finishes = {int(p): value for p, value in result['finishes'].items()}
                if len(finishes) != len(result['finishes']) or any(p not in active or not valid_coin(v, output_bits) for p, v in finishes.items()):
                    raise ParseError('Invalid FINISH identities/results')
                finish_weight = sum(weights[p] for p, v in finishes.items() if v == result['coin'])
                if finish_weight <= threshold or int(result['finish_weight']) != finish_weight:
                    raise ParseError('Matching FINISH weight must be strictly > T')
                expected = {'primary-{}.log'.format(i) for i in active}
                if {p.name for p in (run_path/'logs').glob('primary-*.log')} != expected:
                    raise ParseError('Missing or unexpected party logs')
                parties = []
                sums = dict.fromkeys(services, 0)
                for party in active:
                    events = records(run_path/'logs'/'primary-{}.log'.format(party))
                    if any(e.get('party') != party or e.get('epoch') != epoch or e.get('session') != session or e.get('output_bits', 1) != output_bits for e in events):
                        raise ParseError('Mismatched party/session/epoch')
                    stopped = cls._one(events, 'stopped')
                    ready = cls._one(events, 'ready', optional=True)
                    local_start = cls._one(events, 'start', optional=True)
                    coin = cls._one(events, 'coin', optional=True)
                    counter = cls._one(events, 'bandwidth')
                    behavior = cls._one(events, 'behavior', optional=True)
                    work = cls._one(events, 'work', optional=True)
                    expected_behavior = faults_info['byzantine_behavior'] if party in byzantine else 'honest'
                    if manifest.get('schema_version') == 2:
                        if behavior is None or behavior.get('behavior') != expected_behavior or work is None:
                            raise ParseError('Missing or incorrect node behavior/work log')
                        counters = ['terminal_checks', 'decoded_terminal_checks', 'rejected_terminals', 'forged_terminal_sends']
                        if (any(type(work.get(k)) is not int or work[k] < 0 for k in counters)
                                or work['rejected_terminals'] > work['terminal_checks']
                                or work['decoded_terminal_checks'] > work['terminal_checks']
                                or work.get('corrupted_public') != (party in byzantine and local_start is not None)):
                            raise ParseError('Invalid adversarial work counters')
                        if party in byzantine and (coin is not None or party in finishes):
                            raise ParseError('recovery-stress must withhold output/FINISH')
                    if party in prepared and ready is None:
                        raise ParseError('PREPAREOK without ready party log')
                    if stopped.get('started') != bool(local_start) or stopped.get('coin') != (coin['coin'] if coin else None):
                        raise ParseError('STOP state does not match party log')
                    if coin is not None:
                        if (local_start is None or ready is None or not valid_coin(coin.get('coin'), output_bits)
                                or coin['coin'] != result['coin'] or coin['started_us'] != local_start['started_us']):
                            raise ParseError('Invalid/disagreeing local coin')
                    if party in finishes and (coin is None or coin['coin'] != finishes[party]):
                        raise ParseError('FINISH not backed by local coin log')
                    values = counter['per_service_sent_bytes']
                    if (counter.get('source') != 'linux-af-packet-collector' or set(values) != services
                            or any(type(v) is not int or v < 0 for v in values.values())
                            or type(counter['total_sent_bytes']) is not int or sum(values.values()) != counter['total_sent_bytes']):
                        raise ParseError('Invalid party bandwidth log')
                    for service, value in values.items():
                        sums[service] += value
                    parties.append(dict(party=party, role='byzantine' if party in byzantine else 'honest',
                                        behavior=expected_behavior, work=work, coin=coin['coin'] if coin else None,
                                        reported_finish=party in finishes, stopped=True,
                                        total_sent_bytes=counter['total_sent_bytes'], per_service_sent_bytes=values))
                bandwidth = json.loads((run_path/'bandwidth.json').read_text(encoding='utf8'))
                if (bandwidth['dropped_packets'] != 0 or bandwidth['metric'] != 'tcp_payload_bytes'
                        or bandwidth['per_service_sent_bytes'] != sums or sum(sums.values()) <= 0
                        or bandwidth['total_sent_bytes'] != sum(sums.values())
                        or bandwidth['per_party_sent_bytes'] != {str(p['party']): p['per_service_sent_bytes'] for p in parties}):
                    raise ParseError('Missing, inconsistent or lossy bandwidth measurement')
                honest_bytes = sum(p['total_sent_bytes'] for p in parties if p['party'] in honest)
                byzantine_bytes = sum(p['total_sent_bytes'] for p in parties if p['party'] in byzantine)
                work_totals = None
                if all(p['work'] is not None for p in parties):
                    work_totals = dict(
                        honest_terminal_checks=sum(p['work']['terminal_checks'] for p in parties if p['party'] in honest),
                        honest_decoded_terminal_checks=sum(p['work']['decoded_terminal_checks'] for p in parties if p['party'] in honest),
                        honest_rejected_terminals=sum(p['work']['rejected_terminals'] for p in parties if p['party'] in honest),
                        honest_rejected_dealer_observations=sum(len(p['work']['rejected_dealers']) for p in parties if p['party'] in honest),
                        byzantine_forged_terminal_sends=sum(p['work']['forged_terminal_sends'] for p in parties if p['party'] in byzantine))
                runs.append(dict(run=index, work=work_totals, epoch=epoch, session=session, output_bits=output_bits, coin=result['coin'],
                                 quorum_reached=True, count=1, parties=parties,
                                 environment=manifest.get('environment'), circuit=manifest.get('circuit'),
                                 configuration_id=manifest.get('configuration_id'),
                                 latency_ms=result['latency_us']/1000, synchronizer=result,
                                 prepared=prepared, prepared_weight=prepared_weight, finish_weight=finish_weight,
                                 matching_finish_count=sum(v == result['coin'] for v in finishes.values()),
                                 finish_weight_ratio=finish_weight / sum(weights),
                                 total_sent_bytes=sum(sums.values()), honest_sent_bytes=honest_bytes,
                                 byzantine_sent_bytes=byzantine_bytes, avg_honest_sent_bytes=honest_bytes/len(honest),
                                 avg_sent_bytes=statistics.mean(p['total_sent_bytes'] for p in parties),
                                 bandwidth=bandwidth, build=manifest['build']))
            return cls(config, runs, directory)
        except ParseError:
            raise
        except (OSError, ValueError, KeyError, TypeError, ZeroDivisionError) as e:
            raise ParseError('Cannot parse complete synchronized benchmark: {}'.format(e))

    def result(self):
        b = self.configs['bench_params']
        lines = ['', '-----------------------------------------', ' SUMMARY:',
                 '-----------------------------------------', ' + CONFIG:',
                 ' Protocol: whcc', ' Output bits: {}'.format(self.data['output_bits']), ' Policy: {}'.format(b['name']),
                 ' Committee size: {} node(s)'.format(self.committee_size),
                 ' Weights: {}'.format(b['weights']), ' Threshold: {}'.format(b['threshold']),
                 ' Faults: {} silent node(s) {}'.format(self.faults, b['faulty_nodes']),
                 ' Byzantine nodes: {} ({})'.format(self.data['fault_model']['byzantine_nodes'], self.data['fault_model']['byzantine_behavior']),
                 ' Weight budget: W={}, T={}, F={}, actual B={} (silent={}, Byzantine={})'.format(
                     *[self.data['fault_model'][k] for k in ['total_weight', 'protocol_threshold', 'fault_weight_threshold',
                                                           'corrupted_weight', 'silent_weight', 'byzantine_weight']]),
                 ' Runs: {}'.format(len(self.runs)),
                 ' Experiment: {}'.format(self.data['metadata']['experiment_id']),
                 ' Weight profile: {}'.format(self.data['metadata']['weight_profile']), '', ' + COIN RESULTS:']
        for run in self.runs:
            lines.append(' Run {}: coin={}, synchronizer latency={:.3f} ms, FINISH weight={} > T={}, avg sent={:,.2f} B/party'.format(
                run['run'], run['coin'], run['latency_ms'], run['finish_weight'], b['threshold'], run['avg_sent_bytes']))
            for party in run['parties']:
                lines.append('  Primary {}: coin={}, {:,} B sent, stopped=True'.format(party['party'], party['coin'], party['total_sent_bytes']))
        s = self.data['summary']
        for label, key, unit in [('Synchronizer latency', 'latency_ms', 'ms'),
                                 ('Mean sent bytes per active party', 'avg_sent_bytes_per_active_party', 'B'),
                                 ('Mean sent bytes per honest party', 'avg_sent_bytes_per_honest_party', 'B'),
                                 ('Byzantine sent bytes per coin', 'byzantine_sent_bytes', 'B'),
                                 ('Total sent bytes per coin', 'total_sent_bytes', 'B')]:
            metric = s[key]
            deviation = '{:,.3f}'.format(metric['stdev']) if metric['stdev'] is not None else 'N/A (one run)'
            lines.append(' {}: mean={:,.3f} {}, range=[{:,.3f}, {:,.3f}] {}, sample stdev={}'.format(
                label, metric['mean'], unit, metric['min'], metric['max'], unit, deviation))
        if s['work'] is not None:
            lines.append(' Observed work (mean/run): honest rejected terminals={:.2f}, rejected dealer observations={:.2f}, Byzantine forged sends={:.2f}'.format(
                s['work']['honest_rejected_terminals']['mean'], s['work']['honest_rejected_dealer_observations']['mean'],
                s['work']['byzantine_forged_terminal_sends']['mean']))
        lines += [' Error bars: observed min/max across runs, not a confidence interval.',
                  ' Completion: matching FINISH weight > T; STOP aborts remaining work.',
                  ' Bandwidth: TCP payload until STOP/exit, excluding synchronizer traffic.',
                  ' Implementation: {}'.format(self.data['measurement']['implementation']),
                  ' Artifacts: {}'.format(self.directory), '-----------------------------------------', '']
        return '\n'.join(lines)

    def print(self, filename):
        filename = Path(filename)
        filename.parent.mkdir(parents=True, exist_ok=True)
        filename.write_text(self.result(), encoding='utf8')
        write_json(filename.with_suffix('.json'), self.data)

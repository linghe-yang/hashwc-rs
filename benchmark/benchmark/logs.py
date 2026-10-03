# Copyright(C) Facebook, Inc. and its affiliates.
# Single-coin latency and bandwidth results; deliberately no throughput fields.
import json
import statistics
import re
from pathlib import Path

from benchmark.config import write_json


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
            if isinstance(value, dict) and value.get('protocol') == 'commoncoin':
                result.append(value)
    return result


def valid_coin(value, bits):
    if bits == 1:
        return type(value) is int and value in (0, 1)
    return (isinstance(value, str) and re.fullmatch(r'0x[0-9a-f]{' + str((bits+3)//4) + '}', value) is not None
            and int(value, 16) < (1 << bits))


def stats(values):
    return dict(mean=statistics.mean(values), min=min(values), max=max(values),
                stdev=statistics.stdev(values) if len(values) > 1 else 0)


class LogParser:
    def __init__(self, config, runs, directory):
        self.configs = config
        self.runs = runs
        self.directory = str(Path(directory).resolve())
        self.faults = config['bench_params']['faults']
        self.committee_size = config['bench_params']['nodes']
        self.data = dict(schema_version=3, protocol='commoncoin', status='ok',
                         output_bits=config['node_params'].get('output_bits', 1), config=config, runs=runs, summary=dict(
                             count=len(runs), latency_ms=stats([r['latency_ms'] for r in runs]),
                             total_sent_bytes=stats([r['total_sent_bytes'] for r in runs]),
                             avg_sent_bytes_per_active_party=stats([r['avg_sent_bytes'] for r in runs])),
                         measurement=dict(latency='synchronizer monotonic START to same-coin FINISH weight > T',
                                          prepare='distinct PREPAREOK weight > W-T',
                                          bandwidth='mean of per-party log counters for every active party, including parties aborted before output',
                                          bandwidth_window='PREPARE through STOP receipt and party process exit; control channel excluded',
                                          termination='quorum completion, not all-party completion',
                                          implementation='full public-record WRBC baseline'),
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
            if faults is not None and faults != bench['faults']:
                raise ParseError('Fault count does not match saved policy')
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
                session = manifest['session']
                epoch = config['node_params']['epoch'] + index-1
                if session in sessions or manifest['epoch'] != epoch or manifest['active_parties'] != active:
                    raise ParseError('Duplicate session or mismatched run manifest')
                sessions.add(session)
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
                    parties.append(dict(party=party, coin=coin['coin'] if coin else None,
                                        reported_finish=party in finishes, stopped=True,
                                        total_sent_bytes=counter['total_sent_bytes'], per_service_sent_bytes=values))
                bandwidth = json.loads((run_path/'bandwidth.json').read_text(encoding='utf8'))
                if (bandwidth['dropped_packets'] != 0 or bandwidth['metric'] != 'tcp_payload_bytes'
                        or bandwidth['per_service_sent_bytes'] != sums or sum(sums.values()) <= 0
                        or bandwidth['total_sent_bytes'] != sum(sums.values())
                        or bandwidth['per_party_sent_bytes'] != {str(p['party']): p['per_service_sent_bytes'] for p in parties}):
                    raise ParseError('Missing, inconsistent or lossy bandwidth measurement')
                runs.append(dict(run=index, epoch=epoch, session=session, output_bits=output_bits, coin=result['coin'],
                                 quorum_reached=True, count=1, parties=parties,
                                 latency_ms=result['latency_us']/1000, synchronizer=result,
                                 prepared=prepared, prepared_weight=prepared_weight, finish_weight=finish_weight,
                                 total_sent_bytes=sum(sums.values()),
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
                 ' Protocol: commoncoin', ' Output bits: {}'.format(self.data['output_bits']), ' Policy: {}'.format(b['name']),
                 ' Committee size: {} node(s)'.format(self.committee_size),
                 ' Weights: {}'.format(b['weights']), ' Threshold: {}'.format(b['threshold']),
                 ' Faults: {} silent node(s) {}'.format(self.faults, b['faulty_nodes']),
                 ' Runs: {}'.format(len(self.runs)), '', ' + COIN RESULTS:']
        for run in self.runs:
            lines.append(' Run {}: coin={}, synchronizer latency={:.3f} ms, FINISH weight={} > T={}, avg sent={:,.2f} B/party'.format(
                run['run'], run['coin'], run['latency_ms'], run['finish_weight'], b['threshold'], run['avg_sent_bytes']))
            for party in run['parties']:
                lines.append('  Primary {}: coin={}, {:,} B sent, stopped=True'.format(party['party'], party['coin'], party['total_sent_bytes']))
        s = self.data['summary']
        lines += [' Synchronizer latency (mean across runs): {:.3f} ms'.format(s['latency_ms']['mean']),
                  ' Mean sent bytes per active party: {:,.2f} B'.format(s['avg_sent_bytes_per_active_party']['mean']),
                  ' Total sent bytes per coin (mean across runs): {:,.0f} B'.format(s['total_sent_bytes']['mean']),
                  ' Completion: matching FINISH weight > T; STOP aborts remaining work.',
                  ' Bandwidth: TCP payload until STOP/exit, excluding synchronizer traffic.',
                  ' Implementation: full public-record WRBC baseline',
                  ' Artifacts: {}'.format(self.directory), '-----------------------------------------', '']
        return '\n'.join(lines)

    def print(self, filename):
        filename = Path(filename)
        filename.parent.mkdir(parents=True, exist_ok=True)
        filename.write_text(self.result(), encoding='utf8')
        write_json(filename.with_suffix('.json'), self.data)

import copy
import json
import socket
import struct
import tempfile
import time
import unittest
from pathlib import Path

from benchmark.bandwidth import BandwidthMeter
from benchmark.config import BenchParameters, ConfigError, LocalCommittee, NodeParameters, Policy, write_json
from benchmark.logs import LogParser, ParseError


class PolicyTests(unittest.TestCase):
    def test_distribution_and_weight_bound(self):
        policy = BenchParameters(dict(nodes=4, weights=dict(distribution='linear', scale=100), threshold='auto'))
        self.assertEqual(policy.weights, [100, 200, 300, 400])
        self.assertEqual(policy.threshold, 333)
        with self.assertRaises(ConfigError):
            BenchParameters(dict(nodes=4, weights=[1, 1, 1, 8], threshold=3, faults=1))
        valid = BenchParameters(dict(nodes=4, weights=[1, 2, 3, 4], threshold=3, faults=1, faulty_nodes=[0]))
        self.assertEqual(valid.faulty_nodes, [0])

    def test_invalid_policy_ports_and_parameters(self):
        for data in [dict(nodes=4, weights=[1]), dict(nodes=True), dict(nodes=4, threshold=2),
                     dict(nodes=4, weigths=[1]*4), dict(nodes=4, duration=float('nan')),
                     dict(nodes=4, faults=1, faulty_nodes=[True])]:
            with self.subTest(data=data), self.assertRaises(ConfigError):
                BenchParameters(data)
        with self.assertRaises(ConfigError):
            BenchParameters(dict(nodes=4)).ports(NodeParameters(dict(port_stride=1)))
        with self.assertRaises(ConfigError):
            BenchParameters(dict(nodes=4, base_port=65530)).ports(NodeParameters({}))
        with self.assertRaises(ConfigError):
            NodeParameters(dict(rounding_bits=253))

    def test_output_width_defaults_and_ax_capacity(self):
        self.assertEqual(NodeParameters({}).json['output_bits'], 1)
        self.assertEqual(NodeParameters(dict(output_bits=128)).json['output_bits'], 128)
        self.assertEqual(NodeParameters(dict(output_bits=189)).json['output_bits'], 189)
        self.assertEqual(NodeParameters(dict(rounding_bits=1, output_bits=252)).json['output_bits'], 252)
        for data in [dict(output_bits=0), dict(output_bits=190), dict(output_bits=True),
                     dict(rounding_bits=1, output_bits=253)]:
            with self.subTest(data=data), self.assertRaises(ConfigError):
                NodeParameters(data)

    def test_upstream_bundle_pair_keys_and_fresh_sessions(self):
        b = BenchParameters(dict(nodes=4, weights=[1, 2, 3, 4], threshold=3))
        with tempfile.TemporaryDirectory() as directory:
            a = LocalCommittee(b, NodeParameters({}))
            a.print(directory)
            nodes = [json.loads((Path(directory)/'.node-{}.json'.format(i)).read_text()) for i in range(4)]
            for i in range(4):
                self.assertEqual(nodes[i]['weights'], ['0x1', '0x2', '0x3', '0x4'])
                self.assertEqual(nodes[i]['session_id'], nodes[0]['session_id'])
                for j in range(4):
                    self.assertEqual(nodes[i]['sk_map'][str(j)], nodes[j]['sk_map'][str(i)])
                    self.assertEqual(len(nodes[i]['sk_map'][str(j)]), 32)
            sync = json.loads((Path(directory)/'.synchronizer.json').read_text())
            for i in range(4):
                self.assertEqual(nodes[i]['sk_map']['4'], sync['sk_map'][str(i)])
            self.assertEqual(sync['net_map']['4'], '127.0.0.1:20024')
            self.assertNotEqual(a.session_id, LocalCommittee(b, NodeParameters({})).session_id)


class BandwidthTests(unittest.TestCase):
    def packet(self, size, source=40000, target=20000):
        packet = bytearray(14+20+20+size)
        packet[12:14] = b'\x08\x00'
        packet[14] = 0x45
        packet[16:18] = (40+size).to_bytes(2, 'big')
        packet[23] = 6
        struct.pack_into('!HH', packet, 34, source, target)
        packet[46] = 0x50
        return bytes(packet)

    def test_loopback_direction_application_ack_and_header_exclusion(self):
        ports = {20000: dict(service='wrbc', party=0)}
        self.assertEqual(BandwidthMeter.decode(self.packet(100), 4, ports), ('wrbc', 100))
        self.assertIsNone(BandwidthMeter.decode(self.packet(100), 0, ports))
        self.assertEqual(BandwidthMeter.decode(self.packet(32, 20000, 40000), 4, ports), ('wrbc', 32))
        self.assertEqual(BandwidthMeter.decode(self.packet(0), 4, ports), ('wrbc', 0))
        self.assertIsNone(BandwidthMeter.decode(self.packet(90, target=20001), 4, ports))

    def test_sender_attribution_handles_fragmented_header_retransmission_and_application_ack(self):
        ports = {20000: dict(service='wrbc', party=0)}
        meter = BandwidthMeter(ports, [0, 1])
        syn = bytearray(self.packet(0))
        struct.pack_into('!I', syn, 38, 100)
        syn[47] = 2
        meter.attribute(syn, 'wrbc', 0)
        header = (120).to_bytes(4, 'little') + bytes(32) + (1).to_bytes(8, 'little') + (0).to_bytes(8, 'little')
        def segment(payload, seq):
            packet = bytearray(self.packet(len(payload)))
            struct.pack_into('!I', packet, 38, seq)
            packet[54:] = payload
            return packet
        meter.attribute(segment(header[4:], 105), 'wrbc', 48)
        self.assertEqual(meter.unattributed, 48)
        meter.attribute(segment(header[:4], 101), 'wrbc', 4)
        meter.attribute(segment(header[:4], 101), 'wrbc', 4)
        meter.attribute(self.packet(32, 20000, 40000), 'wrbc', 32)
        self.assertEqual(meter.per_party, {0: {'wrbc':32}, 1: {'wrbc':56}})
        self.assertEqual(meter.unattributed, 0)

    def test_kernel_reset_from_silent_party_is_not_application_traffic(self):
        meter = BandwidthMeter({20000: dict(service='wrbc', party=0)}, [1])
        reset = bytearray(self.packet(0, 20000, 40000))
        reset[47] = 0x14
        meter.attribute(reset, 'wrbc', 0)
        self.assertEqual(meter.per_party, {1: {'wrbc':0}})

    def test_real_loopback_capture_counts_payload_once(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        meter = BandwidthMeter({listener.getsockname()[1]: dict(service='test', party=0)})
        meter.start()
        try:
            with socket.create_connection(listener.getsockname()) as client:
                peer, _ = listener.accept()
                with peer:
                    client.sendall(b'x'*1234)
                    received = b''
                    while len(received) < 1234:
                        received += peer.recv(4096)
                    peer.sendall(b'y'*32)
                    self.assertEqual(len(client.recv(32)), 32)
            time.sleep(0.05)
            result = meter.stop()
            self.assertEqual(result['total_sent_bytes'], 1266)
            self.assertEqual(result['dropped_packets'], 0)
        finally:
            if meter.thread is not None:
                meter.stop()
            listener.close()


class LogTests(unittest.TestCase):
    def fixture(self, directory, output_bits=1):
        directory = Path(directory)
        bench = BenchParameters(dict(name='test', nodes=4)).json
        write_json(directory/'resolved-policy.json', dict(bench_params=bench, node_params=NodeParameters(dict(output_bits=output_bits)).json))
        run = directory/'run-001'
        write_json(run/'run.json', dict(session='ab'*32, epoch=0, active_parties=list(range(4)), build={}))
        totals = {s: 100 for s in ['wrbc', 'wra', 'wgather', 'wbinaa', 'private', 'recovery']}
        per_party = {str(i): {s:25 for s in totals} for i in range(4)}
        write_json(run/'bandwidth.json', dict(metric='tcp_payload_bytes', dropped_packets=0,
                                             per_service_sent_bytes=totals, total_sent_bytes=600,
                                             per_party_sent_bytes=per_party))
        (run/'logs').mkdir()
        common = dict(protocol='commoncoin', epoch=0, session='ab'*32, output_bits=output_bits)
        coin_value = 1 if output_bits == 1 else '0x80000000000000000000000000000001'
        sync = [dict(common, kind='sync_start', started_us=1000000, prepared=list(range(4)), prepared_weight='4'),
                dict(common, kind='sync_result', coin=coin_value, started_us=1000000, completed_us=1005000,
                     latency_us=5000, finishes={'0':coin_value, '1':coin_value}, finish_weight='2')]
        (run/'logs'/'synchronizer.log').write_text(''.join(json.dumps(e)+'\n' for e in sync))
        for i in range(4):
            base = dict(common, party=i)
            events = [dict(base, kind='ready'), dict(base, kind='start', started_us=1000000),
                      dict(base, kind='coin', coin=coin_value, started_us=1000000, completed_us=1001000+i, latency_us=1000+i),
                      dict(base, kind='stopped', coin=coin_value, started=True),
                      dict(base, kind='bandwidth', source='linux-af-packet-collector', total_sent_bytes=150,
                           per_service_sent_bytes=per_party[str(i)])]
            (run/'logs'/'primary-{}.log'.format(i)).write_text(''.join(json.dumps(e)+'\n' for e in events))
        return run

    def test_summary_and_result_files_have_no_throughput(self):
        with tempfile.TemporaryDirectory() as directory:
            self.fixture(directory)
            parser = LogParser.process(directory)
            self.assertEqual(parser.data['summary']['total_sent_bytes']['mean'], 600)
            self.assertEqual(parser.data['summary']['latency_ms']['mean'], 5)
            self.assertEqual(parser.data['summary']['avg_sent_bytes_per_active_party']['mean'], 150)
            self.assertNotIn('throughput', json.dumps(parser.data))
            parser.print(Path(directory)/'summary.txt')
            self.assertEqual(json.loads((Path(directory)/'summary.json').read_text())['status'], 'ok')

    def test_multibit_result_roundtrip_keeps_full_word(self):
        with tempfile.TemporaryDirectory() as directory:
            self.fixture(directory, 128)
            parser = LogParser.process(directory)
            self.assertEqual(parser.data['output_bits'], 128)
            self.assertEqual(parser.data['schema_version'], 3)
            expected = '0x80000000000000000000000000000001'
            self.assertEqual(parser.data['runs'][0]['coin'], expected)
            parser.print(Path(directory)/'summary.txt')
            self.assertEqual(json.loads((Path(directory)/'summary.json').read_text())['runs'][0]['coin'], expected)

    def test_multibit_noncanonical_mismatched_or_truncated_results_are_rejected(self):
        for bad in [1, '0x1', '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
                    '0x100000000000000000000000000000000', '0x90000000000000000000000000000001', None]:
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as directory:
                run = self.fixture(directory, 128)
                path = run/'logs'/'synchronizer.log'
                events = [json.loads(line) for line in path.read_text().splitlines()]
                events[1]['finishes']['1'] = bad
                path.write_text(''.join(json.dumps(e)+'\n' for e in events))
                with self.assertRaises(ParseError):
                    LogParser.process(directory)
        with tempfile.TemporaryDirectory() as directory:
            run = self.fixture(directory, 128)
            path = run/'logs'/'primary-0.log'
            events = [json.loads(line) for line in path.read_text().splitlines()]
            events[0]['output_bits'] = 1
            path.write_text(''.join(json.dumps(e)+'\n' for e in events))
            with self.assertRaises(ParseError):
                LogParser.process(directory)

    def test_missing_duplicate_disagreeing_or_replayed_coin_is_rejected(self):
        for change in ['missing', 'duplicate', 'disagree', 'replay']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                run = self.fixture(directory)
                path = run/'logs'/'primary-0.log'
                events = [json.loads(line) for line in path.read_text().splitlines()]
                coin = next(e for e in events if e['kind'] == 'coin')
                if change == 'missing':
                    events.remove(coin)
                elif change == 'duplicate':
                    events.append(coin)
                else:
                    coin['coin' if change == 'disagree' else 'session'] = 0 if change == 'disagree' else 'cd'*32
                path.write_text(''.join(json.dumps(e)+'\n' for e in events))
                with self.assertRaises(ParseError):
                    LogParser.process(directory)

    def test_stop_without_local_output_is_valid_and_included_in_bandwidth_average(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.fixture(directory)
            path = run/'logs'/'primary-3.log'
            events = [json.loads(line) for line in path.read_text().splitlines()]
            events = [e for e in events if e['kind'] != 'coin']
            next(e for e in events if e['kind'] == 'stopped')['coin'] = None
            path.write_text(''.join(json.dumps(e)+'\n' for e in events))
            result = LogParser.process(directory).data
            self.assertIsNone(result['runs'][0]['parties'][3]['coin'])
            self.assertEqual(result['runs'][0]['avg_sent_bytes'], 150)
            self.assertEqual(result['runs'][0]['latency_ms'], 5)

    def test_exact_threshold_is_insufficient_and_missing_sync_log_never_falls_back_to_mean(self):
        for kind in ['prepare', 'finish', 'missing']:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                run = self.fixture(directory)
                path = run/'logs'/'synchronizer.log'
                events = [json.loads(line) for line in path.read_text().splitlines()]
                if kind == 'prepare':
                    events[0].update(prepared=[0, 1, 2], prepared_weight='3')
                elif kind == 'finish':
                    events[1].update(finishes={'0':1}, finish_weight='1')
                else:
                    events = events[:1]
                path.write_text(''.join(json.dumps(e)+'\n' for e in events))
                with self.assertRaises(ParseError):
                    LogParser.process(directory)

    def test_dropped_packets_invalidate_bandwidth(self):
        with tempfile.TemporaryDirectory() as directory:
            run = self.fixture(directory)
            path = run/'bandwidth.json'
            data = json.loads(path.read_text())
            data['dropped_packets'] = 1
            write_json(path, data)
            with self.assertRaises(ParseError):
                LogParser.process(directory)


if __name__ == '__main__':
    unittest.main()

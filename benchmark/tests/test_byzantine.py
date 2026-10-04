import json
import tempfile
import unittest
from pathlib import Path

import test_benchmark
from benchmark.commands import CommandMaker
from benchmark.config import BenchParameters, ConfigError, NodeParameters, LocalCommittee, Policy, write_json
from benchmark.logs import LogParser, ParseError
from benchmark.metadata import policy_metadata, fault_metadata


class ByzantineTests(unittest.TestCase):
    def test_inclusive_budget_and_strict_protocol_threshold(self):
        b = BenchParameters(dict(nodes=4, weights=[3]*4, threshold=4, fault_weight_threshold=3, byzantine_nodes=[3]))
        self.assertEqual((b.corrupted_weight, b.fault_weight_threshold), (3, 3))
        self.assertEqual(BenchParameters(b.json).json, b.json)
        self.assertEqual(fault_metadata(b.json)['total_weight'], '12')
        mixed = BenchParameters(dict(nodes=10, threshold=3, faults=1, faulty_nodes=[9], byzantine_nodes=[8]))
        self.assertEqual(mixed.corrupted_weight, 2)
        for change in [dict(fault_weight_threshold=2), dict(fault_weight_threshold=4),
                       dict(byzantine_nodes=[3, 3]), dict(byzantine_nodes=[True]), dict(byzantine_nodes=[4]),
                       dict(byzantine_nodes='3'), dict(faults=1, faulty_nodes=[3]),
                       dict(faults=1, faulty_nodes=[2]), dict(byzantine_behavior='unknown')]:
            data = dict(nodes=4, weights=[3]*4, threshold=4, fault_weight_threshold=3, byzantine_nodes=[3])
            data.update(change)
            with self.subTest(change=change), self.assertRaises(ConfigError):
                BenchParameters(data)
        # Unit weights and T=1 cannot tolerate B=1 in the existing strict model.
        with self.assertRaises(ConfigError):
            BenchParameters(dict(nodes=4, byzantine_nodes=[3]))

    def test_roles_affect_configuration_identity_and_launch_arguments(self):
        b = BenchParameters(dict(nodes=4, weights=[3]*4, threshold=4, byzantine_nodes=[3]))
        node = NodeParameters({})
        honest = BenchParameters(dict(nodes=4, weights=[3]*4, threshold=4))
        self.assertNotEqual(policy_metadata(b.json, node.json)['configuration_id'], policy_metadata(honest.json, node.json)['configuration_id'])
        command = CommandMaker.run_primary('node.json', 'parameters.json', behavior='recovery-stress')
        self.assertEqual(command[-2:], ['--behavior', 'recovery-stress'])
        with tempfile.TemporaryDirectory() as directory:
            LocalCommittee(b, node).print(directory)
            saved = json.loads((Path(directory)/'.node-3.json').read_text())
            self.assertEqual(saved['num_faults'], 1)
            self.assertNotIn('byzantine_nodes', saved)  # Still exactly upstream Node.
            path = Path(directory)/'policy.json'
            write_json(path, dict(bench_params=dict(fault_weight_threshold=3, byzantine_nodes=[3]),
                                  cases=[dict(nodes=4, weights=[3]*4, threshold=4)]))
            self.assertEqual(Policy(path).cases[0].byzantine_nodes, [3])

    def fixture(self, directory):
        path = test_benchmark.LogTests().fixture(directory)
        b = BenchParameters(dict(name='test', nodes=4, weights=[3]*4, threshold=4, byzantine_nodes=[3]))
        params = NodeParameters({}).json
        write_json(Path(directory)/'resolved-policy.json', dict(bench_params=b.json, node_params=params))
        manifest = json.loads((path/'run.json').read_text())
        manifest.update(schema_version=2, byzantine_nodes=[3], byzantine_behavior='recovery-stress',
                        configuration_id=policy_metadata(b.json, params)['configuration_id'],
                        circuit=dict(gates=1, public_bytes=100), environment=dict(network='linux-loopback'))
        write_json(path/'run.json', manifest)
        for logfile in (path/'logs').glob('*.log'):
            events = [json.loads(line) for line in logfile.read_text().splitlines()]
            if logfile.name == 'synchronizer.log':
                events[0]['prepared_weight'] = '12'
                events[1]['finish_weight'] = '6'
            else:
                party = events[0]['party']
                if party == 3:
                    events = [e for e in events if e['kind'] != 'coin']
                    next(e for e in events if e['kind'] == 'stopped')['coin'] = None
                common = {k: events[0][k] for k in ['protocol', 'epoch', 'session', 'output_bits', 'party']}
                events += [dict(common, kind='behavior', behavior='recovery-stress' if party == 3 else 'honest'),
                           dict(common, kind='work', terminal_checks=4, decoded_terminal_checks=4,
                                rejected_terminals=1 if party != 3 else 0, forged_terminal_sends=12 if party == 3 else 0,
                                rejected_dealers=[3] if party != 3 else [], corrupted_public=party == 3)]
            logfile.write_text(''.join(json.dumps(e)+'\n' for e in events))
        return path

    def test_role_aware_result_and_measured_work(self):
        with tempfile.TemporaryDirectory() as directory:
            self.fixture(directory)
            parser = LogParser.process(directory)
            result = parser.data
            self.assertEqual(result['fault_model']['corrupted_weight'], '3')
            self.assertEqual(result['fault_model']['protocol_threshold'], '4')
            self.assertEqual(result['fault_model']['fault_weight_threshold'], '3')
            self.assertEqual(result['runs'][0]['honest_sent_bytes'], 450)
            self.assertEqual(result['runs'][0]['byzantine_sent_bytes'], 150)
            self.assertEqual(result['summary']['avg_sent_bytes_per_honest_party']['mean'], 150)
            self.assertEqual(result['summary']['work']['honest_rejected_terminals']['mean'], 3)
            self.assertEqual(result['summary']['work']['byzantine_forged_terminal_sends']['mean'], 12)
            self.assertEqual(result['runs'][0]['parties'][3]['role'], 'byzantine')
            self.assertIn('actual B=3', parser.result())

    def test_wrong_roles_budget_or_manifest_cannot_be_misreported(self):
        for change in ['role', 'manifest', 'budget', 'missing_work']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                path = self.fixture(directory)
                if change in ('role', 'missing_work'):
                    logfile = path/'logs'/'primary-3.log'
                    events = [json.loads(line) for line in logfile.read_text().splitlines()]
                    if change == 'role':
                        next(e for e in events if e['kind'] == 'behavior')['behavior'] = 'honest'
                    else:
                        events = [e for e in events if e['kind'] != 'work']
                    logfile.write_text(''.join(json.dumps(e)+'\n' for e in events))
                elif change == 'manifest':
                    filename = path/'run.json'
                    data = json.loads(filename.read_text())
                    data['byzantine_nodes'] = []
                    write_json(filename, data)
                else:
                    filename = Path(directory)/'resolved-policy.json'
                    data = json.loads(filename.read_text())
                    data['bench_params']['fault_weight_threshold'] = 2
                    write_json(filename, data)
                with self.assertRaises(ParseError):
                    LogParser.process(directory)


if __name__ == '__main__':
    unittest.main()

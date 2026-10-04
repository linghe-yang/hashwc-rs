import copy
import json
import math
import shutil
import tempfile
import unittest
from pathlib import Path

import test_benchmark
from benchmark.config import BenchParameters, ConfigError, NodeParameters, Policy, write_json
from benchmark.logs import LogParser, ParseError, stats
from benchmark.metadata import policy_metadata


class MetadataTests(unittest.TestCase):
    def test_policy_metadata_inheritance_runs_precedence_and_roundtrip(self):
        data = dict(metadata=dict(experiment_id='scaling-v1', experiment_axis='weight_scale'),
                    bench_params=dict(runs=2), cases=[
                        dict(name='base', nodes=4, weights=dict(distribution='linear'), threshold=3),
                        dict(name='scaled', nodes=4, weights=dict(distribution='linear', scale=100),
                             threshold=300, runs=3, metadata=dict(experiment_id='override'))])
        original = copy.deepcopy(data)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'policy.json'
            write_json(path, data)
            policy = Policy(path)
            self.assertEqual([b.runs for b in policy.cases], [2, 3])
            self.assertEqual([b.runs for b in Policy(path, runs='4').cases], [4, 4])
            self.assertEqual(policy.cases[0].metadata['experiment_id'], 'scaling-v1')
            self.assertEqual(policy.cases[1].metadata['experiment_id'], 'override')
            self.assertEqual(policy.cases[1].metadata['experiment_axis'], 'weight_scale')
            self.assertEqual(policy.cases[1].metadata['weight_scale'], 100)
            self.assertEqual(policy.cases[0].metadata['weight_profile'], policy.cases[1].metadata['weight_profile'])
            for case in policy.cases:
                self.assertEqual(BenchParameters(case.json).json, case.json)
            for invalid in [0, -1, True, 'bad']:
                with self.assertRaises(ConfigError):
                    Policy(path, runs=invalid)
        self.assertEqual(data, original)
        self.assertEqual(BenchParameters(dict(nodes=4)).runs, 1)

    def test_provenance_unknowns_validation_and_large_weight_fingerprint(self):
        a = BenchParameters(dict(nodes=4, weights=[1, 2, 3, 4], threshold=3))
        self.assertIsNone(a.metadata['weight_scale'])
        self.assertEqual(a.metadata['weight_profile']['id'], 'explicit')
        node = NodeParameters({}).json
        metadata = policy_metadata(a.json, node)
        self.assertEqual(metadata['policy']['total_weight_decimal'], '10')
        self.assertAlmostEqual(metadata['policy']['gini'], 0.25)
        self.assertEqual(metadata['policy']['threshold_ratio'], 0.3)
        repeated = copy.deepcopy(a.json)
        repeated['runs'] = 100
        self.assertEqual(policy_metadata(repeated, dict(node, epoch=99))['configuration_id'], metadata['configuration_id'])
        scaled = BenchParameters(dict(nodes=4, weights=[w*2**1024 for w in a.weights], threshold=3*2**1024))
        large = policy_metadata(scaled.json, node)
        self.assertEqual(large['policy']['total_weight_bits'], 1028)
        self.assertNotEqual(large['weight_instance_id'], metadata['weight_instance_id'])
        self.assertEqual(large['policy']['coefficient_of_variation'], metadata['policy']['coefficient_of_variation'])
        for bad in [dict(experiment_axis='typo'), dict(weight_scale=0), dict(weight_profile='uniform'),
                    dict(generation=dict(method='snapshot', version=1, snapshot=dict(sha256='bad'))),
                    dict(weight_profile=dict(id='x', parameters=dict(a=float('nan'))))]:
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                BenchParameters(dict(nodes=4, metadata=bad))
        with self.assertRaises(ConfigError):
            BenchParameters(dict(nodes=4, weights=dict(distribution='linear', scale=100), metadata=dict(weight_scale=2)))

    def test_snapshot_metadata_survives_without_inventing_a_generator(self):
        source = dict(experiment_id='aptos-v1', weight_profile=dict(id='aptos-quantile', parameters=dict(mean_weight=3000)),
                      weight_scale=1, generation=dict(method='empirical-quantiles', version=1, seed=7,
                          snapshot=dict(network='mainnet', epoch='123', ledger_version='456',
                                        timestamp='2026-10-04T00:00:00Z', sha256='ab'*32, source='snapshot.json')))
        bench = BenchParameters(dict(nodes=4, weights=[1, 2, 3, 4], metadata=source))
        self.assertEqual(bench.metadata, dict(source, experiment_axis=None))
        self.assertEqual(BenchParameters(bench.json).metadata, bench.metadata)

    def test_epoch_overflow_still_checked_with_runs_override(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'policy.json'
            write_json(path, dict(node_params=dict(epoch=2**64-1), cases=[dict(nodes=4)]))
            Policy(path)
            with self.assertRaises(ConfigError):
                Policy(path, runs=2)


class RepeatedRunTests(unittest.TestCase):
    def fixture(self, directory):
        directory = Path(directory)
        first = test_benchmark.LogTests().fixture(directory)
        policy = json.loads((directory/'resolved-policy.json').read_text())
        policy['bench_params']['runs'] = 3
        write_json(directory/'resolved-policy.json', policy)
        config_id = policy_metadata(policy['bench_params'], policy['node_params'])['configuration_id']
        for index in range(1, 4):
            path = directory/'run-{:03}'.format(index)
            if index != 1:
                shutil.copytree(first, path)
            manifest = json.loads((path/'run.json').read_text())
            manifest.update(schema_version=1, session='{:064x}'.format(index), epoch=index-1,
                            configuration_id=config_id, circuit=dict(gates=6, public_bytes=1192),
                            environment=dict(network='linux-loopback', tokio_worker_threads='2'))
            write_json(path/'run.json', manifest)
            for log in (path/'logs').glob('*.log'):
                events = [json.loads(line) for line in log.read_text().splitlines()]
                for event in events:
                    event.update(session=manifest['session'], epoch=index-1)
                    if event['kind'] == 'sync_result':
                        event['latency_us'] = (3+2*index)*1000
                        event['completed_us'] = event['started_us'] + event['latency_us']
                    if event['kind'] == 'bandwidth':
                        event['total_sent_bytes'] = 150*index
                        event['per_service_sent_bytes'] = {s: 25*index for s in event['per_service_sent_bytes']}
                log.write_text(''.join(json.dumps(e)+'\n' for e in events))
            bandwidth = json.loads((path/'bandwidth.json').read_text())
            bandwidth.update(total_sent_bytes=600*index,
                             per_service_sent_bytes={s: 100*index for s in bandwidth['per_service_sent_bytes']},
                             per_party_sent_bytes={str(i): {s:25*index for s in bandwidth['per_service_sent_bytes']} for i in range(4)})
            write_json(path/'bandwidth.json', bandwidth)
        return directory

    def test_statistics_are_across_runs_and_keep_plot_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            self.fixture(directory)
            parser = LogParser.process(directory)
            result = parser.data
            latency = result['summary']['latency_ms']
            self.assertEqual((latency['mean'], latency['min'], latency['max'], latency['stdev']), (7, 5, 9, 2))
            self.assertAlmostEqual(latency['standard_error'], 2/math.sqrt(3))
            self.assertEqual(latency['error_bar'], dict(method='min_max', lower=5, upper=9, minus=2, plus=2))
            sent = result['summary']['avg_sent_bytes_per_active_party']
            self.assertEqual((sent['count'], sent['mean'], sent['stdev']), (3, 300, 150))
            self.assertEqual(result['summary']['total_sent_bytes']['mean'], 1200)
            self.assertEqual(result['metadata']['circuit']['gates'], 6)
            self.assertEqual(result['metadata']['provenance_status'], 'recorded')
            self.assertEqual(result['runs'][0]['matching_finish_count'], 2)
            self.assertIn('sample stdev=2.000', parser.result())
            parser.print(Path(directory)/'summary.txt')
            self.assertEqual(json.loads((Path(directory)/'summary.json').read_text())['summary'], result['summary'])

    def test_single_run_does_not_claim_estimated_variability(self):
        result = stats([5])
        self.assertEqual(result['error_bar'], dict(method='min_max', lower=5, upper=5, minus=0, plus=0))
        self.assertIsNone(result['stdev'])
        self.assertIsNone(result['standard_error'])
        self.assertFalse(result['variability_estimated'])
        for values in [[], [float('nan')], [-1], [True]]:
            with self.assertRaises(ParseError):
                stats(values)

    def test_mixed_or_missing_runs_never_become_a_successful_mean(self):
        for change in ['build', 'environment', 'circuit', 'configuration', 'session', 'missing']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                self.fixture(directory)
                path = Path(directory)/'run-003'/'run.json'
                manifest = json.loads(path.read_text())
                if change == 'missing':
                    path.unlink()
                else:
                    if change == 'build':
                        manifest['build'] = dict(binary_sha256='different')
                    elif change == 'environment':
                        manifest['environment']['tokio_worker_threads'] = '8'
                    elif change == 'circuit':
                        manifest['circuit']['gates'] += 1
                    elif change == 'configuration':
                        manifest['configuration_id'] = 'wrong'
                    else:
                        manifest['session'] = '{:064x}'.format(1)
                    write_json(path, manifest)
                with self.assertRaises(ParseError):
                    LogParser.process(directory)

    def test_legacy_missing_metadata_stays_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            test_benchmark.LogTests().fixture(directory)
            path = Path(directory)/'resolved-policy.json'
            data = json.loads(path.read_text())
            del data['bench_params']['metadata']
            write_json(path, data)
            result = LogParser.process(directory).data
            self.assertIsNone(result['metadata']['weight_profile'])
            self.assertIsNone(result['metadata']['environment'])
            self.assertIsNone(result['metadata']['circuit'])
            self.assertEqual(result['metadata']['provenance_status'], 'legacy-partial')


if __name__ == '__main__':
    unittest.main()

import contextlib
import hashlib
import io
import json
import math
import shutil
import subprocess
import tempfile
import unittest
from functools import reduce
from pathlib import Path
from unittest.mock import patch

from benchmark.config import ConfigError, Policy, write_json
from benchmark.generate import coprime_weights, generate, heavy_weights, read_pool
from benchmark.gate_search import Oracle
from benchmark.utils import PathMaker


class GenerateTests(unittest.TestCase):
    def test_near_equal_coprime_for_divisible_nondivisible_and_huge_totals(self):
        for n in [2, 3, 4, 16, 64]:
            for total in [n, n+1, n*3, n*100, 64**64]:
                weights = coprime_weights(n, total)
                self.assertEqual(sum(weights), total)
                self.assertEqual(reduce(math.gcd, weights), 1)
                self.assertGreater(min(weights), 0)
                self.assertLessEqual(max(weights)-min(weights), 4 if n == 2 else 2)
        self.assertEqual(coprime_weights(4, 400), [99, 101, 100, 100])
        self.assertEqual(coprime_weights(2, 6), [1, 5])

    def test_heavy_group_respects_cap_and_reports_capped_target(self):
        for n in [4, 16, 31, 46, 64]:
            weights, details = heavy_weights(n, n*1000, n*1000//3-1)
            k = details['heavy_count']
            self.assertEqual(sum(weights), n*1000)
            self.assertLessEqual(max(weights), n*1000//3-1)
            self.assertGreater(min(weights[:k]), max(weights[k:]))
        weights, details = heavy_weights(4, 400, 132, 1, '0.8')
        self.assertEqual(weights[0], 132)
        self.assertTrue(details['capped'])
        for args in [(4, 12, 3), (3, 300, 99), (4, 400, 90), (4, 400, 132, 2),
                     (4, 400, 132, 1, '0'), (4, 400, 132, 1, 'NaN')]:
            with self.assertRaises((ConfigError, ValueError)):
                heavy_weights(*args)

    def test_uniform_and_coprime_export_parse_roles_ports_and_default_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            for mode in [1, 2]:
                target = Path(temporary)/('mode{}.json'.format(mode))
                result = generate(16, 16000, mode, output=target, fault_case='both')
                policy = Policy(target)
                self.assertEqual(result['cases'], 2)
                self.assertEqual(result['runs'], 1)
                for case in policy.cases:
                    self.assertEqual(case.total_weight, 16000)
                    self.assertEqual(len(case.ports(policy.node_parameters)), 96)
                    self.assertLess(case.corrupted_weight, case.threshold)
                self.assertEqual(len(set(policy.cases[0].weights)) == 1, mode == 1)
                self.assertEqual(result['gcd'], '1000' if mode == 1 else '1')
            with self.assertRaises(ConfigError):
                generate(4, 401, 1, output=Path(temporary)/'bad.json')

    def test_pool_exact_apportionment_and_immutable_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            pool, target = Path(temporary)/'pool.json', Path(temporary)/'policy.json'
            write_json(pool, {'weights': ['100', '300', '900']})
            original = pool.read_bytes()
            result = generate(2, 26, pool=pool, output=target)
            self.assertEqual(Policy(target).cases[0].weights, [5, 21])
            report = json.loads(Path(result['report']).read_text())
            self.assertEqual(report['pool']['sha256'], hashlib.sha256(original).hexdigest())
            self.assertEqual((target.with_suffix('.generation')/'source/pool.json').read_bytes(), original)
            self.assertEqual(pool.read_bytes(), original)
            with self.assertRaises(ConfigError):
                generate(2, 26, pool=pool, output=pool, overwrite=True)
            write_json(pool, [1.5, 2])
            with self.assertRaises(ConfigError):
                read_pool(pool)

    def test_aptos_raw_and_pinned_snapshot_preserve_same_weights(self):
        source = PathMaker.BENCHMARK/'data/aptos-mainnet-v7479751174'
        with tempfile.TemporaryDirectory() as temporary:
            targets = [Path(temporary)/'pinned.json', Path(temporary)/'raw.json']
            for path, pool in zip(targets, [source, source/'validator-set.json']):
                generate(4, 12000000, pool=pool, output=path)
            self.assertEqual(Policy(targets[0]).cases[0].weights, Policy(targets[1]).cases[0].weights)
            self.assertIn('snapshot', Policy(targets[0]).cases[0].metadata['generation'])
            self.assertNotIn('snapshot', Policy(targets[1]).cases[0].metadata['generation'])

    def test_invalid_options_fail_without_creating_policy(self):
        cases = [dict(), dict(distribution=5), dict(distribution=1, pool='missing'),
                 dict(distribution=1, total_weight=None), dict(distribution=4, total_weight=100),
                 dict(distribution=2, total_weight=400, threshold=134),
                 dict(distribution=2, total_weight=400, fault_weight_threshold=133),
                 dict(distribution=2, total_weight=400, heavy_count=1),
                 dict(distribution=2, total_weight=400, fault_case='bad'),
                 dict(distribution=2, total_weight=400, output_bits=253),
                 dict(distribution=2, total_weight=400, fault_case='stress', fault_weight_threshold=0)]
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)/'invalid.json'
            for options in cases:
                with self.subTest(options=options), self.assertRaises(ConfigError):
                    generate(4, output=target, **options)
                self.assertFalse(target.exists())
            with self.assertRaises(ConfigError):
                generate(512, distribution=4, output=target)

    def test_overwrite_replaces_artifacts_and_failure_keeps_previous_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            pool, target = Path(temporary)/'pool.json', Path(temporary)/'policy.json'
            write_json(pool, [1, 3, 9])
            generate(4, 400, pool=pool, output=target)
            previous = target.read_bytes()
            with self.assertRaises(ConfigError):
                generate(4, 400, 2, output=target)
            self.assertEqual(target.read_bytes(), previous)
            with self.assertRaises(ConfigError):
                generate(4, 401, 1, output=target, overwrite=True)
            self.assertEqual(target.read_bytes(), previous)
            generate(4, 400, 2, output=target, overwrite=True)
            self.assertFalse((target.with_suffix('.generation')/'source').exists())
            self.assertEqual(reduce(math.gcd, Policy(target).cases[0].weights), 1)

    def test_max_gate_mode_uses_actual_requested_threshold_and_warm_start(self):
        binary = PathMaker.BENCHMARK.parent/'target/release/examples/count_gates'
        if not binary.exists():
            self.skipTest('build count_gates to test the real oracle')
        with tempfile.TemporaryDirectory() as temporary, patch('benchmark.generate.compile_oracle', return_value=binary):
            for threshold in [64, 85]:
                target = Path(temporary)/('search{}.json'.format(threshold))
                with contextlib.redirect_stdout(io.StringIO()):
                    result = generate(4, distribution=4, output=target, threshold=threshold, samples=12, steps=24)
                case = Policy(target).cases[0]
                self.assertEqual(sum(case.weights), 256)
                self.assertEqual(case.threshold, threshold)
                oracle = Oracle(binary)
                try:
                    self.assertEqual(result['details']['gates'], oracle.count(case.weights, threshold)['gates'])
                finally:
                    oracle.close()
                if threshold == 85:
                    self.assertGreaterEqual(result['details']['gates'], 111)

    def test_fabric_task_end_to_end_and_error_exit(self):
        fab = shutil.which('fab')
        if not fab:
            self.skipTest('Fabric unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)/'cli.json'
            result = subprocess.run([fab, 'policy', '--nodes=4', '--total-weight=400', '--distribution=2',
                '--runs=2', '--fault-case=both', '--output='+str(target)],
                cwd=str(PathMaker.BENCHMARK), text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertEqual(Policy(target).cases[0].runs, 2)
            result = subprocess.run([fab, 'policy', '--nodes=4', '--total-weight=401', '--distribution=1',
                '--output='+str(target)], cwd=str(PathMaker.BENCHMARK), text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()

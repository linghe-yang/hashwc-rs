import contextlib
import io
import json
import random
import tempfile
import unittest
from pathlib import Path

from benchmark.config import Policy, write_json
from benchmark.gate_search import Oracle, column_weights, make_policy, mutate, search
from benchmark.utils import PathMaker


class GateSearchTests(unittest.TestCase):
    def test_columns_preserve_large_exact_totals_at_all_densities(self):
        for n in [4, 16, 31, 46, 64]:
            for density in [0, 25, 50, 90, 95, 99, 100]:
                a = column_weights(n, n**n, density, random.Random(10))
                b = column_weights(n, n**n, density, random.Random(10))
                self.assertEqual(a, b)
                self.assertEqual(sum(a), n**n)
                self.assertTrue(all(type(w) is int and w >= 0 for w in a))

    def test_mutation_preserves_positive_weights_and_total(self):
        for n in [4, 16, 64]:
            rng = random.Random(42)
            weights = [n**(n-1)]*n
            for i in range(200):
                weights = mutate(weights, rng, i)
                self.assertEqual(len(weights), n)
                self.assertEqual(sum(weights), n**n)
                self.assertGreater(min(weights), 0)

    def test_exported_policy_preserves_search_instance_and_fault_budget(self):
        rows = [dict(nodes=n, weights=[str(n**(n-1))]*n, threshold=str(n**n//3),
                     evaluated=10, weight_sha256='a'*64, gates=100, best_origin='test')
                for n in [4, 16, 31, 46, 64]]
        policy = make_policy(rows, {'source': 'b'*64})
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'policy.json'
            write_json(path, policy)
            parsed = Policy(path)
        self.assertEqual(len(parsed.cases), 10)
        for case in parsed.cases:
            n = case.nodes[0]
            self.assertEqual(case.total_weight, n**n)
            self.assertEqual(case.threshold, n**n//3)
            self.assertEqual(case.fault_weight_threshold, n**n//3-1)
            self.assertLess(case.corrupted_weight, case.threshold)
            self.assertEqual(len(case.ports(parsed.node_parameters)), 7*n)

    def test_production_oracle_and_search_reproducibility(self):
        binary = PathMaker.BENCHMARK.parent/'target/release/examples/count_gates'
        if not binary.exists():
            self.skipTest('build count_gates example to exercise the Rust oracle')
        oracle = Oracle(binary)
        try:
            self.assertEqual(oracle.count([64]*4, 85)['gates'], 9)
            score = oracle.count([64]*4, 85)
            self.assertEqual(score['and_gates']+score['or_gates'], score['gates'])
        finally:
            oracle.close()
        baselines = [dict(nodes=4, weights=[64]*4, byzantine_nodes=[],
                          metadata=dict(weight_profile=dict(id='uniform')))]
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            first = search(4, binary, baselines, 24, 64, 123, Path(temporary))
            second = search(4, binary, baselines, 24, 64, 123, Path(temporary))
        for key in ['gates', 'weights', 'weight_sha256', 'evaluated', 'improvements', 'trace_sha256']:
            self.assertEqual(first[key], second[key])
        self.assertGreaterEqual(first['gates'], max(first['baselines'].values()))


if __name__ == '__main__':
    unittest.main()

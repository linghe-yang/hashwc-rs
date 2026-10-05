import math
import tempfile
import unittest
from functools import reduce
from pathlib import Path

from benchmark.config import Policy, ConfigError, write_json
from benchmark.matrix import matrix
from benchmark.plot import Ploter


class MatrixTests(unittest.TestCase):
    def test_controlled_matrix_preserves_scaling_and_distribution(self):
        policy, plot, report = matrix()
        self.assertEqual((len(policy['cases']), report['total_runs']), (120, 360))
        Ploter.validate(plot)
        self.assertEqual(len(plot['charts']), 8)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'matrix.json'
            write_json(path, policy)
            self.assertEqual(len(Policy(path).cases), 120)
        bases = {}
        parameters = {}
        for case in policy['cases']:
            meta = case['metadata']
            profile = meta['weight_profile']['id']
            scale = meta['weight_scale']
            n = case['nodes']
            weights = list(map(int, case['weights']))
            self.assertEqual(sum(weights), 300*n*scale)
            self.assertEqual(int(case['threshold']), 100*n*scale)
            self.assertEqual(int(case['fault_weight_threshold']), (100*n-1)*scale)
            self.assertLess(sum(weights[i] for i in case['byzantine_nodes']), int(case['threshold']))
            base = [w//scale for w in weights]
            self.assertEqual(weights, [w*scale for w in base])
            key = (n, profile, bool(case['byzantine_nodes']))
            value = (base, case['byzantine_nodes'])
            self.assertEqual(bases.setdefault(key, value), value)
            params = meta['weight_profile']['parameters']
            self.assertEqual(parameters.setdefault(profile, params), params)
            if profile == 'near-uniform':
                self.assertEqual(reduce(math.gcd, base), 1)
            if profile == 'heavy-tail':
                self.assertLessEqual(max(weights), int(case['fault_weight_threshold']))

    def test_invalid_matrix_options(self):
        for options in [dict(nodes=[4,4]), dict(scales=[0]), dict(mean_weight=301),
                        dict(profiles=['bad']), dict(runs=0)]:
            with self.subTest(options=options), self.assertRaises(ConfigError):
                matrix(**options)

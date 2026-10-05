import hashlib
import itertools
import json
import math
import tempfile
import unittest
from fractions import Fraction
from functools import reduce
from pathlib import Path

from benchmark.config import Policy, write_json
from benchmark.plot import Ploter
from benchmark.utils import PathMaker
from benchmark.weight_policies import (
    DEFAULT_SNAPSHOT, NODES, apportion, build_policies, dense_weights,
    load_snapshot, plot_config, quantile_masses, stress_ids,
)


class WeightPolicyTests(unittest.TestCase):
    def test_quantile_integral_preserves_all_source_mass_and_lorenz_knots(self):
        source = [1, 3, 9, 11, 27]
        for n in [2, 4, 5, 16]:
            masses = quantile_masses(source, n)
            self.assertEqual(sum(masses), n*sum(source))
            self.assertEqual(masses, sorted(masses))
            for i in range(1, n+1):
                rank = Fraction(i*len(source), n)
                full = int(rank)
                partial = source[full]*(rank-full) if full < len(source) else 0
                self.assertEqual(Fraction(sum(masses[:i]), n), sum(source[:full])+partial)
        self.assertEqual(apportion(quantile_masses(source, len(source)), sum(source)), source)
        self.assertEqual(quantile_masses([1, 3, 9], 2), [5, 21])

    def test_hamilton_is_exact_at_385_bits_and_deterministic(self):
        self.assertEqual(apportion([1, 1, 1], 5), [2, 2, 1])
        masses, total = [3, 7, 13], 64**64
        weights = apportion(masses, total)
        self.assertEqual(sum(weights), total)
        for w, mass in zip(weights, masses):
            self.assertLess(abs(Fraction(mass*total, sum(masses))-w), 1)
        with self.assertRaises(ValueError):
            apportion([1, 1000], 2)

    def test_dense_weights_are_reproducible_positive_coprime_and_exact(self):
        for n in NODES:
            weights = dense_weights(n, n**n)
            self.assertEqual(weights, dense_weights(n, n**n))
            self.assertNotEqual(weights, dense_weights(n, n**n, seed=1))
            self.assertEqual(sum(weights), n**n)
            self.assertEqual(reduce(math.gcd, weights), 1)
            self.assertGreater(min(weights), 0)
        self.assertEqual((64**64).bit_length(), 385)

    def test_stress_selector_maximizes_count_without_claiming_global_weight(self):
        for weights in [[1, 2, 4, 8, 10], [3]*9, [1, 3, 8, 20, 21, 22]]:
            for budget in range(sum(weights)//3):
                ids = stress_ids(weights, budget)
                self.assertLessEqual(sum(weights[i] for i in ids), budget)
                feasible = [subset for count in range(len(weights)+1)
                            for subset in itertools.combinations(range(len(weights)), count)
                            if sum(weights[i] for i in subset) <= budget]
                self.assertEqual(len(ids), max(map(len, feasible)))
                total = sum(weights[i] for i in ids)
                self.assertFalse(any(0 < weights[j]-weights[i] <= budget-total
                    for i in ids for j in range(len(weights)) if j not in ids))
        # Local optimum need not be the maximum-weight subset of that cardinality.
        weights = [18, 24, 25, 32, 36, 55, 58, 69]
        self.assertEqual(sum(weights[i] for i in stress_ids(weights, 89)), 85)
        self.assertEqual(max(sum(s) for s in itertools.combinations(weights, 3) if sum(s) <= 89), 86)

    def test_snapshot_digest_and_pending_departures(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            resource = dict(type='0x1::stake::ValidatorSet', data=dict(
                active_validators=[dict(addr='0x1', voting_power='10')],
                pending_inactive=[dict(addr='0x2', voting_power='20')],
                pending_active=[dict(addr='0x3', voting_power='999')], total_voting_power='30'))
            write_json(directory/'validator-set.json', resource)
            raw = (directory/'validator-set.json').read_bytes()
            manifest = dict(network='mainnet', chain_id=1, epoch='2', ledger_version='3',
                sha256=hashlib.sha256(raw).hexdigest(), validator_count=2, total_voting_power='30')
            write_json(directory/'snapshot.json', manifest)
            write_json(directory/'ledger-info.json', dict(chain_id=1, epoch='2', ledger_version='3'))
            write_json(directory/'reconfiguration.json', dict(data=dict(epoch='2')))
            _, validators = load_snapshot(directory)
            self.assertEqual([v['weight'] for v in validators], [10, 20])
            (directory/'validator-set.json').write_bytes(raw+b' ')
            with self.assertRaises(ValueError):
                load_snapshot(directory)

    def test_policies_round_trip_snapshot_provenance_and_port_limits(self):
        manifest, validators = load_snapshot(PathMaker.BENCHMARK/DEFAULT_SNAPSHOT)
        families, report = build_policies(manifest, validators)
        self.assertEqual(len(report['cases']), 50)
        with tempfile.TemporaryDirectory() as tmp:
            for family, content in families.items():
                path = Path(tmp)/(family+'.json')
                write_json(path, content)
                policy = Policy(path)
                self.assertEqual({c.nodes[0] for c in policy.cases}, set(NODES))
                Ploter.validate(plot_config(family, content))
                means = set()
                for case in policy.cases:
                    n = case.nodes[0]
                    self.assertEqual(len(case.ports(policy.node_parameters)), 7*n)
                    self.assertLess(case.synchronizer_port(policy.node_parameters), 65536)
                    self.assertLess(case.corrupted_weight, case.threshold)
                    self.assertEqual(case.threshold, case.total_weight//3)
                    self.assertEqual(case.fault_weight_threshold, case.threshold-1)
                    means.add(Fraction(case.total_weight, n))
                    if family == 'npow':
                        self.assertEqual(case.total_weight, n**n)
                    else:
                        self.assertEqual(case.threshold*3, case.total_weight)
                        self.assertEqual(case.metadata['generation']['snapshot']['sha256'], manifest['sha256'])
                if family != 'npow':
                    self.assertEqual(len(means), 1)
            # Reproducibility must not depend on retained experiment artifacts.
            repeated, _ = build_policies(manifest, validators)
            self.assertEqual(families, repeated)


if __name__ == '__main__':
    unittest.main()

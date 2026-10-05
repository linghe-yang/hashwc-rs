import json
import tempfile
import unittest
from pathlib import Path
from benchmark.coding import (block_size, circuit_geometry, sampling_quotas, geometry,
                              cost, select, resolve_parameters, optimize_policy, evidence_transport_bound)
from benchmark.config import BenchParameters, NodeParameters, ConfigError, LocalCommittee
from benchmark.metadata import policy_metadata

class CodingTests(unittest.TestCase):
    def test_shared_rust_serialization_fixtures(self):
        fixture=Path(__file__).resolve().parents[2]/'consensus/wiawvss/tests/fixtures/coding-layout.json'
        for row in json.loads(fixture.read_text()):
            g=geometry(tuple(row['weights']),row['threshold'],40)
            self.assertEqual(g,row['geometry'])
            self.assertEqual(cost(g,row['cost']['block_bytes']),row['cost'])

    def test_transport_constraint_preserves_fault_delivery(self):
        self.assertLess(evidence_transport_bound(4,4096),1024*1024-256)
        self.assertGreater(evidence_transport_bound(512,4096),1024*1024-256)
        b=BenchParameters(dict(nodes=512,weights=[3]*512,threshold=512))
        with self.assertRaises(ConfigError):
            resolve_parameters(b,NodeParameters(dict(bulk_block_bytes=4096)))

    def test_known_circuit_layouts_and_sampling(self):
        for scale,gates in [(1,2525),(10,5070),(100,4584)]:
            c=circuit_geometry(tuple([300*scale]*31),3100*scale)
            self.assertEqual(c['gates'],gates)
            self.assertEqual(c['public_bytes'],360+64*31+96*gates)
        self.assertEqual(sampling_quotas(tuple([300]*31),3100,40)[1],tuple([24]*31))
        near=tuple([299]*15+[300]+[301]*15)
        self.assertEqual(circuit_geometry(near,3100)['gates'],3269)
        self.assertEqual(sampling_quotas(near,3100,40)[1],tuple([31]*31))

    def test_global_minimum_accounts_for_receipts_and_all_nonlocal_edges(self):
        g=geometry((3,3,3,3),4,40)
        report=select((3,3,3,3),4)
        self.assertEqual(report['candidate_count'],2033)
        chosen=report['selected']
        self.assertEqual((chosen['modeled_bytes'],chosen['block_bytes']),
                         min((cost(g,b)['modeled_bytes'],b) for b in range(32,4097,2)))
        self.assertLessEqual(chosen['modeled_bytes'],report['baseline_32']['modeled_bytes'])
        c=cost(g,128)
        self.assertEqual(g['quotas'],[4]*4)
        self.assertEqual(c['components']['bulk_retrieve'],4*c['components']['bulk_disperse'])
        self.assertEqual(c['components']['success_terminals'],4*4*3*257)
        self.assertEqual(c['components']['private_receipts'],3*sum(x+193 for x in c['receipt_bytes']))

    def test_configuration_resolution_and_legacy_ids(self):
        b=BenchParameters(dict(nodes=4,weights=[3]*4,threshold=4))
        old=dict(epoch=0,coverage_bits=40,rounding_bits=64,output_bits=128,port_stride=None)
        self.assertEqual(policy_metadata(b.json,old)['configuration_id'],
                         policy_metadata(b.json,dict(old,bulk_block_bytes=32))['configuration_id'])
        selected,report=resolve_parameters(b,NodeParameters(dict(old,bulk_block_bytes='auto')))
        self.assertIsInstance(selected.json['bulk_block_bytes'],int)
        self.assertEqual(selected.json['bulk_block_bytes'],report['selected']['block_bytes'])
        b.json['bulk_block_bytes']=126
        params,report=resolve_parameters(b,NodeParameters(dict(old,bulk_block_bytes='auto')))
        self.assertEqual(params.json['bulk_block_bytes'],126)
        self.assertIsNone(report)
        self.assertNotEqual(policy_metadata(b.json,old)['configuration_id'],policy_metadata(b.json,params.json)['configuration_id'])
        with tempfile.TemporaryDirectory() as tmp:
            LocalCommittee(b,params).print(tmp)
            self.assertEqual(json.loads((Path(tmp)/'.parameters.json').read_text())['bulk_block_bytes'],126)
            self.assertNotIn('bulk_block_bytes',json.loads((Path(tmp)/'.node-0.json').read_text()))

    def test_reject_invalid_and_preserve_source_policy(self):
        for bad in [True,0,30,33,4098,1.5,'wrong']:
            with self.assertRaises(ConfigError):block_size(bad)
        self.assertEqual(block_size('auto',allow_auto=True),'auto')
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'input.json';out=Path(tmp)/'selected.json'
            source=dict(node_params=dict(output_bits=128),cases=[dict(name='four',nodes=4,weights=[3]*4,threshold=4)])
            raw=json.dumps(source);p.write_text(raw)
            result=optimize_policy(p,out)
            self.assertEqual(p.read_text(),raw)
            chosen=json.loads(out.read_text())['cases'][0]['bulk_block_bytes']
            self.assertEqual(chosen,result['selections'][0]['block_bytes'])
            self.assertTrue(Path(result['report']).exists())
            with self.assertRaises(ConfigError):optimize_policy(p,p)

if __name__=='__main__':unittest.main()

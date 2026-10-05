import copy
import json
import tempfile
import unittest
from pathlib import Path

from benchmark.config import BenchParameters, NodeParameters, Policy, write_json
from benchmark.experiments import max_corruption, scalability_policy
from benchmark.metadata import policy_metadata
from benchmark.plot import Ploter, PlotError


class PlotTests(unittest.TestCase):
    def result(self, base, n, scale=1, latencies=(10, 14)):
        bench = BenchParameters(dict(name='case-n{}-s{}'.format(n, scale), nodes=n, weights=[6*scale]*n,
            threshold=2*n*scale, metadata=dict(experiment_id='test', weight_scale=scale,
                weight_profile=dict(id='uniform', parameters=dict(base_mean=6))))).json
        params = NodeParameters({}).json
        meta = policy_metadata(bench, params)
        meta.update(build={k:'test' for k in ['binary_sha256', 'cargo_lock_sha256', 'benchmark_source_sha256',
                    'transport_source_sha256', 'implementation', 'profile', 'rustc']}, environment=dict(network='loopback'),
                    circuit=dict(gates=n, public_bytes=100*n))
        bench['runs'] = len(latencies)
        data = dict(schema_version=5, status='ok', protocol='whcc', config=dict(bench_params=bench,node_params=params),
                    metadata=meta, measurement=dict(latency='synchronizer'), summary=dict(count=len(latencies), latency_ms=dict(mean=999)),
                    fault_model=meta['fault_model'], runs=[dict(run=i+1, session='{}-{}-{}'.format(n,scale,i),epoch=i, coin=1,
                        latency_ms=v, avg_honest_sent_bytes=1024*(i+1), avg_sent_bytes=1024*(i+1), total_sent_bytes=n*1024*(i+1))
                        for i,v in enumerate(latencies)])
        file = base/'results'/bench['name']/'result.json'
        write_json(file, data)
        return file, data

    def config(self):
        return dict(results=['results'], filters=dict(experiment_id=['test'], weight_profile=['uniform'], fault_case=['honest']),
                    series=['weight_profile', 'fault_case'], metrics=['latency_ms','avg_sent_bytes_per_honest_party'],
                    min_runs=2, output='plots/test', formats=['png','pdf','svg'],
                    charts=[dict(name='party',x='nodes',values=[4,10])])

    def test_real_render_recomputes_means_deduplicates_and_records_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            _, data = self.result(base, 4)
            self.result(base,10)
            write_json(base/'results/copy/result.json',data)
            result = Ploter.plot(self.config(),base)
            self.assertEqual(result['figures'],2)
            report = json.loads((base/'plots/test/party-points.json').read_text())
            first = report['points'][0]
            self.assertEqual(first['statistics']['latency_ms']['mean'],12)
            self.assertEqual(first['statistics']['latency_ms']['lower'],10)
            self.assertEqual(first['statistics']['latency_ms']['upper'],14)
            self.assertEqual(first['statistics']['latency_ms']['count'],2)
            self.assertEqual(len(report['duplicates']),2)
            self.assertEqual(len(first['sources']),2)
            self.assertTrue((base/'plots/test/party-latency_ms.pdf').read_bytes().startswith(b'%PDF'))
            self.assertIn('<svg',(base/'plots/test/party-latency_ms.svg').read_text())
            self.assertTrue((base/'plots/test/index.html').exists())
            self.assertIn('W = 6n', (base/'plots/test/party-latency_ms.svg').read_text())
            self.assertIn('Full public-record WRBC', (base/'plots/test/party-latency_ms.svg').read_text())

    def test_missing_grid_and_mixed_versions_are_rejected(self):
        for change in ['missing_x','missing_series','build','implementation','security','profile','conflict']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                base=Path(directory)
                first, a=self.result(base,4)
                path,b=self.result(base,10)
                params=self.config()
                if change=='missing_x':
                    params['charts'][0]['values'].append(16)
                elif change=='missing_series':
                    params['filters']['weight_profile'].append('bimodal')
                elif change=='build':
                    b['metadata']['build']['binary_sha256']='other'
                elif change=='implementation':
                    a['metadata']['build']['implementation'] = 'compact-header-striped-wavid-v1'
                    b['metadata']['build']['implementation'] = 'compact-header-striped-wavid-v2'
                    write_json(first, a)
                elif change=='security':
                    b['config']['node_params']['output_bits']=128
                elif change=='profile':
                    b['metadata']['weight_profile']['parameters']['base_mean']=7
                else:
                    duplicate=copy.deepcopy(a)
                    duplicate['runs'][0]['latency_ms']=100
                    write_json(base/'results/conflict/result.json',duplicate)
                write_json(path,b)
                with self.assertRaises(PlotError):
                    Ploter.plot(params,base)
                self.assertFalse((base/'plots/test/party-latency_ms.png').exists())

    def test_weight_scale_requires_matching_base_weights_and_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            self.result(base,4,1)
            path,data=self.result(base,4,10)
            params=Ploter.validate(self.config())
            params['charts']=[dict(name='weight',x='weight_scale',values=[1,10],filters=dict(nodes=[4]),xscale='log')]
            rows,_,_=Ploter.discover(params['results'],base)
            report=Ploter.aggregate(rows,params,params['charts'][0])
            self.assertEqual(len(report['points']),2)
            data['config']['bench_params']['threshold']=79
            write_json(path,data)
            rows,_,_=Ploter.discover(params['results'],base)
            with self.assertRaises(PlotError):
                Ploter.aggregate(rows,params,params['charts'][0])

    def test_total_weight_axis_uses_exact_totals(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.result(base, 4, 1)
            self.result(base, 4, 10)
            params = self.config()
            params['charts'] = [dict(name='total', x='total_weight', values=[24,240],
                                    filters=dict(nodes=[4]), xscale='log')]
            result = Ploter.plot(params, base)
            self.assertEqual(result['figures'], 2)
            report = json.loads((base/'plots/test/total-points.json').read_text())
            self.assertEqual([p['x'] for p in report['points']], [24,240])

    def test_large_run_counts_pool_observations_not_means_of_means(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            _,data=self.result(base,4,latencies=(10,10))
            extra=copy.deepcopy(data)
            extra['runs']=[dict(data['runs'][0],session='different',latency_ms=100)]
            extra['config']['bench_params']['runs']=1
            extra['summary']['count']=1
            write_json(base/'results/extra/result.json',extra)
            params=Ploter.validate(self.config())
            params['charts'][0]['values']=[4]
            rows,_,_=Ploter.discover(params['results'],base)
            report=Ploter.aggregate(rows,params,params['charts'][0])
            self.assertEqual(report['points'][0]['statistics']['latency_ms']['mean'],40)

    def test_maximum_corruption_selector_and_controlled_matrix(self):
        self.assertEqual(max_corruption([3,3,9,9],7),[0,1])
        self.assertEqual(max_corruption([1,1,2],2),[0,1])
        matrix=scalability_policy()
        self.assertEqual(len(matrix['cases']),36)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'policy.json'
            write_json(path,matrix)
            cases=Policy(path).cases
            self.assertEqual(len(cases),36)
        for case in matrix['cases']:
            scale=case['metadata']['weight_scale']
            self.assertEqual(sum(case['weights']),6*case['nodes']*scale)
            self.assertEqual(case['threshold']*3,sum(case['weights']))
            if case['byzantine_nodes']:
                self.assertEqual(case['byzantine_nodes'],max_corruption(case['weights'],case['fault_weight_threshold']))
        with self.assertRaises(ValueError):
            max_corruption([1]*21,6)

    def test_n_pow_n_is_an_explicit_checked_joint_scalability_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for n in [4, 10]:
                path, data = self.result(base, n)
                bench = data['config']['bench_params']
                bench['weights'] = [n**(n-1)]*n
                bench['threshold'] = n**n//3
                write_json(path, data)
            params = Ploter.validate(self.config())
            rows, _, _ = Ploter.discover(params['results'], base)
            with self.assertRaises(PlotError):
                Ploter.aggregate(rows, params, params['charts'][0])
            params['charts'][0]['weight_control'] = 'n_pow_n'
            result = Ploter.plot(params, base)
            self.assertEqual(result['figures'], 2)
            for violation in ['weights', 'threshold']:
                changed = copy.deepcopy(rows)
                bench = changed[0]['data']['config']['bench_params']
                if violation == 'weights':
                    bench['weights'][0] += 1
                else:
                    bench['threshold'] -= 1
                with self.assertRaises(PlotError):
                    Ploter.aggregate(changed, params, params['charts'][0])
            params['charts'][0]['x'] = 'weight_scale'
            with self.assertRaises(PlotError):
                Ploter.validate(params)

    def test_invalid_configuration_and_escape_are_rejected(self):
        for change in [dict(error_bar='ci95'),dict(min_runs=0),dict(series=['typo']),dict(formats=['exe'])]:
            params=self.config()
            params.update(change)
            with self.assertRaises(PlotError):
                Ploter.validate(params)
        params=self.config()
        params['output']='../elsewhere'
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(PlotError):
            Ploter.plot(params,Path(directory))


if __name__=='__main__':
    unittest.main()

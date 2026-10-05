"""Read saved results, validate comparable cohorts, and plot run-level statistics."""
import copy
import html
import itertools
import json
import math
import os
import re
import statistics
from collections import defaultdict
from fractions import Fraction
from pathlib import Path

from benchmark.config import write_json
from benchmark.metadata import fingerprint
from benchmark.utils import PathMaker


class PlotError(ValueError):
    pass


FIELDS = {'total_weight', 'protocol', 'experiment_id', 'nodes', 'weight_profile', 'weight_scale', 'fault_case',
          'output_bits', 'rounding_bits', 'coverage_bits', 'case_name', 'bulk_block_bytes'}
METRICS = {
    'latency_ms': ('latency_ms', 'Coin latency (ms)', 1),
    'avg_sent_bytes_per_honest_party': ('avg_honest_sent_bytes', 'Sent per honest party / coin (MiB)', 2**20),
    'avg_sent_bytes_per_active_party': ('avg_sent_bytes', 'Sent per active party / coin (MiB)', 2**20),
    'total_sent_bytes': ('total_sent_bytes', 'Total sent per coin (MiB)', 2**20),
}


def object_keys(value, allowed, name):
    if not isinstance(value, dict) or set(value)-set(allowed):
        raise PlotError('Invalid {} fields'.format(name))


def validate_filters(filters):
    object_keys(filters, FIELDS, 'filters')
    for key, values in filters.items():
        if not isinstance(values, list) or not values or any(isinstance(v, (list, dict)) for v in values):
            raise PlotError('Filter {} needs a nonempty list'.format(key))


def dimensions(data):
    bench, node = data['config']['bench_params'], data['config']['node_params']
    meta = data.get('metadata') or {}
    byz = bench.get('byzantine_nodes', [])
    silent = bench.get('faulty_nodes', [])
    fault = bench.get('byzantine_behavior', 'recovery-stress') if byz else 'honest'
    if silent:
        fault = 'silent' if not byz else fault + '+silent'
    return dict(protocol='whcc' if data['protocol'] == 'commoncoin' else data['protocol'],
                experiment_id=meta.get('experiment_id'), nodes=bench['nodes'], total_weight=sum(bench['weights']), case_name=bench['name'],
                weight_profile=(meta.get('weight_profile') or {}).get('id'), weight_scale=meta.get('weight_scale'),
                fault_case=fault, output_bits=node.get('output_bits', 1),
                rounding_bits=node['rounding_bits'], coverage_bits=node['coverage_bits'], bulk_block_bytes=node.get('bulk_block_bytes',32))


def matches(dims, filters):
    return all(dims[k] in values for k, values in filters.items())


def metric_value(run, metric, bench):
    field = METRICS[metric][0]
    value = run.get(field)
    if value is None and metric == 'avg_sent_bytes_per_honest_party' and not bench.get('byzantine_nodes'):
        value = run.get('avg_sent_bytes')
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise PlotError('Missing/nonfinite {} in run {}'.format(metric, run.get('run')))
    return value


def summarize(values, method):
    mean = statistics.mean(values)
    sd = statistics.stdev(values) if len(values) > 1 else None
    if method == 'min_max':
        low, high = min(values), max(values)
    elif method == 'stdev':
        low, high = mean-(sd or 0), mean+(sd or 0)
    else:
        low = high = mean
    return dict(count=len(values), mean=mean, min=min(values), max=max(values), stdev=sd,
                lower=low, upper=high, error_bar=method, variability_estimated=len(values)>1)


class Ploter:
    @staticmethod
    def read_config(filename):
        try:
            return json.loads(Path(filename).read_text(encoding='utf8'))
        except (OSError, ValueError) as e:
            raise PlotError('Cannot read plot config: {}'.format(e))

    @staticmethod
    def validate(params):
        object_keys(params, ['results', 'filters', 'series', 'metrics', 'error_bar', 'min_runs', 'formats', 'output', 'charts'], 'plot')
        defaults = dict(results=['results'], filters={}, series=['weight_profile', 'fault_case'],
                        metrics=['latency_ms', 'avg_sent_bytes_per_honest_party'], error_bar='min_max',
                        min_runs=1, formats=['pdf', 'svg', 'png'], output='plots/scalability')
        p = dict(defaults, **copy.deepcopy(params))
        validate_filters(p['filters'])
        for key, allowed in [('series', FIELDS), ('metrics', METRICS), ('formats', {'pdf', 'svg', 'png'})]:
            if not isinstance(p[key], list) or not p[key] or any(v not in allowed for v in p[key]) or len(set(p[key])) != len(p[key]):
                raise PlotError('Invalid {}'.format(key))
        if p['error_bar'] not in ('min_max', 'stdev', 'none') or type(p['min_runs']) is not int or p['min_runs'] < 1:
            raise PlotError('Invalid statistics options')
        if not isinstance(p['results'], list) or not p['results'] or any(not isinstance(v, str) for v in p['results']):
            raise PlotError('results needs directory/file paths')
        if not isinstance(p['output'], str):
            raise PlotError('output must be a directory path')
        if not isinstance(p.get('charts'), list) or not p['charts']:
            raise PlotError('At least one chart is required')
        names = set()
        for chart in p['charts']:
            object_keys(chart, ['name', 'x', 'values', 'filters', 'xscale', 'yscale', 'weight_control'], 'chart')
            name = chart.get('name')
            if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', name) or name in names:
                raise PlotError('Chart names must be unique safe filenames')
            names.add(name)
            if chart.get('x') not in ('nodes', 'weight_scale', 'total_weight') or chart['x'] in p['series']:
                raise PlotError('x must be nodes, weight_scale, or total_weight, independent of series')
            values = chart.get('values')
            if not isinstance(values, list) or not values or any(type(v) is not int or v < 1 for v in values) or len(set(values)) != len(values):
                raise PlotError('Chart values must list distinct positive expected x values')
            chart.setdefault('weight_control', 'fixed_mean')
            if chart['weight_control'] not in ('fixed_mean', 'n_pow_n') or (chart['weight_control'] == 'n_pow_n' and chart['x'] != 'nodes'):
                raise PlotError('n_pow_n weight control requires a nodes axis')
            chart.setdefault('filters', {})
            validate_filters(chart['filters'])
            chart.setdefault('xscale', 'linear')
            chart.setdefault('yscale', 'linear')
            if chart['xscale'] not in ('linear', 'log') or chart['yscale'] not in ('linear', 'log'):
                raise PlotError('Unknown axis scale')
        return p

    @staticmethod
    def discover(roots, base):
        paths = set()
        failures = []
        for name in roots:
            path = (base/name).resolve()
            if not path.exists():
                raise PlotError('Result input does not exist: {}'.format(path))
            candidates = [path] if path.is_file() else path.rglob('*.json')
            for file in candidates:
                if file.name.startswith('.') or any(part.startswith('run-') for part in file.relative_to(path.parent).parts):
                    continue
                if file.name == 'failure.json':
                    failures.append(str(file))
                    continue
                if file.name in ('policy.json', 'resolved-policy.json', 'bandwidth.json', 'run.json'):
                    continue
                paths.add(file.resolve())
        rows, skipped = [], []
        for path in sorted(paths):
            try:
                data = json.loads(path.read_text(encoding='utf8'))
            except (OSError, ValueError) as e:
                raise PlotError('Unreadable JSON {}: {}'.format(path, e))
            if not isinstance(data, dict) or not {'protocol', 'summary', 'runs', 'config'} <= data.keys():
                continue
            if data.get('status') != 'ok':
                skipped.append(dict(file=str(path), reason='unsuccessful result'))
                continue
            try:
                rows.append(dict(file=str(path), data=data, dims=dimensions(data)))
            except (KeyError, TypeError) as e:
                raise PlotError('Malformed result {}: {}'.format(path, e))
        return rows, skipped, sorted(set(failures))

    @staticmethod
    def comparable(row):
        data, dims = row['data'], row['dims']
        meta = data.get('metadata') or {}
        build, env = meta.get('build'), meta.get('environment')
        if not build or not env or not meta.get('weight_profile') or not meta.get('configuration_id'):
            raise PlotError('Missing provenance in {}; reparse newer logs or supply a separate experiment'.format(row['file']))
        required = ['binary_sha256', 'cargo_lock_sha256', 'benchmark_source_sha256', 'transport_source_sha256', 'implementation']
        if any(not build.get(k) for k in required):
            raise PlotError('Incomplete build identity in {}'.format(row['file']))
        captures = [{k: run.get('bandwidth', {}).get(k) for k in ['backend', 'capture_filter', 'snapshot_bytes', 'direction']} for run in data['runs']]
        if any(c != captures[0] for c in captures):
            raise PlotError('Mixed capture backends in one result')
        return dict(capture=captures[0], build={k: build.get(k) for k in required+['profile', 'rustc']}, environment=env,
                    security=[dims[k] for k in ['output_bits', 'rounding_bits', 'coverage_bits']],
                    measurement=data['measurement'])

    @classmethod
    def aggregate(cls, rows, params, chart):
        selected = [r for r in rows if matches(r['dims'], params['filters']) and matches(r['dims'], chart['filters'])
                    and r['dims'][chart['x']] in chart['values']]
        if not selected:
            raise PlotError('No results for {}'.format(chart['name']))
        cohorts, invariants, points, seen, duplicates = {}, {}, {}, {}, []
        common_environment = None
        for row in selected:
            data, dims, meta = row['data'], row['dims'], row['data'].get('metadata', {})
            comparison = cls.comparable(row)
            common = fingerprint({k: comparison[k] for k in ['environment', 'security', 'measurement', 'capture']})
            if common_environment is not None and common_environment != common:
                raise PlotError('Mixed environment/security/measurement across protocols')
            common_environment = common
            cohort = fingerprint(comparison)
            # Different protocols may have different binaries; within a protocol all curves must match.
            if dims['protocol'] in cohorts and cohorts[dims['protocol']] != cohort:
                raise PlotError('Mixed build/environment/security/measurement in {}'.format(chart['name']))
            cohorts[dims['protocol']] = cohort
            bench = data['config']['bench_params']
            weights, threshold = bench['weights'], bench['threshold']
            if (meta.get('fault_selection') or {}).get('method') == 'max-weight-then-count-v1':
                from benchmark.experiments import max_corruption
                if bench.get('faulty_nodes') or bench.get('byzantine_nodes') != max_corruption(weights, bench['fault_weight_threshold']):
                    raise PlotError('Claimed maximum corruption selection does not match policy')
            series = tuple(dims[k] for k in params['series'])
            if any(v is None for v in series):
                raise PlotError('Missing series metadata in {}'.format(row['file']))
            generation = meta.get('generation') or {}
            npow = chart.get('weight_control', 'fixed_mean') == 'n_pow_n'
            if npow and (sum(weights) != dims['nodes']**dims['nodes'] or threshold != sum(weights)//3
                         or dims['weight_scale'] != 1):
                raise PlotError('n_pow_n requires W=n^n, T=floor(W/3), and weight_scale=1')
            invariant = dict(profile=meta['weight_profile'], threshold_ratio='floor(W/3)' if npow else str(Fraction(threshold, sum(weights))),
                             generation={k: generation.get(k) for k in ['method', 'version', 'seed', 'snapshot']},
                             protocol=dims['protocol'], fault_case=dims['fault_case'],
                             fault_selection=(meta.get('fault_selection') or {}).get('method'),
                             fixed=dims['weight_scale'] if chart['x']=='nodes' else dims['nodes'])
            if chart['x'] == 'nodes':
                invariant['mean_weight'] = 'W=n^n' if npow else str(Fraction(sum(weights), len(weights)))
            else:
                scale = dims['weight_scale']
                invariant['base_weights'] = [str(Fraction(w, scale)) for w in weights]
                invariant['base_threshold'] = str(Fraction(threshold, scale))
                invariant['corrupted_ids'] = bench.get('byzantine_nodes', []) + bench.get('faulty_nodes', [])
            inv = fingerprint(invariant)
            if series in invariants and invariants[series] != inv:
                raise PlotError('Uncontrolled distribution/threshold/scale/fault policy within series {}'.format(series))
            invariants[series] = inv
            point_key = (series, dims[chart['x']])
            if point_key not in points:
                points[point_key] = dict(series=dict(zip(params['series'], series)), x=dims[chart['x']],
                    configuration_id=meta['configuration_id'], fault_case=dims['fault_case'], nodes=dims['nodes'], total_weight=sum(weights), weight_scale=dims['weight_scale'],
                    weight_profile=meta['weight_profile'], circuit=meta.get('circuit'), fault_model=data.get('fault_model', meta.get('fault_model')),
                    fault_selection=meta.get('fault_selection'), sources=[], runs=[], measurements={m: [] for m in params['metrics']})
            point = points[point_key]
            if point['configuration_id'] != meta['configuration_id'] or point['circuit'] != meta.get('circuit'):
                raise PlotError('Multiple weight instances or circuit sizes at one plot point')
            runs = data['runs']
            if not runs or len(runs) != data['summary']['count'] or len(runs) != bench['runs']:
                raise PlotError('Incomplete runs in {}'.format(row['file']))
            point['sources'].append(row['file'])
            for run in runs:
                values = {m: metric_value(run, m, bench) for m in params['metrics']}
                run_id = (dims['protocol'], run['session'], run['epoch'])
                signature = fingerprint(dict(configuration=meta['configuration_id'], measurements=values, coin=run['coin']))
                if run_id in seen:
                    if seen[run_id] != signature:
                        raise PlotError('Conflicting records for the same session/epoch')
                    duplicates.append(dict(file=row['file'], session=run['session'], epoch=run['epoch']))
                    continue
                seen[run_id] = signature
                point['runs'].append(dict(session=run['session'], epoch=run['epoch'], run=run['run'], source=row['file']))
                for metric, value in values.items():
                    point['measurements'][metric].append(value)
        expected_filters = dict(params['filters'], **chart['filters'])
        # Explicit series filters also demand their Cartesian product, catching wholly missing curves.
        expected_series = set(itertools.product(*[expected_filters[k] for k in params['series']])) if all(k in expected_filters for k in params['series']) else set(invariants)
        missing = [(series, x) for series in expected_series for x in chart['values'] if (series, x) not in points]
        if missing:
            raise PlotError('Missing points in {}: {}'.format(chart['name'], missing))
        for point in points.values():
            if len(point['runs']) < params['min_runs']:
                raise PlotError('Not enough distinct runs at {} x={}'.format(point['series'], point['x']))
            point['statistics'] = {m: summarize(v, params['error_bar']) for m, v in point['measurements'].items()}
        return dict(name=chart['name'], implementation=selected[0]['data']['metadata']['build'].get('implementation'), output_bits=selected[0]['dims']['output_bits'], chart=chart, cohorts=cohorts, duplicates=duplicates,
                    points=sorted(points.values(), key=lambda p: (json.dumps(p['series'], sort_keys=True), p['x'])))

    @classmethod
    def plot(cls, plot_params, base=None):
        base = Path(base or PathMaker.BENCHMARK).resolve()
        params = cls.validate(plot_params)
        output = (base/params['output']).resolve()
        try:
            output.relative_to((base/'plots').resolve())
        except ValueError:
            raise PlotError('Plot output must be inside benchmark/plots')
        rows, skipped, failures = cls.discover(params['results'], base)
        reports = [cls.aggregate(rows, params, chart) for chart in params['charts']]
        selected_files = {file for report in reports for point in report['points'] for file in point['sources']}
        skipped += [dict(file=r['file'], reason='outside selected filters/x values') for r in rows if r['file'] not in selected_files]
        output.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault('MPLCONFIGDIR', str(base/'plots/.matplotlib'))
        try:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt
        except ImportError as e:
            raise PlotError('Install benchmark/requirements.txt: {}'.format(e))
        plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 10, 'pdf.fonttype': 42,
                             'svg.fonttype': 'none', 'axes.spines.top': False, 'axes.spines.right': False})
        images = []
        for report in reports:
            chart = report['chart']
            grouped = defaultdict(list)
            for point in report['points']:
                grouped[tuple(point['series'].values())].append(point)
            profiles = sorted({p['weight_profile']['id'] for p in report['points']})
            colors = {p: plt.get_cmap('tab10')(i) for i, p in enumerate(profiles)}
            for metric in params['metrics']:
                fig, ax = plt.subplots(figsize=(7.2, 6.2))
                for _, points in sorted(grouped.items()):
                    points.sort(key=lambda p:p['x'])
                    first = points[0]
                    profile = first['weight_profile']['id']
                    fault = first['fault_case']
                    labels = {'honest': 'Honest', 'uniform': 'Uniform', 'bimodal': 'Bimodal', 'near-uniform': 'Near-uniform', 'heavy-tail': 'Minority-heavy', 'aptos': 'Aptos',
                              'recovery-stress': 'Max-weight stress' if (first.get('fault_selection') or {}).get('method') == 'max-weight-then-count-v1' else 'Recovery stress'}
                    label = ' / '.join(labels.get(str(v), str(v)) for v in first['series'].values())
                    factor = METRICS[metric][2]
                    x = [p['x'] for p in points]
                    y = [p['statistics'][metric]['mean']/factor for p in points]
                    lower = [(p['statistics'][metric]['mean']-p['statistics'][metric]['lower'])/factor for p in points]
                    upper = [(p['statistics'][metric]['upper']-p['statistics'][metric]['mean'])/factor for p in points]
                    if chart['yscale'] == 'log' and any(p['statistics'][metric]['lower'] <= 0 for p in points):
                        raise PlotError('Log y axis needs positive lower bounds')
                    ax.errorbar(x, y, yerr=[lower, upper] if params['error_bar']!='none' else None,
                                color=colors[profile], linestyle='--' if 'stress' in fault else '-',
                                marker='s' if 'stress' in fault else 'o', capsize=4, linewidth=1.6, markersize=5, label=label)
                ax.set_xscale(chart['xscale'])
                ax.set_yscale(chart['yscale'])
                ax.set_xticks(sorted(chart['values']))
                ax.set_xticklabels([str(v) for v in sorted(chart['values'])])
                ax.set_xlabel({'nodes': 'Number of parties', 'weight_scale': 'Weight scale (weights and threshold scaled together)',
                               'total_weight': 'Total weight W (threshold scaled proportionally)'}[chart['x']])
                ax.set_ylabel(METRICS[metric][1])
                title = 'Party scalability' if chart['x']=='nodes' else 'Weight scalability | {} parties'.format(report['points'][0]['nodes'])
                if chart.get('weight_control') == 'n_pow_n':
                    title = 'Joint party / weight stress | W = n^n'
                elif chart['x'] == 'nodes':
                    point = report['points'][0]
                    title += ' | W = {}n'.format(Fraction(point['total_weight'], point['nodes']))
                ax.set_title(title, loc='left', fontweight='bold', pad=12)
                ax.grid(True, alpha=0.22)
                if chart['yscale']=='linear':
                    ax.set_ylim(bottom=0)
                handles, labels = ax.get_legend_handles_labels()
                fig.legend(handles, labels, fontsize=8, loc='lower center',
                           bbox_to_anchor=(0.5, 0.105), ncol=2, frameon=False)
                counts = sorted({len(p['runs']) for p in report['points']})
                security = report['output_bits']
                note = '{}-bit coin | {} runs/point | error bars: {}\n'.format(security, '/'.join(map(str, counts)), params['error_bar'].replace('_', '–'))
                label = 'Header WRBC + striped WAVID' if report.get('implementation') in ('compact-header-striped-wavid-v1', 'compact-header-striped-wavid-v2', 'compact-header-striped-wavid-v3-cpu', 'compact-header-striped-wavid-v4-coding') else 'Full public-record WRBC'
                note += label + '; local multiprocess; quorum STOP.\n'
                note += 'Recovery stress is bounded, not a proven global worst case.'
                fig.text(0.1, 0.035, note, fontsize=7, color='#555555')
                fig.tight_layout(rect=(0, 0.25, 1, 1))
                stem = '{}-{}'.format(report['name'], metric)
                for extension in params['formats']:
                    fig.savefig(output/(stem+'.'+extension), dpi=180)
                plt.close(fig)
                images.append(dict(stem=stem, title=title+' — '+METRICS[metric][1]))
            write_json(output/(report['name']+'-points.json'), report)
        write_json(output/'config.json', params)
        write_json(output/'manifest.json', dict(schema_version=1, matplotlib=matplotlib.__version__, selected_results=sorted(selected_files),
                    excluded=skipped, failed_experiments=failures, figures=images,
                    note='Failures are reported, never filled with zeros. Strict complete grids; statistics use distinct runs.'))
        cards = []
        for image in images:
            links = ' · '.join('<a href="{}.{}">{}</a>'.format(image['stem'], ext, ext.upper()) for ext in params['formats'])
            preview = '<img src="{}.png" alt="{}">'.format(image['stem'], html.escape(image['title'])) if 'png' in params['formats'] else ''
            cards.append('<section><h2>{}</h2>{}<p>{}</p></section>'.format(html.escape(image['title']), preview, links))
        (output/'index.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><title>WHCC scalability</title>'
            '<style>body{font:16px sans-serif;max-width:1500px;margin:32px auto;padding:0 20px;background:#f5f6f8;color:#182431}'
            'main{display:grid;grid-template-columns:repeat(auto-fit,minmax(480px,1fr));gap:24px}section{background:white;padding:18px;border-radius:8px}'
            'img{width:100%}h2{font-size:17px}a{color:#2166ac}</style><h1>WHCC scalability</h1>'
            '<p>Mean across runs; error bars as specified in config.json. Byzantine curves are bounded recovery-stress experiments, not a proven global worst case.</p>'
            '<p><a href="manifest.json">Sources and exclusions</a> · <a href="config.json">Plot configuration</a></p><main>'+
            ''.join(cards)+'</main></html>', encoding='utf8')
        return dict(directory=str(output), figures=len(images), selected_results=len(selected_files), excluded=len(skipped), failed=len(failures))

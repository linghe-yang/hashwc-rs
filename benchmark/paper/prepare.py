"""Offline preparation; freeze inputs, Linux artifacts, and the paired run order."""
from pathlib import Path
from types import SimpleNamespace
import argparse
import json
import sys
import shutil
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WAN = ROOT/'benchmark/wan_scaling'
FROZEN = ROOT/'results/prepared-paper'
sys.path[:0] = [str(WAN), str(ROOT/'benchmark/clean_comparison')]
import run
from common import save, digest
from evidence import verify_source

PAIRS = {'sui': ('hashrand','whcc'), 'aptos': ('warmup','whcc')}
def read(path):
    return json.loads(path.read_text())

def prepare(directory, smoke=False, css_max=False):
    manifest_path = HERE/('css-max-manifest.json' if css_max else 'manifest.json')
    manifest = read(manifest_path)
    for entry in manifest['cases']:
        src = HERE/entry['input']
        obj = read(src)
        if obj['chain'] not in PAIRS:
            continue
        assert digest(src) == entry['sha256']
        cert = HERE/obj['reduction_certificate'] if 'reduction_certificate' in obj else HERE/'reduction_checks'/src.name
        snap = HERE/obj['source_manifest']
        assert digest(cert) == obj['reduction_certificate_sha256'] and digest(snap) == obj['source_manifest_sha256']
        verify_source(obj,read(cert),read(snap))
    run.prepare(SimpleNamespace(directory=directory,smoke=smoke,source_data=None,dataset_plan=None if smoke else manifest_path,
        workers=2,actor_inbox=4096,compute_jobs=1,receive_capacity=1024,transport_stall_ms=30000),
        protocol_pairs=None if smoke else PAIRS)
    plan = run.load_plan(directory)
    plan['settings'].update(prepare_timeout_s=900,coin_timeout_s=180,drain_timeout_s=300,shutdown_timeout_s=60,
                            runs_per_configuration=1 if smoke else 2,bulk_audit=True)
    if smoke:
        for c in plan['configurations']:
            c['repeat'] = 1
        save(directory/'plan.json',plan)
        save(directory/'plan_digest.json',{'sha256':digest(directory/'plan.json')})
        return plan
    configs = {(c['family'],c['n'],c['protocol']):c for c in plan['configurations']}
    jobs = []
    sizes = (32,48,64,80) if css_max else (16,32,48,64)
    for index,n in enumerate(sizes):
        for rep in ((1,) if css_max else (1,2)):
            for family,pair in ({'aptos':PAIRS['aptos']} if css_max else PAIRS).items():
                if css_max and index % 2:
                    pair = tuple(reversed(pair))
                for proto in (pair if rep==1 else reversed(pair)):
                    case = configs[family,n,proto].copy()
                    assert case['preflight_status']=='ready', case
                    case.update(job_id=f'{family}-n{n}--{proto}-r{rep}',repeat=rep)
                    if css_max:
                        from local_rejection import maximum_coalition
                        source = read(directory/case['input'])
                        case.update(campaign='css-max', dealer_fault='css-corrections',
                                    faulty_dealers=maximum_coalition(source))
                    jobs.append(case)
    plan.update(instance_type="t3a.medium",cpu_credits="unlimited",configurations=jobs,wan_sources={name:digest(WAN/name) for name in
        ('cloud_control.py','cloud_entry.py','campaign_cloud.py','pipeline.py','../remote_coin/remote.py',
         '../remote_coin/pilot4.py')})
    if css_max:
        plan.update(campaign='css-max', scope='maximum-cardinality below one third; CSS dealer input only')
        plan['settings'].update(runs_per_configuration=1, log_mode='formal')
        plan['wan_sources'].update({f'../paper/{f}':digest(HERE/f) for f in
                                    ('measurements.py','local_rejection.py','campaign.py')})
    assert len(jobs)==len({c['job_id'] for c in jobs})==(8 if css_max else 32)
    save(directory/'plan.json',plan)
    save(directory/'plan_digest.json',{'sha256':digest(directory/'plan.json')})
    print(f"Frozen {len(jobs)} paired single-coin runs in {directory}", flush=True)
    return plan

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path)
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--smoke', action='store_true', help='prepare six four-party jobs')
    group.add_argument('--css-max', action='store_true', help='prepare one formal pair per size at 32/48/64/80')
    args = parser.parse_args()
    directory = args.directory or (ROOT/'results/prepared-css-max' if args.css_max else FROZEN)
    directory = directory.resolve()
    if args.css_max:
        if directory.exists():
            raise FileExistsError(directory)
        # Node preparation performs many small writes. Stage on native Linux
        # storage when the destination is a Windows-mounted paper workspace.
        with tempfile.TemporaryDirectory() as temp:
            staged = Path(temp)/'prepared'
            prepare(staged, False, True)
            shutil.copytree(staged, directory)
    else:
        prepare(directory, args.smoke)

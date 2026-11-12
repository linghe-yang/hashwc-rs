"""Offline preparation; freeze inputs, Linux artifacts, and the paired run order."""
from pathlib import Path
from types import SimpleNamespace
import argparse
import json
import sys

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

def prepare(directory, smoke=False):
    manifest = read(HERE/'manifest.json')
    for entry in manifest['cases']:
        src = HERE/entry['input']
        obj = read(src)
        if obj['chain'] not in PAIRS:
            continue
        assert digest(src) == entry['sha256']
        cert, snap = (HERE/obj[k] for k in ('reduction_certificate','source_manifest'))
        assert digest(cert) == obj['reduction_certificate_sha256'] and digest(snap) == obj['source_manifest_sha256']
        verify_source(obj,read(cert),read(snap))
    run.prepare(SimpleNamespace(directory=directory,smoke=smoke,source_data=None,dataset_plan=None if smoke else HERE/'manifest.json',
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
    for n in (16,32,48,64):
        for rep in (1,2):
            for family,pair in PAIRS.items():
                for proto in (pair if rep==1 else reversed(pair)):
                    case = configs[family,n,proto].copy()
                    assert case['preflight_status']=='ready', case
                    case.update(job_id=f'{family}-n{n}--{proto}-r{rep}',repeat=rep)
                    jobs.append(case)
    plan.update(instance_type="t3a.medium",cpu_credits="unlimited",configurations=jobs,wan_sources={name:digest(WAN/name) for name in
        ('cloud_control.py','cloud_entry.py','campaign_cloud.py','pipeline.py','../remote_coin/remote.py')})
    assert len(jobs)==len({c['job_id'] for c in jobs})==32
    save(directory/'plan.json',plan)
    save(directory/'plan_digest.json',{'sha256':digest(directory/'plan.json')})
    print(f"Frozen {len(jobs)} paired single-coin runs in {directory}", flush=True)
    return plan

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=FROZEN)
    parser.add_argument('--smoke', action='store_true', help='prepare six four-party jobs')
    args = parser.parse_args()
    prepare(args.directory.resolve(), args.smoke)

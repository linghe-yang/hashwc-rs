"""Preview by default; explicit --apply creates the cloud fleet."""
import argparse
import asyncio
import signal
import sys
import uuid
import shutil
import shlex
from pathlib import Path
from prepare import HERE,ROOT,WAN,FROZEN,PAIRS,read,run,digest,save
from measurements import export,table
import pipeline as pl

class PairedCloud(pl.Cloud):
    def grow(self,n,previous,stage):
        rows=super().grow(n,previous,stage)
        verified={}
        for region in pl.REGIONS:
            ids=[r['id'] for r in rows if r['region']==region]
            if not ids:continue
            specs=pl.p.ec2(region,'describe-instance-credit-specifications','--instance-ids',*ids)
            modes={v['InstanceId']:v['CpuCredits'] for v in specs['InstanceCreditSpecifications']}
            if modes!={i:self.cfg['cpu_credits'] for i in ids}:
                raise RuntimeError(f'{region}: unexpected CPU credit mode')
            verified.update(modes)
        save(stage/'cpu-credit-modes.json',verified)
        return rows

def check(plan):
    assert (plan['instance_type'],plan['cpu_credits'])==('t3a.medium','unlimited')
    assert len(plan['configurations'])==32 and plan['settings']['coin_timeout_s']==180 and plan['settings']['bulk_audit']
    for name,h in plan['wan_sources'].items():
        assert digest(WAN/name)==h
    cases=plan['configurations']
    for n in (16,32,48,64):
        for family,pair in PAIRS.items():
            for rep in (1,2):
                group=[c for c in cases if (c['n'],c['family'],c['repeat'])==(n,family,rep)]
                assert [c['protocol'] for c in group]==list(pair if rep==1 else reversed(pair))
                assert len({c['weight_policy_sha256'] for c in group})==1
                for c in group:
                    p=c['parameters']
                    assert c['preflight_status']=='ready' and p['rounding_bits']==40 and p['output_bits']==1
                    if c['protocol']=='hashrand':
                        assert p['sampling_bits']==40 and p['batches']==p['batch_size']==1
                    if c['protocol']=='whcc':
                        assert p['coverage_bits']==40 and p['sampling_mode']=='tight-v1'
    assert len({c['job_id'] for c in cases})==32

def certified_timeout(work,raw,case):
    if case['protocol']!='hashrand':
        return False
    names=('control.json','credential-cleanup.json','cloud-status.json','cloud-logs.tar.gz')
    if not all((work/p).is_file() for p in names):
        return False
    control=read(work/'control.json')
    status=read(work/'cloud-status.json')
    if (control.get('phase')!='await_outputs' or control['error']!='TimeoutError()'
        or status['error']!='TimeoutError()' or digest(work/'cloud-logs.tar.gz')!=status['archive_sha256']
        or not read(work/'credential-cleanup.json')['confirmed']):
        return False
    outputs=[]
    for i in range(case['n']):
        party=work/f'party-{i}.jsonl'
        stderr=raw/f'remote-{i}-stderr.log'
        if not all(p.is_file() for p in (party,stderr,raw/f'remote-{i}-stdout.jsonl')):
            return False
        if any(k in stderr.read_text(errors='replace').lower() for k in ('panicked','out of memory','oom-kill')):
            return False
        events=[__import__('json').loads(line) for line in party.read_text().splitlines()]
        if not any(e['kind']=='started' for e in events) or any(e.get('event',{}).get('kind')=='failed' for e in events):
            return False
        outputs.extend(e['event']['value'] for e in events if e.get('event',{}).get('kind') in ('coin','beacon'))
    return len(outputs)<case['n'] and all(v==outputs[0] for v in outputs)

def stages(args,cloud,plan,policy):
    history=[]; previous=0; stop_hr=False
    for n in (16,32,48,64):
        stage=args.out/f'n{n:02d}'
        stage.mkdir()
        rows=cloud.grow(n,previous,stage)
        hosts=pl.p.connections(args,rows,args.out)
        timeouts=sum(int(r['n'])==n and r['status']=='online_timeout' for r in history)
        for case in (c for c in plan['configurations'] if c['n']==n):
            key=case['job_id']
            if stop_hr and case['protocol']=='hashrand':
                history.append(dict(job_id=key,protocol='hashrand',family='sui',n=n,repeat=case['repeat'],status='not_run_after_two_timeouts'))
                continue
            save(stage/'progress.json',dict(current=key))
            print(key,flush=True)
            work=stage/'controller-logs'/key
            dest=stage/'analysis'/key
            try:
                asyncio.run(pl.measure(args,cloud,hosts,case,plan,policy,stage))
            except RuntimeError as exc:
                if 'AWS controller failed: TimeoutError()' not in str(exc) or not certified_timeout(work,stage/'remote-logs'/key,case):
                    raise
                # A disconnected SSH process must not leave a benchmark running into the next run.
                async def verify_idle():
                    # Match the actual executable inode even if argv is relative.
                    sha=plan['binaries']['driver']['sha256']
                    probe=("import os,pathlib\n"
                           f"exe=str(pathlib.Path.home()/'.hashwc/bin/{sha}')\n"
                           "alive=False\n"
                           "for proc in pathlib.Path('/proc').glob('[0-9]*'):\n"
                           " try:\n"
                           "  if proc.stat().st_uid==os.getuid() and os.readlink(proc/'exe')==exe: alive=True\n"
                           " except (FileNotFoundError,ProcessLookupError): pass\n"
                           "print(alive)")
                    states=await asyncio.gather(*(h.shell('python3 -c '+shlex.quote(probe)) for h in hosts))
                    if any(s!='False' for s in states):
                        raise RuntimeError('worker still active after timeout')
                    if any(not (stage/'remote-logs'/key/f'remote-{i}-stdout.jsonl').is_file() for i in range(n)):
                        raise RuntimeError('missing downloaded worker log')
                    await pl.p.remote.cleanup(hosts,read(work/'deployment.json')['remote'])
                asyncio.run(verify_idle())
                result=None
                timeouts+=1
            else:
                result=read(dest/'result.json')
            history.append(export(work,dest,case,result))
            table(args.out/'measurements.csv',history)
        stop_hr=stop_hr or timeouts==2
        table(args.out/'measurements.csv',history)
        save(stage/'gate.json',dict(passed=True,hashrand_timeouts=timeouts,skip_larger_hashrand=stop_hr))
        previous=n

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true')
    parser.add_argument('--cleanup',action='store_true')
    parser.add_argument('--prepared',type=Path,default=FROZEN)
    parser.add_argument('--out',type=Path,default=ROOT/'results/aws-paired40')
    parser.add_argument('--config',type=Path,default=ROOT/'benchmark/aws_fleet/fleet.json')
    parser.add_argument('--key',type=Path,default=Path('~/.ssh/whcc-aws'))
    parser.add_argument('--ssh-proxy', action='store_true', help='route local SSH via HTTP proxy 127.0.0.1:7890')
    args=parser.parse_args()
    args.out=args.out.resolve()
    args.user='ubuntu'; args.port=pl.BASE; args.boot_ssh_seconds=180; args.max_replacements=1
    args.trust_first_use=True
    if args.cleanup:
        if not args.apply:raise ValueError('cleanup requires --apply')
        cfg=read(args.config)
        pl.Cloud(args.out,cfg,args,read(args.out/'campaign.json')).cleanup()
        return
    folder=args.prepared.resolve()
    plan=run.load_plan(folder,True)
    check(plan)
    print('Validated 32 paired runs, 16/32/48/64; local preview complete.',flush=True)
    if not args.apply:return
    cfg=read(args.config)
    cfg.update(instance_type=plan['instance_type'],cpu_credits=plan['cpu_credits'])
    args.driver=folder/plan['binaries']['driver']['path']
    args.generator=folder/plan['binaries']['generator']['path']
    args.out.mkdir(mode=0o700,parents=True,exist_ok=False)
    shutil.copyfile(FROZEN/'plan.json',args.out/'plan.json')
    state=dict(fleet='scale-'+uuid.uuid4().hex[:16],regions={},requests=[],driver_sha256=digest(args.driver),instance_type=cfg['instance_type'],cpu_credits=cfg['cpu_credits'])
    cloud=PairedCloud(args.out,cfg,args,state)
    signal.signal(signal.SIGTERM,lambda *_:sys.exit('SIGTERM'))
    pl.execute(args,cloud,plan,{},stage_runner=stages)
    from plot_paired import plot
    plot(args.out)
if __name__=='__main__': main()


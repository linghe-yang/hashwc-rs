"""WSL prepares and downloads. The measured interval runs entirely on AWS."""
import asyncio
import io
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import uuid

from campaign_cloud import p
from common import ROOT,digest,save
from analyze import analyze_run

HERE=Path(__file__).resolve().parent

def unpack(archive,directory):
    with tarfile.open(archive) as tar:
        for m in tar.getmembers():
            if not m.isfile() or Path(m.name).name!=m.name or m.name in ('.','..'):
                raise ValueError('unsafe controller archive')
            # All files live directly in the job directory; no links or subpaths.
            if not (m.name in ('case.json','parameters.json','execution.json','control.json','deployment.json','result.json')
                    or m.name.startswith(('party-','remote-'))):raise ValueError('unexpected log member')
        tar.extractall(directory,filter='data')

def authorization(public_key,ips,tag):
    return 'restrict,from="'+','.join(sorted(set(ips)))+'" '+public_key.strip()+' '+tag

def trusted_hosts(args,rows):
    source=args.out/'known_hosts'
    if not source.exists():source=Path.home()/'.ssh/known_hosts'
    result=[]
    for row in rows:
        for name in (row['id'],row['public_ip']):
            found=subprocess.run(['ssh-keygen','-F',name,'-f',str(source)],capture_output=True,text=True)
            lines=[l.split() for l in found.stdout.splitlines() if l and not l.startswith('#')]
            if lines:
                result.extend(row['id']+' '+' '.join(l[1:]) for l in lines)
                break
        else:raise ValueError('missing verified SSH host key for '+row['id'])
    return '\n'.join(result)+'\n'

async def retry(op):
    for attempt in range(5):
        try:return await op()
        except (OSError,RuntimeError,TimeoutError,ValueError):
            if attempt==4:raise
            await asyncio.sleep(2**attempt)

async def verified_get(host,src,dest):
    async def one():
        sha=(await host.shell('sha256sum '+shlex.quote(src))).split()[0]
        temp=dest.with_suffix('.partial')
        await host.get(src,temp)
        if digest(temp)!=sha:raise ValueError('download checksum mismatch')
        temp.replace(dest)
    await retry(one)

async def experiment(args,hosts,case,plan,sha,directory,rows):
    directory.mkdir(mode=0o700,parents=True,exist_ok=False)
    tag='hashwc-controller-'+uuid.uuid4().hex
    remote='.hashwc/controllers/'+tag
    controller=hosts[0]
    save(directory/'cloud-deployment.json',dict(remote=remote,slot=0,instance_id=rows[0]['id'],
         controller_ip=controller.ip,credential_tag=tag,measurement='AWS controller; local VPN outside measured interval'))
    await p.remote.before_upload(hosts)
    trusted=trusted_hosts(args,rows)
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C',tag,'-f',str(directory/'key')],check=True)
    public=(directory/'key.pub').read_text().split()
    pub=' '.join(public[:2])
    (directory/'known_hosts').write_text(trusted)
    ips=[controller.ip,rows[0].get('private_ip',controller.ip),'127.0.0.1','::1']
    line=authorization(pub,ips,tag)
    add='import os,pathlib; p=pathlib.Path.home()/".ssh"; p.mkdir(mode=0o700,exist_ok=True); f=p/"authorized_keys"; f.open("a").write('+repr('\n'+line+'\n')+'); os.chmod(f,0o600)'
    remove='import pathlib; p=pathlib.Path.home()/".ssh/authorized_keys"; s=p.read_text(); p.write_text("".join(l for l in s.splitlines(True) if not l.rstrip().endswith('+repr(' '+tag)+')))'
    shell=lambda code:'python3 -c '+shlex.quote(code)
    authorized=[];downloaded=False;launched=False
    try:
        for i,h in enumerate(hosts):
            # Register before mutation so cleanup also covers a lost SSH reply.
            authorized.append(h)
            await h.shell(shell(add))
        await controller.shell('python3 -c '+shlex.quote('import sys; assert sys.version_info>=(3,11)')+
                               f' && mkdir -p -m 700 {remote}/code/remote_coin {remote}/code/clean_comparison')
        generator_sha=digest(args.generator)
        await p.remote.deploy(controller,args.generator,generator_sha)
        for source,target in ((HERE/'cloud_entry.py','cloud_entry.py'),
                  (ROOT/'benchmark/remote_coin/remote.py','code/remote_coin/remote.py'),
                  (ROOT/'benchmark/clean_comparison/common.py','code/clean_comparison/common.py'),
                  (ROOT/'benchmark/clean_comparison/analyze.py','code/clean_comparison/analyze.py'),
                  (directory/'key','key'),(directory/'known_hosts','known_hosts')):
            await controller.put(source,f'{remote}/{target}')
        await controller.shell(f'chmod 600 {remote}/key')
        job=dict(user=args.user,port=args.port,peers=rows,case=case,settings=plan['settings'],
                 driver_sha256=sha,generator=f'/home/{args.user}/.hashwc/bin/{generator_sha}')
        # Resolve HOME at the host, supporting usernames whose home is not /home/user.
        home=await controller.shell('printf %s "$HOME"')
        job['generator']=home+f'/.hashwc/bin/{generator_sha}'
        save(directory/'job.json',job);await controller.put(directory/'job.json',remote+'/job.json')
        # A VPN interruption after this command does not own the process lifetime.
        launched=True
        budget=sum(plan['settings'][k] for k in ('prepare_timeout_s','coin_timeout_s','drain_timeout_s','shutdown_timeout_s'))+240
        start=f'cd {remote}\nnohup setsid timeout --signal=TERM --kill-after=15s {budget}s python3 cloud_entry.py </dev/null >controller.log 2>&1 &\necho $! >controller.pid'
        await controller.shell('sh -c '+shlex.quote(start))
        async with asyncio.timeout(budget):
            while True:
                try:
                    status=await controller.shell(f'if test -f {remote}/status.json; then cat {remote}/status.json; fi')
                    if status:break
                except (RuntimeError,TimeoutError):pass
                await asyncio.sleep(3)
        await verified_get(controller,remote+'/status.json',directory/'cloud-status.json')
        await verified_get(controller,remote+'/logs.tar.gz',directory/'cloud-logs.tar.gz')
        await verified_get(controller,remote+'/controller.log',directory/'cloud-controller.log')
        status=json.loads((directory/'cloud-status.json').read_text())
        if digest(directory/'cloud-logs.tar.gz')!=status['archive_sha256']:raise ValueError('archive differs from completed run')
        unpack(directory/'cloud-logs.tar.gz',directory);downloaded=True
        if status['error']:raise RuntimeError('AWS controller failed: '+status['error'])
        result=analyze_run(directory,case)
        outputs=[]
        for i in range(case['n']):
            events=[json.loads(l) for l in (directory/f'party-{i}.jsonl').read_text().splitlines()]
            outputs.extend(e['elapsed_us'] for e in events if e.get('event',{}).get('kind') in ('coin','beacon'))
        result.update(max_node_elapsed_to_output_ms=max(outputs)/1000,controller_placement='AWS party 0',
                      latency_scope='AWS controller START to observation; local VPN excluded',controller_resources=status)
        save(directory/'result.json',result)
    finally:
        failures=[]
        if launched and not downloaded:
            try:
                stop=f'if test -f {remote}/controller.pid; then kill -TERM -- -$(cat {remote}/controller.pid) 2>/dev/null || true; fi'
                await controller.shell('bash -c '+shlex.quote(stop))
            except Exception as exc:failures.append('controller stop: '+str(exc))
        for h in authorized:
            try:await retry(lambda h=h:h.shell(shell(remove)))
            except Exception as exc:failures.append(str(exc))
        # Remote run folders are owned by this unique tag. On failure the fleet's
        # finally cleanup terminates instances; retained files permit recovery.
        try:
            code='import pathlib; p=pathlib.Path('+repr(remote+'/key')+'); p.unlink(missing_ok=True)'
            await controller.shell(shell(code))
        except Exception as exc:failures.append(str(exc))
        for name in ('key','key.pub'):(directory/name).unlink(missing_ok=True)
        save(directory/'credential-cleanup.json',dict(confirmed=not failures,errors=failures))
        if failures:raise RuntimeError('temporary credential cleanup incomplete: '+repr(failures))
    if downloaded:
        await controller.shell('rm -rf -- '+shlex.quote(remote))

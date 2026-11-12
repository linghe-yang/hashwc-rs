"""Runs on AWS slot 0. No AWS credentials or AWS API calls."""
import asyncio
import json
from pathlib import Path
import resource
import sys
import tarfile
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'code/remote_coin'))
import remote
from common import digest,save

async def main():
    job=json.loads((HERE/'job.json').read_text())
    args=SimpleNamespace(user=job['user'],key=HERE/'key',port=job['port'],generator=Path(job['generator']))
    hosts=[]
    for row in job['peers']:
        h=remote.Host(row['public_ip'],args)
        opt=['-o',f'UserKnownHostsFile={HERE}/known_hosts','-o',f'HostKeyAlias={row["id"]}']
        h.ssh[1:1]=opt;h.scp[1:1]=opt
        hosts.append(h)
    error=None
    try:
        await remote.experiment(args,hosts,job['case'],job['settings'],job['driver_sha256'],HERE/'run')
        p=HERE/'run/result.json';result=json.loads(p.read_text())
        result['latency_scope']='AWS slot-0 controller START to observation; no local VPN/SSH link'
        result['controller_placement']='co-located with party 0'
        save(p,result)
    except BaseException as exc:
        error=repr(exc)
    finally:
        usage=resource.getrusage(resource.RUSAGE_SELF)
        children=resource.getrusage(resource.RUSAGE_CHILDREN)
        # Configs and temporary SSH credentials are deliberately excluded.
        folder=HERE/'run'
        names=['case.json','parameters.json','execution.json','control.json','deployment.json','result.json']
        files=[folder/n for n in names if (folder/n).is_file()]
        files+=list(folder.glob('party-*.jsonl'))+list(folder.glob('remote-*'))
        with tarfile.open(HERE/'logs.tar.gz','w:gz') as tar:
            for p in files:
                if p.is_file():tar.add(p,arcname=p.name)
        save(HERE/'status.json',dict(finished=True,error=error,archive_sha256=digest(HERE/'logs.tar.gz'),
             controller_user_s=usage.ru_utime,controller_system_s=usage.ru_stime,controller_max_rss_kib=usage.ru_maxrss,
             controller_subprocess_user_s=children.ru_utime,controller_subprocess_system_s=children.ru_stime,
             ssh_subprocess_cpu_included=False))
    if error:raise RuntimeError(error)

if __name__=='__main__':asyncio.run(main())

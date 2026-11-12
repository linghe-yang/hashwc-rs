import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

from campaign import certified_timeout, stages, check, HERE, WAN, digest, save, read
from measurements import table
from plot_paired import plot

class OfflineTests(unittest.TestCase):
    def test_actual_launch_arguments_and_credit_verification(self):
        from campaign import PairedCloud,pl
        region=pl.REGIONS[0]
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            cfg=dict(instance_type='t3a.medium',cpu_credits='unlimited')
            state=dict(fleet='offline',regions={region:dict(aux='sg-offline')},requests=[])
            cloud=PairedCloud(root,cfg,SimpleNamespace(),state)
            def fake_apply(name,ops,config,call):
                call(region,'run-instances','--instance-type',config['instance_type'],'--security-group-ids','sg-test','--client-token','test')
            with patch.object(pl.p.fleet,'apply',fake_apply),patch.object(pl.p,'ec2',return_value={'Instances':[{'InstanceId':'i-test'}]}) as ec2:
                cloud.launch(region,0)
                args=ec2.call_args.args
                self.assertEqual(args[args.index('--instance-type')+1],'t3a.medium')
                self.assertEqual(args[args.index('--credit-specification')+1],'CpuCredits=unlimited')
            with patch.object(pl.Cloud,'grow',return_value=[dict(id='i-test',region=region)]),patch.object(pl.p,'ec2',return_value={'InstanceCreditSpecifications':[dict(InstanceId='i-test',CpuCredits='standard')]}):
                with self.assertRaises(RuntimeError):cloud.grow(1,0,root)
    def test_timeout_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            work=Path(t); raw=work/'raw'; raw.mkdir()
            case=dict(protocol='hashrand',n=2)
            save(work/'control.json',dict(phase='await_outputs',error='TimeoutError()'))
            save(work/'credential-cleanup.json',dict(confirmed=True))
            (work/'cloud-logs.tar.gz').write_bytes(b'test')
            save(work/'cloud-status.json',dict(error='TimeoutError()',archive_sha256=digest(work/'cloud-logs.tar.gz')))
            for i in range(2):
                (raw/f'remote-{i}-stderr.log').write_text('')
                (raw/f'remote-{i}-stdout.jsonl').write_text('{}')
                (work/f'party-{i}.jsonl').write_text(json.dumps({'kind':'started'})+'\n')
            self.assertTrue(certified_timeout(work,raw,case))
            save(work/'control.json',dict(phase='drain',error='TimeoutError()'))
            self.assertFalse(certified_timeout(work,raw,case))
            save(work/'control.json',dict(phase='await_outputs',error='TimeoutError()'))
            (raw/'remote-1-stderr.log').write_text('panicked')
            self.assertFalse(certified_timeout(work,raw,case))

    def test_order_and_gates(self):
        plan=read(HERE/'results/original-plan.json')
        plan['wan_sources'] = {name: digest(WAN / name) for name in plan['wan_sources']}
        check(plan)
        class Host:
            async def shell(self,cmd):return 'False'
        class Cloud:
            def grow(self,n,previous,stage):return [Host() for _ in range(n)]
        for failures,expected in ((1,32),(2,26)):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                executed=[]
                async def measure(args,cloud,hosts,c,plan,policy,stage):
                    executed.append(c['job_id'])
                    dest=stage/'analysis'/c['job_id']; dest.mkdir(parents=True)
                    if c['protocol']=='hashrand' and c['n']==16 and c['repeat']<=failures:
                        raw=stage/'remote-logs'/c['job_id'];raw.mkdir(parents=True)
                        for i in range(c['n']):(raw/f'remote-{i}-stdout.jsonl').touch()
                        save(stage/'controller-logs'/c['job_id']/'deployment.json',dict(remote='test'))
                        raise RuntimeError('AWS controller failed: TimeoutError()')
                    save(dest/'result.json',{})
                async def cleanup(*args):pass
                def export(work,dest,c,r):
                    return dict(job_id=c['job_id'],family=c['family'],protocol=c['protocol'],repeat=c['repeat'],n=c['n'],
                        status='success' if r is not None else 'online_timeout',mean_cpu_ms=50,latency_ms=200,
                        sent_bytes=5000,path_bytes=4000,shared_bytes=1000)
                with patch('campaign.pl.measure',measure),patch('campaign.pl.p.connections',lambda args,r,out:r),patch('campaign.pl.p.remote.cleanup',cleanup),patch('campaign.export',export),patch('campaign.certified_timeout',return_value=True):
                    stages(SimpleNamespace(out=root),Cloud(),plan,{})
                self.assertEqual(len(executed),expected)
                self.assertIn('sui-n64--whcc-r2',executed)
                plot(root)
                self.assertTrue((root/'aptos-paired.pdf').is_file())
if __name__=='__main__':unittest.main()


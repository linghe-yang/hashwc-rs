import asyncio
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from campaign import pl
import campaign_cloud
import cloud_control as cc


class SSHRecovery(unittest.TestCase):
    def test_admission_replaces_only_failed_slot_until_all_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            cloud=campaign_cloud.Cloud.__new__(campaign_cloud.Cloud)
            cloud.out=root
            cloud.args=SimpleNamespace(boot_ssh_seconds=180,driver=root/'driver')
            cloud.state=dict(requests=[],driver_sha256='digest')
            rows={}
            def launch(region,slot,generation=0):
                iid=f'i-{slot}-{generation}'
                rows[slot]=dict(slot=slot,id=iid,region=region)
                cloud.state['requests'].append(dict(slot=slot,id=iid,region=region,generation=generation))
            cloud.launch=Mock(side_effect=launch)
            cloud.write=Mock()
            cloud.inventory=lambda n:[rows[i] for i in range(n)]
            cloud.sync_rules=Mock()
            with patch.object(pl.p,'connections',side_effect=lambda args,rs,out:[r['id'] for r in rs]), \
                 patch.object(pl.p,'retire') as retire, \
                 patch.object(pl.p.remote,'ssh_failures',new_callable=AsyncMock,side_effect=[[1],[1],[]]) as test, \
                 patch.object(pl.p.remote,'deploy',new_callable=AsyncMock) as deploy:
                result=cloud.grow(2,0,root)
            self.assertEqual([call.args[0]['id'] for call in retire.call_args_list],['i-1-0','i-1-1'])
            self.assertEqual([call.args[0] for call in test.await_args_list],
                             [['i-0-0','i-1-0'],['i-0-0','i-1-1'],['i-0-0','i-1-2']])
            self.assertEqual(result[1]['region'],campaign_cloud.REGIONS[1])
            self.assertEqual([c.args[0] for c in deploy.await_args_list],['i-0-0','i-1-2'])


class DownloadRecovery(unittest.IsolatedAsyncioTestCase):
    async def test_reboot_then_check_new_boot_and_redownload(self):
        data=b'worker measurement'
        checksum=hashlib.sha256(data).hexdigest()
        host=Mock()
        host.shell=AsyncMock(side_effect=[checksum+'  log','old','old\n120 22','new\n2 1',checksum+'  log'])
        writes=0
        async def transfer(src,temp):
            nonlocal writes
            writes+=1
            temp.write_bytes(data if writes==2 else b'partial')
            if writes==1: raise pl.p.remote.SSHTransportError('connection reset')
        host.get=transfer
        row=dict(id='i-source',slot=7,region='us-east-1')
        with tempfile.TemporaryDirectory() as tmp, patch.object(pl.p,'ec2') as ec2, \
                patch.object(cc.asyncio,'sleep',new_callable=AsyncMock):
            path=Path(tmp)/'log'
            await cc.verified_get(host,'log',path,row)
            ec2.assert_called_once_with('us-east-1','reboot-instances','--instance-ids','i-source')
            self.assertEqual(path.read_bytes(),data)
            self.assertEqual(writes,2)

    async def test_corrupt_file_is_not_a_transport_failure(self):
        host=Mock()
        host.shell=AsyncMock(return_value='0'*64+'  log')
        async def transfer(src,temp):temp.write_bytes(b'bad')
        host.get=transfer
        with tempfile.TemporaryDirectory() as tmp, patch.object(pl.p,'ec2') as ec2:
            with self.assertRaisesRegex(ValueError,'checksum mismatch'):
                await cc.verified_get(host,'log',Path(tmp)/'dest',{})
            ec2.assert_not_called()


if __name__=='__main__':unittest.main()

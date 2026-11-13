"""Offline test of the live worker-error path through campaign cleanup."""
import asyncio
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from campaign import pl
from common import save

remote = pl.p.remote


class WorkerLogAbort(unittest.TestCase):
    def test_successful_exit_with_error_stops_campaign(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root/'n32/controller-logs/test'
            cloud = Mock()
            visited = []
            case = dict(case_id='local', n=2, protocol='whcc', parameters={}, weights=['1','2'], threshold='1')
            hosts = []
            sha = 'd'*64
            for i in range(2):
                node = root/f'worker{i}'
                binary = node/'.hashwc/bin'/sha
                binary.parent.mkdir(parents=True)
                binary.write_text(
                    "#!/usr/bin/env python3\nimport json, sys\n"
                    "p=json.load(open('node.json'))['id']\n"
                    "print(json.dumps(dict(kind='ready',party=p)),flush=True)\n"
                    "assert input()=='start'\n"
                    "if p==0: print('ERROR injected failure',file=sys.stderr,flush=True)\n"
                    "for line in sys.stdin: pass\n"
                )
                binary.chmod(0o700)
                class Local:
                    ip='127.0.0.1'
                    async def shell(self, command):
                        return await remote.command(*self.ssh,command)
                    async def get(self, src, dst):
                        shutil.copyfile(self.folder/src,dst)
                    async def put(self, src, dst):
                        shutil.copyfile(src,self.folder/dst)
                h=Local()
                h.folder=node
                h.ssh=['env','-C',str(node),'sh','-c']
                hosts.append(h)
            def config(_generator, path, *_):
                for i in range(2):
                    save(path/f'node-{i}.json',dict(id=i))
            def stages(*_):
                visited.append(32)
                save(work.parent.parent/'progress.json',dict(current='test'))
                args=SimpleNamespace(generator=root,port=21000)
                settings=dict(tokio_workers=2,quiet_seconds=1,prepare_timeout_s=15,coin_timeout_s=30,
                              execution=dict(actor_inbox=4096, compute_jobs=1, transport_receive_capacity=1024,
                                             transport_stall_ms=30000))
                asyncio.run(remote.experiment(args,hosts,case,settings,sha,work))
                visited.append(48)
            with patch.object(remote,'make_config',config), self.assertRaisesRegex(RuntimeError,'ERROR injected'):
                pl.execute(SimpleNamespace(out=root),cloud,{},None,stage_runner=stages)
            self.assertEqual(visited,[32])
            cloud.cleanup.assert_called_once()
            control=json.loads((work/'control.json').read_text())
            self.assertEqual(control['returncodes'],{'0':0,'1':0})
            self.assertIn('party 0 stderr: ERROR injected',control['error'])
            self.assertEqual(control['phase'],'await_outputs')
            self.assertIn('ERROR injected',(work/'remote-0-stderr.log').read_text())
            self.assertTrue((root/'diagnosis.json').is_file())


if __name__=='__main__':
    unittest.main()

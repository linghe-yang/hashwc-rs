"""Retry a case after a completed evaluation, with a prioritized capture reader.
Only the external tcpdump process gets a different nice value. Protocol processes,
TCP payload definition, filter, snapshot length and all security parameters agree.
The auxiliary runner hash and nice value are recorded for reproducibility.
"""
import copy,hashlib,json,os,sys,time,traceback
from pathlib import Path
root=Path(__file__).resolve().parents[2];sys.path.insert(0,str(root/'benchmark'))
from benchmark.capture import NativeCapture
from benchmark.config import Policy,write_json
from benchmark.local import LocalBench
from benchmark.logs import LogParser

policy_path=Path(sys.argv[1]).resolve()
status_path=Path(sys.argv[2]).resolve()
priority=int(sys.argv[3]) if len(sys.argv)>3 else -15
while json.loads(status_path.read_text())['status']!='complete': time.sleep(2)
policy=Policy(policy_path);case=policy.cases[0]
state=json.loads(status_path.read_text());info=next(c for c in state['cases'] if c['name']==case.name)
info['previous_attempts']=[dict(status=info['status'],reason=info.get('reason'),results=info['results'])]
info.update(status='retrying',completed_runs=0,results=[],latency_ms=[])
state['status']='running';write_json(status_path,state)
tuning=dict(tcpdump_nice=priority,runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            protocol_process_priority='unchanged',snapshot_bytes=256,capture_buffer_kib=131072,
            note='Only scheduling priority changes. Any kernel packet drop still invalidates a run.')
original=NativeCapture.start

def prioritized(self):
    original(self)
    os.setpriority(os.PRIO_PROCESS,self.process.pid,priority)
    write_json(self.directory/'capture-tuning.json',dict(tuning,actual_nice=os.getpriority(os.PRIO_PROCESS,self.process.pid)))
NativeCapture.start=prioritized
for number in range(1,4):
    params=copy.deepcopy(case.json);params['runs']=1
    try:
        before=set(status_path.parent.glob('whcc-'+case.name+'-*/whcc-0-*.json'))
        ret=LocalBench(params,policy.node_parameters.json,policy_source=policy.source,output='file',results=status_path.parent).run()
        files=set(status_path.parent.glob('whcc-'+case.name+'-*/whcc-0-*.json'))-before
        if len(files)!=1: raise RuntimeError('ambiguous new result')
        file=files.pop();run=file.parent/'run-001/run.json';manifest=json.loads(run.read_text())
        manifest['build']['capture_tuning']=tuning;write_json(run,manifest)
        parsed=LogParser.process(file.parent);parsed.print(file.with_suffix('.txt'));print(parsed.result(),flush=True)
        data=json.loads(file.read_text())
        info['results'].append(str(file));info['latency_ms'].append(data['runs'][0]['latency_ms']);info['completed_runs']+=1
        write_json(status_path,state)
    except Exception as e:
        info.update(status='failed',reason=str(e));traceback.print_exc();break
if info['completed_runs']==3:
    info['status']='complete';info.pop('reason',None)
info['capture_tuning']=tuning
state['status']='complete';write_json(status_path,state)

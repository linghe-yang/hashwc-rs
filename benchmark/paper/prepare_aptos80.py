from pathlib import Path
import json, random, sys
repo=Path(sys.argv[1]); out=Path(sys.argv[2])
paper=repo/'benchmark/paper'
sys.path[:0]=[str(repo/'benchmark/wan_scaling'),str(repo/'benchmark/clean_comparison')]
from common import digest, policy_hash, save, validate_input
from reducer import reduce_weights
from evidence import verify_source
snap=paper/'data/aptos/manifest.json'
base=paper/'inputs/aptos-n64.json'
anchor=json.loads(base.read_bytes())
assert digest(snap)==anchor['source_manifest_sha256']
snapshot=json.loads(snap.read_bytes()); byid={v['id']:int(v['weight']) for v in snapshot['validators']}
prefix=anchor['party_source_ids']; assert len(set(prefix))==64 and len(byid)==83
assert [byid[i] for i in prefix]==list(map(int,anchor['original_weights']))
seed=20261103
extra=random.Random(seed).sample(sorted(set(byid)-set(prefix)),16)
ids=prefix+extra; w=[byid[i] for i in ids]; t=(sum(w)+2)//3
threshold=t; weights=w; steps=[]
while True:
 step=reduce_weights(weights,threshold,budget_factor=anchor['reduction_budget_factor'],backend="numpy")
 steps.append(step)
 strong=step['strong']; next_w=list(map(int,strong['weights'])); next_t=int(strong['threshold'])
 if weights==next_w and threshold==next_t: break
 weights,threshold=next_w,next_t
case=dict(case_id="aptos-n80",n=80,chain="aptos",weights=list(map(str,weights)),threshold=str(threshold),
          original_weights=list(map(str,w)),original_threshold=str(t),party_source_ids=ids,
          source_n=len(byid),source_manifest=anchor['source_manifest'],source_manifest_sha256=digest(snap),
          prefix_case="aptos-n64",prefix_sha256=digest(base),extension_seed=seed,
          extension_rule="freeze 64 existing IDs, random.Random(20261103).sample(sorted(remaining IDs),16) without replacement",
          reducer_version=steps[-1]['version'],reduction_budget_factor=anchor['reduction_budget_factor'],
          threshold_rule=anchor['threshold_rule'],input_policy_sha256=policy_hash(weights,threshold))
verify_source(case,steps,snapshot); validate_input(case)
coalition=[]; subtotal=0
for i in sorted(range(80),key=lambda i:(w[i],i)):
 if 3*(subtotal+w[i])>=sum(w):break
 coalition.append(i);subtotal+=w[i]
out.mkdir(exist_ok=False)
save(out/'reduction.json',steps);case['reduction_certificate_sha256']=digest(out/'reduction.json')
save(out/'aptos-n80.json',case);save(out/'coalition.json',dict(faulty=len(coalition),ids=coalition,weight_fraction=subtotal/sum(w)))
print('n=80; F=',len(coalition),'weight fraction=',subtotal/sum(w),'reduced sum=',sum(weights),'raw sum=',sum(w),flush=True)

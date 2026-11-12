"""Export per-run tidy tables. The raw node logs remain authoritative."""
import csv
import json
from pathlib import Path

def read(path):
    return json.loads(path.read_text())

def coin_outputs(work, n):
    outputs = []
    for i in range(n):
        with (work / f'party-{i}.jsonl').open() as log:
            events = [event for line in log if (event := json.loads(line)).get('event', {}).get('kind') in ('coin', 'beacon')]
        if len(events) > 1 or any(event['party'] != i for event in events):
            raise ValueError(f'invalid output records for party {i}')
        outputs.extend(events)
    if outputs and any(e['event']['value'] != outputs[0]['event']['value'] for e in outputs):
        raise ValueError('coin outputs disagree')
    return outputs

def table(path,rows):
    if not rows:
        return
    with path.open('w', newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(dict.fromkeys(k for r in rows for k in r)))
        writer.writeheader()
        writer.writerows(rows)

def export(work,dest,case,result=None):
    dest.mkdir(parents=True,exist_ok=True)
    n=case['n']
    common={k:case[k] for k in ('job_id','family','n','protocol','repeat')}
    dealers=[dict(dealer=i,selected=0,retrieve_started=0,remote_getters=0,local_reuses=0,data_response_body_bytes=0,
                 remote_logical_file_bytes=0,bulk_bytes=None) for i in range(n)]
    samples=[]; nodes=[]; outputs=0
    for i in range(n):
        log=work/f'party-{i}.jsonl'
        events=[json.loads(s) for s in log.read_text().splitlines()]
        outputs+=any(e.get('event',{}).get('kind') in ('coin','beacon') for e in events)
        for e in events:
            r=e.get('resources')
            if r:
                samples.append(dict(**common,party=i,sequence=e['sequence'],kind=e['kind'],
                    event=e.get('event',{}).get('kind'),elapsed_us=e.get('elapsed_us'),observer_ns=e['observer_ns'],
                    **{k:r[k] for k in ('user_us','system_us','rss_kib','max_rss_kib','major_faults')}))
        audits=[e for e in events if e['kind']=='bulk_audit']
        if result is None:
            continue
        if len(audits)!=1:
            raise ValueError(f'{log}: missing or repeated final audit')
        p=result['parties'][str(i)]
        nodes.append(dict(**common,party=i,**{k:p[k] for k in ('output_ms','peak_rss_kib','total_cpu_ms','received_bytes','sent_bytes')},
                          **p['cpu_phases_ms']))
        for dealer,field,value in audits[0]['counters']:
            d=dealers[dealer]
            if field=='data_response_body_bytes':
                d[field]+=value
            elif field in ('selected','retrieve_started'):
                assert value==1 and case['protocol']=='whcc'
                d[field]+=1
            elif field in ('remote_file_bytes','local_reuse_bytes'):
                if (field=='local_reuse_bytes')!=(dealer==i) or value<=0 or d['bulk_bytes'] not in (None,value):
                    raise ValueError('file provenance/size mismatch')
                d['bulk_bytes']=value
                if field=='remote_file_bytes':
                    d['remote_getters']+=1
                    d['remote_logical_file_bytes']+=value
                else:
                    d['local_reuses']+=1
            else:
                raise ValueError(field)
    table(dest/'resource-samples.csv',samples)
    row=dict(**common,outputs=outputs,status='online_timeout' if result is None else 'success')
    if result is not None:
        assert outputs==n and result['agreement'] and result['status']=='success'
        services=result['per_service_sent_bytes']
        control={'wbinaa','wra','wgather'}
        if case['protocol'] in ('warmup','whcc'):
            expected={'wrbc','csshashcoin/private','csshashcoin/recovery'} if case['protocol']=='warmup' else {'wrbc','wavid','whcc/private','whcc/recovery'}
            assert set(services)<=expected|control
            assert all(d['bulk_bytes'] is not None for d in dealers)
            if case['protocol']=='warmup':
                assert all(d['remote_getters']==n-1 and d['local_reuses']==1 for d in dealers)
                for d in dealers:
                    d['selected']=None
                    d['retrieve_started']=None
            else:
                assert all(d['remote_getters']<=d['retrieve_started']<=d['selected']<=n and
                           d['remote_getters']+d['local_reuses']<=d['selected'] for d in dealers)
            table(dest/'dealers.csv',[dict(**common,**d) for d in dealers])
            row.update(remote_getters_per_dealer=sum(d['remote_getters'] for d in dealers)/n,
                       local_reuses=sum(d['local_reuses'] for d in dealers),
                       remote_logical_file_bytes=sum(d['remote_logical_file_bytes'] for d in dealers),
                       data_response_body_bytes=sum(d['data_response_body_bytes'] for d in dealers))
            if case['protocol']=='whcc':
                row['selected_per_dealer']=sum(d['selected'] for d in dealers)/n
            row.update(path_bytes=sum(services.get(k,0) for k in expected),shared_bytes=sum(services.get(k,0) for k in control))
            assert row['path_bytes']+row['shared_bytes']==result['total_sent_bytes']
        table(dest/'nodes.csv',nodes)
        table(dest/'services.csv',[dict(**common,service=k,sent_bytes=v) for k,v in services.items()])
        row.update(sent_bytes=result['total_sent_bytes'],latency_ms=result['max_node_elapsed_to_output_ms'],
                   mean_cpu_ms=result['mean_party_total_cpu_ms'],peak_party_rss_kib=result['peak_party_rss_kib'])
    table(dest/'measurement.csv',[row])
    return row


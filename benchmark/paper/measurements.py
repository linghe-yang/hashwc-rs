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

def ena_rows(control, common):
    snapshots = control.get('ena_before_start')
    if snapshots is None:
        return []
    after = control['ena_after_stop']
    if len(snapshots) != common['n'] or len(after) != common['n']:
        raise ValueError('incomplete ENA party list')
    rows = []
    for party, (a, b) in enumerate(zip(snapshots, after)):
        before = a.get('interfaces', {})
        end = b.get('interfaces', {})
        for interface in sorted(before.keys() | end.keys()) or [None]:
            for counter in ('bw_in_allowance_exceeded', 'bw_out_allowance_exceeded', 'pps_allowance_exceeded'):
                start = before.get(interface, {}).get(counter)
                stop = end.get(interface, {}).get(counter)
                delta = None
                status = a.get('error') or b.get('error')
                if status is None:
                    if start is None or stop is None:
                        status = 'missing counter or interface'
                    elif stop < start:
                        status = 'counter reset'
                    else:
                        delta = stop - start
                        status = 'ok'
                rows.append(dict(**common, party=party, interface=interface, counter=counter,
                                 before=start, after=stop, delta=delta, status=status))
    return rows


def export(work,dest,case,result=None):
    dest.mkdir(parents=True,exist_ok=True)
    n=case['n']
    common={k:case[k] for k in ('job_id','family','n','protocol','repeat')}
    if (work/'control.json').exists():
        table(dest/'ena.csv', ena_rows(read(work/'control.json'), common))
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
            elif field in ('terminal_broadcasts', 'certificate_bytes_before_fanout',
                           'root_generated', 'root_received', 'module_generated', 'module_received',
                           'module_generate_ns', 'module_verify_ns',
                           'root_checks', 'root_check_ns', 'local_root_certificates',
                           'local_root_final_step_ns'):
                d[field] = d.get(field, 0) + value
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
    if case.get('campaign') == 'css-max' and result is not None:
        from local_rejection import summarize_run
        honest = sorted(set(range(n)) - set(case['faulty_dealers']))
        metrics = summarize_run(work, case, result, honest)
        path = 'PVR+Sampling' if case['protocol'] == 'whcc' else 'RBC full retrieval'
        row.update(path=path, faulty=len(case['faulty_dealers']), honest=len(honest), **metrics)
        table(dest/'recovery.csv',[dict(**common, path=path, honest=len(honest),
              mean_honest_sent_bytes=metrics['mean_observer_path_bytes'],
              max_honest_freeze_to_required_ms=metrics['last_observer_required_ms'])])
    table(dest/'measurement.csv',[row])
    return row


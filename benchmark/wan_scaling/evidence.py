"""Offline certificate verification; no network or protocol start."""
import json
from common import digest
from reducer import inspect_candidate

def verify_source(c,certificate,snapshot):
    ids=c['party_source_ids']; table={x['id']:int(x['weight']) for x in snapshot['validators']}
    w=[table[i] for i in ids];t=(sum(w)+2)//3
    assert len(set(ids))==c['n'] and w==list(map(int,c['original_weights']))
    assert t==int(c['original_threshold'])
    for step in certificate:
        assert step['version']=='bounded-sum-exact-integer-v2'
        assert step['original']['weights']==list(map(str,w)) and int(step['original']['threshold'])==t
        v=list(map(int,step['strong']['weights']));u=int(step['strong']['threshold'])
        if (v,u)!=(w,t):
            if step['strong']['method']=='exact-policy-gcd':
                g=int(step['strong']['certificate']['divisor'])
                assert g>0 and all(a==g*b for a,b in zip(w,v)) and t==g*u
            else:
                check=inspect_candidate(w,t,v,step['candidate_sum_budget'])
                assert check['strong_threshold']==u
        assert u==(sum(v)+2)//3
        w,t=v,u
    assert certificate and w==list(map(int,c['weights'])) and t==int(c['threshold'])
    assert certificate[-1]['original']['weights']==certificate[-1]['strong']['weights']
    assert certificate[-1]['original']['threshold']==certificate[-1]['strong']['threshold']

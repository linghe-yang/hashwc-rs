"""Reconstruct the published measurements from the verified cloud log archives."""
import csv
import hashlib
import json
import re
import shutil
import sys
import tarfile
import tempfile
from collections import Counter
from pathlib import Path

from measurements import coin_outputs, export, read

RESULTS = Path(__file__).resolve().parent / 'results'
sys.path.insert(0, str(RESULTS.parents[1] / 'clean_comparison'))
from analyze import analyze_run


def main():
    index = read(RESULTS / 'verified.json')
    logs = {entry['job']: entry for entry in index['logs']}
    with (RESULTS / 'measurements.csv').open() as f:
        rows = list(csv.DictReader(f))
    expected = {c['job_id'] for c in read(RESULTS / 'original-plan.json')['configurations']}
    if len(rows) != 32 or {r['job_id'] for r in rows} != expected:
        raise ValueError('published job matrix differs from the original plan')
    if Counter(row['status'] for row in rows) != index['counts']:
        raise ValueError('outcome counts differ')
    for row in rows:
        job = row['job_id']
        if row['status'] == 'not_run_after_two_timeouts':
            if job in logs or row['protocol'] != 'hashrand' or row['n'] != '64':
                raise ValueError(f'{job}: invalid skip')
            continue
        entry = logs.pop(job)
        folder = RESULTS / 'logs' / job
        archive = folder / 'cloud-logs.tar.gz'
        status = read(folder / 'cloud-status.json')
        with archive.open('rb') as stream:
            checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
        if checksum != entry['archive_sha256'] or checksum != status['archive_sha256']:
            raise ValueError(f'{job}: archive digest differs')
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            with tarfile.open(archive, 'r|gz') as tar:
                for member in tar:
                    if not re.fullmatch(r'party-\d+\.jsonl|control\.json|case\.json|execution\.json|result\.json', member.name):
                        continue
                    if not member.isfile():
                        raise ValueError(f'{job}: unexpected member type')
                    with (work / member.name).open('xb') as dest:
                        shutil.copyfileobj(tar.extractfile(member), dest)
            case = read(work / 'case.json')
            if case['job_id'] != job:
                raise ValueError('archive identity differs')
            outputs = coin_outputs(work, case['n'])
            if row['status'] == 'success':
                if len(outputs) != case['n'] or status['error'] is not None:
                    raise ValueError(f'{job}: incomplete output')
                result = analyze_run(work, case)
                recorded = read(work / 'result.json')
                if any(recorded.get(key) != value for key, value in result.items()):
                    raise ValueError(f'{job}: event-derived result differs from the archived analysis')
                result['max_node_elapsed_to_output_ms'] = max(e['elapsed_us'] for e in outputs) / 1000
            else:
                control = read(work / 'control.json')
                if (control['error'] != 'TimeoutError()' or control['phase'] != 'await_outputs'
                        or status['error'] != 'TimeoutError()' or len(outputs) >= case['n']):
                    raise ValueError(f'{job}: invalid timeout')
                result = None
            dest = work / 'derived'
            actual = export(work, dest, case, result)
            if {k: str(v) for k, v in actual.items()} != {k: v for k, v in row.items() if v != ''}:
                raise ValueError(f'{job}: regenerated measurements differ')
            for file in dest.glob('*.csv'):
                with file.open(newline='') as fresh, (folder/file.name).open(newline='') as stored:
                    if list(csv.DictReader(fresh)) != list(csv.DictReader(stored)):
                        raise ValueError(f'{job}: {file.name} differs')
    if logs:
        raise ValueError('unexpected archived runs')
    print('Verified 30 raw archives and 32 scheduled observations:', index['counts'])


if __name__ == '__main__':
    main()

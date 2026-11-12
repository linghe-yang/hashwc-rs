"""Run a frozen paper plan with one Linux loopback process per party."""
import argparse
import asyncio
import os
from collections import Counter
from pathlib import Path

from prepare import FROZEN, ROOT, read, run
from runner import run_case
from measurements import coin_outputs, export, table


async def local(prepared, out):
    plan = run.load_plan(prepared, check_controller=True)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    binaries = {k: prepared / v['path'] for k, v in plan['binaries'].items()}
    os.environ['COIN_BULK_AUDIT'] = '1'
    timeouts = Counter()
    rows = []
    for case in plan['configurations']:
        job, n = case['job_id'], case['n']
        identity = {k: case[k] for k in ('job_id','family','protocol','n','repeat')}
        key = (case['family'], n)
        if case['protocol'] == 'hashrand' and any(f == key[0] and size < n and count >= 2
                                                  for (f, size), count in timeouts.items()):
            rows.append(dict(**identity, status='not_run_after_two_timeouts'))
        else:
            print(job, flush=True)
            work = out / 'runs' / job
            result = await run_case(work, case, binaries, plan['settings'])
            outputs = coin_outputs(work, n)
            if result['status'] == 'success' and len(outputs) == n:
                result['max_node_elapsed_to_output_ms'] = max(e['elapsed_us'] for e in outputs) / 1000
            else:
                control = read(work / 'control.json')
                if (case['protocol'] != 'hashrand' or control.get('phase') != 'await_outputs'
                        or control['error'] != 'TimeoutError: ' or len(outputs) >= n):
                    raise RuntimeError(f'{job}: {control["error"] or result.get("error", "incomplete")}')
                timeouts[key] += 1
                result = None
            rows.append(export(work, out / 'analysis' / job, case, result))
        table(out / 'measurements.csv', rows)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, default=FROZEN)
    parser.add_argument('--out', type=Path, default=ROOT/'results/local-paper')
    args = parser.parse_args()
    asyncio.run(local(args.prepared.resolve(), args.out.resolve()))

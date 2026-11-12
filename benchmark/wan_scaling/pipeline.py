"""Stage measurement and cleanup for the paper AWS campaign."""
import json
from campaign_cloud import BASE, REGIONS, Cloud, p
from common import save
import cloud_control

async def measure(args,cloud,hosts,case,plan,policy,stage):
    key=case["job_id"]
    work=stage/"controller-logs"/key
    raw=stage/"remote-logs"/key
    analysis=stage/"analysis"/key
    raw.mkdir(parents=True)
    analysis.mkdir(parents=True)
    try:
        await cloud_control.experiment(args,hosts,case,plan,cloud.state["driver_sha256"],work,
                                       json.loads((stage/'inventory.json').read_text()))
    finally:
        for path in work.glob("remote-*"):
            path.rename(raw/path.name)
        if (work/"result.json").exists():
            (work/"result.json").rename(analysis/"result.json")
    for i in range(case["n"]):
        for name in ("stdout.jsonl","stderr.log"):
            if not (raw/f"remote-{i}-{name}").is_file():
                raise RuntimeError(f"missing verified {key} slot {i} {name}")
    result=json.loads((analysis/"result.json").read_text())
    if result["status"]!="success": raise RuntimeError("analyzer did not certify "+key)
def report_failure(out,error):
    stages_so_far=sorted(out.glob("n[0-9][0-9]"))
    evidence=dict(error=repr(error))
    if stages_so_far:
        stage=stages_so_far[-1]
        evidence["stage"]=stage.name
        for name in ("progress","gate","admission"):
            path=stage/(name+".json")
            if path.exists():evidence[name]=json.loads(path.read_text())
        progress=evidence.get("progress",{})
        job=progress.get("current","")
        ctrl=stage/"controller-logs"/job/"control.json"
        if ctrl.exists():
            control=json.loads(ctrl.read_text())
            evidence["controller_error"]=control["error"]
            evidence["nonzero_exits"]={i:v for i,v in control["returncodes"].items() if v!=0}
        evidence["diagnostic_paths"]=["inventory.json","controller-logs","remote-logs","analysis"]
        if not (stage/"gate.json").exists():
            save(stage/"gate.json",dict(passed=False,issues=[repr(error)],completed=evidence.get("progress",{}).get("completed",[])))
    save(out/"diagnosis.json",evidence)


def execute(args,cloud,plan,policy,stage_runner):
    error=None
    try:
        cloud.preflight()
        cloud.ensure_groups()
        stage_runner(args,cloud,plan,policy)
    except BaseException as exc:
        error=exc
        save(args.out/"failure.json",dict(error=repr(exc)))
        raise
    finally:
        try: cloud.cleanup()
        finally:
            if error is not None:
                report_failure(args.out,error)

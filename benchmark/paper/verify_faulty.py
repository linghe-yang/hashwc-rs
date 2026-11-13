"""Recompute the faulty-dealer panels from the eight archived WAN runs."""
import csv
import hashlib
import json
import math
import shutil
import tarfile
import tempfile
from pathlib import Path

from verify_results import RESULTS, analyze_run
from local_rejection import maximum_coalition
from measurements import coin_outputs, export


def rows(path):
    with path.open(newline="") as source:
        return list(csv.DictReader(source))


def verify_run(n, protocol, checksum):
    job = f"aptos-n{n}--{protocol}-r1"
    folder = RESULTS / "faulty" / job
    archive = folder / "cloud-logs.tar.gz"
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != checksum:
            raise ValueError(f"{job}: checksum mismatch")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        names = {"case.json", "control.json", "execution.json", "result.json"}
        names.update(f"party-{i}.jsonl" for i in range(n))
        with tarfile.open(archive, "r|gz") as source:
            for item in source:
                if item.name in names:
                    if not item.isfile():
                        raise ValueError(f"{job}: unexpected archive member")
                    with (work / item.name).open("xb") as out:
                        shutil.copyfileobj(source.extractfile(item), out)
        case = json.loads((work / "case.json").read_bytes())
        inputs = json.loads((RESULTS.parent / "inputs" / f"aptos-n{n}.json").read_bytes())
        if (case["job_id"] != job or case["n"] != n or case["protocol"] != protocol
                or case["dealer_fault"] != "css-corrections" or case["campaign"] != "css-max"
                or case["weights"] != inputs["weights"] or case["threshold"] != inputs["threshold"]
                or case["faulty_dealers"] != maximum_coalition(inputs)):
            raise ValueError(f"{job}: invalid frozen configuration")
        outputs = coin_outputs(work, n)
        if len(outputs) != n or json.loads((work / "control.json").read_bytes())["error"] is not None:
            raise ValueError(f"{job}: incomplete run")
        result = analyze_run(work, case)
        result["max_node_elapsed_to_output_ms"] = max(e["elapsed_us"] for e in outputs) / 1000
        dest = work / "derived"
        export(work, dest, case, result)
        for name in ("recovery.csv", "measurement.csv"):
            if rows(dest / name) != rows(folder / name):
                raise ValueError(f"{job}: {name} differs from raw events")
        obs, = rows(dest / "recovery.csv")
        return (float(obs["mean_honest_sent_bytes"]) / 2**20,
                float(obs["max_honest_freeze_to_required_ms"]) / 1000)


def main():
    folder = RESULTS / "faulty"
    checks = json.loads((folder / "checksums.json").read_bytes())
    expected = rows(folder / "path-summary.csv")
    sizes = (32, 48, 64, 80)
    if [int(row["n"]) for row in expected] != list(sizes):
        raise ValueError("wrong size matrix")
    for n, row in zip(sizes, expected):
        pvr, pt = verify_run(n, "whcc", checks.pop(f"aptos-n{n}--whcc-r1"))
        rbc, rt = verify_run(n, "warmup", checks.pop(f"aptos-n{n}--warmup-r1"))
        values = dict(pvr_sampling_mib=pvr, rbc_full_mib=rbc,
                      pvr_vs_rbc_traffic_pct=100*(pvr/rbc-1), pvr_sampling_s=pt,
                      rbc_full_s=rt, pvr_vs_rbc_latency_pct=100*(pt/rt-1))
        if any(not math.isclose(value, float(row[key]), rel_tol=1e-12, abs_tol=1e-12)
               for key, value in values.items()):
            raise ValueError(f"{n}: path summary differs")
    if checks:
        raise ValueError("unexpected archives")
    print("Verified 8 faulty-dealer archives and all 4 recovery comparisons")


if __name__ == "__main__":
    main()

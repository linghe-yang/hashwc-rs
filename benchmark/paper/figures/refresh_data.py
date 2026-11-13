"""Refresh all six WAN panels from the archived measurements."""
import argparse
import csv
import hashlib
import json
import re
import tarfile
from collections import defaultdict
from pathlib import Path
from statistics import mean

HERE = Path(__file__).resolve().parent
RESULTS = HERE.parent / "results"
SERIES = {
    ("sui", "hashrand"): "suihr",
    ("sui", "whcc"): "suiwhcc",
    ("aptos", "warmup"): "aptoswarm",
    ("aptos", "whcc"): "aptoswhcc",
}

def freeze_at_last_output(row, digest):
    archive = RESULTS / "logs" / row["job_id"] / "cloud-logs.tar.gz"
    with archive.open("rb") as source:
        assert hashlib.file_digest(source, "sha256").hexdigest() == digest
    elapsed = {}
    with tarfile.open(archive, "r|gz") as source:
        for item in source:
            match = re.fullmatch(r"party-(\d+)\.jsonl", item.name)
            if not match:
                continue
            party = int(match[1])
            times = {}
            for line in source.extractfile(item):
                event = json.loads(line)
                kind = event.get("event", {}).get("kind")
                if kind in ("frozen", "coin"):
                    assert event["party"] == party and kind not in times
                    times[kind] = event["elapsed_us"]
            assert party not in elapsed and times["coin"] >= times["frozen"]
            elapsed[party] = times
    assert set(elapsed) == set(range(int(row["n"])))
    last = max(sorted(elapsed), key=lambda p: elapsed[p]["coin"])
    assert abs(elapsed[last]["coin"] / 1000 - float(row["latency_ms"])) < 1e-6
    return elapsed[last]["frozen"] / 1e6

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=HERE / "coin-comparison.tex")
    out = parser.parse_args().out
    with (RESULTS / "measurements.csv").open() as source:
        rows = list(csv.DictReader(source))
    sha = {r["job"]: r["archive_sha256"] for r in json.loads((RESULTS / "verified.json").read_text())["logs"]}
    groups = defaultdict(dict)
    for row in rows:
        size = int(row["n"])
        status = row["status"]
        if status != "success":
            assert row["protocol"] == "hashrand" and (
                (size == 48 and status == "online_timeout") or
                (size == 64 and status == "not_run_after_two_timeouts"))
            continue
        fields = dict(sent=int(row["sent_bytes"]) / (size * 2**20), lat=float(row["latency_ms"]) / 1000)
        if row["family"] == "aptos":
            assert int(row["path_bytes"]) + int(row["shared_bytes"]) == int(row["sent_bytes"])
            fields.update(shared=int(row["shared_bytes"]) / (size * 2**20),
                          pre=freeze_at_last_output(row, sha[row["job_id"]]))
        runs = groups[row["family"], row["protocol"], size]
        assert row["repeat"] not in runs
        runs[row["repeat"]] = fields
    tables = []
    for (family, protocol), macro in SERIES.items():
        fields = ["sent", "lat", "shared", "pre"] if family == "aptos" else ["sent", "lat"]
        lines = ["n " + " ".join(f"{k} {k}err" for k in fields)]
        for n in ((16, 32) if protocol == "hashrand" else (16, 32, 48, 64)):
            runs = groups[family, protocol, n]
            assert set(runs) == {"1", "2"}
            cells = [str(n)]
            for k in fields:
                pair = [run[k] for run in runs.values()]
                cells += [f"{mean(pair):.8f}", f"{(max(pair)-min(pair))/2:.8f}"]
            lines.append(" ".join(cells))
        tables.append("\\pgfplotstableread{\n" + "\n".join(lines) + "\n}\\" + macro)
    figure = HERE / "coin-comparison.tex"
    original = figure.read_text(encoding="utf-8")
    prefix, rest = original.split("% BEGIN MEASUREMENTS\n")
    _, suffix = rest.split("% END MEASUREMENTS")
    with (RESULTS / "faulty/path-summary.csv").open(newline="") as stream:
        faulty = list(csv.DictReader(stream))
    if [int(r["n"]) for r in faulty] != [32, 48, 64, 80]:
        raise ValueError("incomplete faulty-dealer measurements")
    lines = ["n pvrMiB rbcMiB pvrSec rbcSec"]
    for r in faulty:
        lines.append(f"{r['n']} {float(r['pvr_sampling_mib']):.8f} "
                     f"{float(r['rbc_full_mib']):.8f} {float(r['pvr_sampling_s']):.6f} "
                     f"{float(r['rbc_full_s']):.6f}")
    marker = "}\\faultypaths"
    old_faulty, tail = suffix.split(marker)
    lead, _ = old_faulty.split("\\pgfplotstableread{\n")
    suffix = lead + "\\pgfplotstableread{\n" + "\n".join(lines) + "\n" + marker + tail
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(prefix+"% BEGIN MEASUREMENTS\n"+"\n".join(tables)+"\n% END MEASUREMENTS"+suffix,encoding="utf-8")

if __name__ == "__main__":
    main()


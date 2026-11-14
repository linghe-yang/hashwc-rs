"""Verify both faulty-dealer repetitions and reconstruct the plotted means and ranges."""
import argparse
import csv
import hashlib
import json
import math
import shutil
import tarfile
import tempfile
from pathlib import Path
from statistics import mean

from verify_results import RESULTS, analyze_run
from local_rejection import maximum_coalition
from measurements import coin_outputs, export


def rows(path):
    with path.open(newline="") as source:
        return list(csv.DictReader(source))


def verify_run(folder, n, protocol, checksum):
    job = f"aptos-n{n}--{protocol}-r1"
    archive = folder / "cloud-logs.tar.gz"
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != checksum:
            raise ValueError(f"{folder.name}: checksum mismatch")
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
        measurement, = rows(dest / "measurement.csv")
        return dict(honest=int(obs["honest"]), mib=float(obs["mean_honest_sent_bytes"]) / 2**20,
                    s=float(obs["max_honest_freeze_to_required_ms"]) / 1000,
                    reject_mib=int(measurement["honest_reject_remote_bytes"]) / int(obs["honest"]) / 2**20)


def build_summary(folder):
    checks = json.loads((folder / "checksums.json").read_bytes())
    results = []
    runs = []
    for n in (32, 48, 64, 80):
        row = dict(n=n, runs_per_protocol=2)
        for protocol, prefix in (("whcc", "pvr_sampling"), ("warmup", "rbc_full")):
            samples = []
            pair_digests = set()
            for repeat in (1, 2):
                name = f"aptos-n{n}--{protocol}-r{repeat}"
                checksum = checks.pop(name)
                pair_digests.add(checksum)
                sample = verify_run(folder / name, n, protocol, checksum)
                samples.append(sample)
                runs.append(dict(n=n, protocol=protocol, round=repeat, honest=sample["honest"],
                                 path_mib_per_honest=sample["mib"], max_honest_recovery_s=sample["s"],
                                 reject_mib_per_honest=sample["reject_mib"],
                                 archive=f"{name}/cloud-logs.tar.gz"))
            if len(pair_digests) != 2:
                raise ValueError(f"{n} {protocol}: duplicate run archive")
            for metric in ("mib", "s"):
                pair = [sample[metric] for sample in samples]
                row[f"{prefix}_{metric}"] = mean(pair)
                row[f"{prefix}_{metric}_half_range"] = (max(pair) - min(pair)) / 2
            if protocol == "whcc":
                row["reject_mib_per_honest"] = mean(sample["reject_mib"] for sample in samples)
        row["pvr_vs_rbc_traffic_pct"] = 100 * (row["pvr_sampling_mib"] / row["rbc_full_mib"] - 1)
        row["pvr_vs_rbc_latency_pct"] = 100 * (row["pvr_sampling_s"] / row["rbc_full_s"] - 1)
        results.append(row)
    if checks:
        raise ValueError("unexpected archives")
    return runs, results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-summary", action="store_true",
                        help="regenerate runs.csv and path-summary.csv after verifying the raw runs")
    args = parser.parse_args()
    folder = RESULTS / "faulty"
    snapshot = folder / "path-summary.csv"
    runs, results = build_summary(folder)
    run_index = folder / "runs.csv"
    if args.write_summary:
        for path, records in ((run_index, runs), (snapshot, results)):
            with path.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(records[0]))
                writer.writeheader()
                writer.writerows(records)
    if rows(run_index) != [{key: str(value) for key, value in row.items()} for row in runs]:
        raise ValueError("runs.csv differs from the archived runs")
    expected = rows(snapshot)
    if len(expected) != len(results):
        raise ValueError("wrong size matrix")
    for row, saved in zip(results, expected):
        if row.keys() != saved.keys() or any(
                not math.isclose(v, float(saved[k]), rel_tol=1e-12, abs_tol=1e-12)
                for k, v in row.items()):
            raise ValueError(f"{row['n']}: path summary differs")
    print("Verified 16 faulty-dealer archives and the run index and four two-run comparisons")


if __name__ == "__main__":
    main()

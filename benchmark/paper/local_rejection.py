"""Linux loopback, dealer-only AX rejection sweep. Uses paper parameters and the full-service transport audit.

Build with cargo build --release -p coin-benchmark-driver -p csshashcoin --bins.
Run with python3 benchmark/paper/local_rejection.py --out /tmp/whcc-ax-run
Pass --bin-dir if the Cargo target directory is outside the source tree.

For a three-point 64-party pilot, add
--input benchmark/paper/inputs/aptos-n64.json --levels 0 17 35 --repeats 3.
The longest legal prefix of weight-sorted nodes is fixed; its first r members submit
one noncanonical sharing each. All nodes still perform their other duties.
runs.csv reports full-service socket writes (including framing and ACKs) for
all nodes and for the fixed observers outside the coalition. paired.csv gives
WHCC minus warm-up within each repeat. Root timing is elapsed time in the
final local recovery step or in a successful remote certificate check.
Remote certificate payload excludes framing, ACKs and self-delivery.
Module timers cover producing the authenticated evidence after fault detection
and successfully verifying a decoded remote proof. They exclude transport,
serialization, and waiting. Values are sums of elapsed nanoseconds.
Use --select-fixture to compare ax-root and css-corrections at the maximum
legal coalition size. The CSS fixture flips one bit of each generated OR
correction before commitment in both encodings. All other roles stay active.
selection.json ranks these two fixtures by the median honest-sender remote
rejection payload across repeats; a tie selects ax-root. Recipients include
all other parties. Path metrics exclude shared RA, Gather and BinAA. Recovery
latency is measured from local Freeze until all positive outcomes are ready.
"""
import argparse
import asyncio
import csv
import json
import os
import random
import statistics
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "benchmark/clean_comparison"))
from common import digest, parameters, policy_hash, save, validate_input
from runner import run_case


def path_measurements(events, party_result, protocol):
    frozen = next(e for e in events if e.get("event", {}).get("kind") == "frozen")
    outcome = "terminal" if protocol == "whcc" else "reconstructed"
    coefficients = frozen["event"]
    nums = ([v["numerator"] for v in coefficients["coefficients"]]
            if protocol == "whcc" else coefficients["numerators"])
    required = {i for i, value in enumerate(nums) if int(str(value), 0) > 0}
    if not required:
        raise ValueError("empty positive-coefficient set")
    ends = [e["elapsed_us"] for e in events if e.get("event", {}).get("kind") == outcome
            and e["event"]["dealer"] in required]
    if len(ends) != len(required):
        raise ValueError("missing required dealer outcome")
    path = ({"wrbc", "wavid", "whcc/private", "whcc/recovery"} if protocol == "whcc"
            else {"wrbc", "csshashcoin/private", "csshashcoin/recovery"})
    services = party_result["resources_at_exit"]["network"]
    if not set(services) <= path | {"wra", "wgather", "wbinaa"}:
        raise ValueError("unclassified transport service")
    return (sum(v["sent_bytes"] for k, v in services.items() if k in path),
            max(0, max(ends) - frozen["elapsed_us"]) / 1000)


def record_certificates(counters, n, bad, sender, honest, stats, lengths):
    fields = {(d, key): v for d, key, v in counters}
    for d in range(n):
        generated = [k for k in ("root", "module") if fields.get((d, k+"_generated"))]
        received = [k for k in ("root", "module") if fields.get((d, k+"_received"))]
        kinds = generated + received
        if len(kinds) != int(d in bad):
            raise ValueError(f"unexpected rejection evidence at party {sender}, dealer {d}")
        if generated:
            stats[generated[0] + "_generated"] += 1
        if received:
            stats[received[0] + "_verified"] += 1
        if fields.get((d, "terminal_broadcasts"), 0) != fields.get((d, "selected"), 0):
            raise ValueError("assigned terminal was not broadcast exactly once")
        if not fields.get((d, "terminal_broadcasts")):
            continue
        size = fields[d, "certificate_bytes_before_fanout"]
        lengths[d in bad].add(size)
        if d in bad:
            kind = kinds[0]
            stats["reject_payload_bytes_remote"] += size * (n - 1)
            if sender in honest:
                stats[kind + "_honest_broadcasts"] += 1
                stats[kind + "_honest_remote_bytes"] += size * (n - 1)
    for _, key, value in counters:
        if key in ("module_generate_ns", "module_verify_ns",
                   "local_root_certificates", "local_root_final_step_ns", "root_checks", "root_check_ns"):
            stats[key] += value


def summarize_run(work, case, result, observers):
    n = case["n"]
    bad = set(case["faulty_dealers"])
    expected_kind = "terminal" if case["protocol"] == "whcc" else "reconstructed"
    all_stats = Counter()
    lengths = {True: set(), False: set()}
    latencies = {}
    paths = {}
    for i in range(n):
        events = [json.loads(line) for line in (work / f"party-{i}.jsonl").read_text().splitlines()]
        terminal = [e["event"] for e in events if e.get("event", {}).get("kind") == expected_kind]
        if (len(terminal) != n or {t["dealer"] for t in terminal} != set(range(n))
                or {t["dealer"] for t in terminal if t["rejected"]} != bad):
            raise ValueError(f"outcome mismatch at party {i} in {work}")
        latencies[i] = next(e["elapsed_us"] for e in events if e.get("event", {}).get("kind") == "coin") / 1000
        paths[i] = path_measurements(events, result["parties"][str(i)], case["protocol"])
        if case["protocol"] == "whcc":
            counters = next(e["counters"] for e in events if e["kind"] == "bulk_audit")
            record_certificates(counters, n, bad, i, observers, all_stats, lengths)
    if case["protocol"] == "whcc" and bad:
        if not lengths[True] or all_stats["root_generated"] + all_stats["module_generated"] < len(bad):
            raise ValueError("missing locally generated rejection certificates")
        if case["dealer_fault"] == "ax-root" and all_stats["module_generated"]:
            raise ValueError("AX root fixture produced an unexpected module certificate")
    parties = result["parties"]
    return dict(mean_all_path_bytes=statistics.mean(v[0] for v in paths.values()),
                mean_observer_path_bytes=statistics.mean(paths[i][0] for i in observers),
                last_observer_required_ms=max(paths[i][1] for i in observers),
                honest_reject_remote_bytes=sum(all_stats[k + "_honest_remote_bytes"] for k in ("module","root")),
                **{k + suffix: all_stats[k + suffix] for k in ("module","root")
                   for suffix in ("_generated","_verified","_honest_broadcasts","_honest_remote_bytes")},
                mean_all_bytes=result["mean_party_sent_bytes"], last_all_ms=max(latencies.values()),
                mean_observer_bytes=statistics.mean(parties[str(i)]["sent_bytes"] for i in observers),
                last_observer_ms=max(latencies[i] for i in observers),
                reject_cert_sizes="|".join(map(str, sorted(lengths[True]))),
                success_cert_sizes="|".join(map(str, sorted(lengths[False]))),
                **{key: all_stats.get(key, None if all_stats[count] else 0)
                   for key, count in (("module_generate_ns", "module_generated"),
                                      ("module_verify_ns", "module_verified"))},
                **{k: all_stats[k] for k in ("reject_payload_bytes_remote","local_root_certificates",
                   "local_root_final_step_ns","root_checks","root_check_ns")})


def maximum_coalition(source):
    weights, threshold = validate_input(source)
    original = list(map(int, source["original_weights"]))
    n = len(weights)
    if len(original) != n or min(original) <= 0:
        raise ValueError("invalid original weights")
    ranked = sorted(range(n), key=lambda i: (original[i], i))
    coalition = []
    for i in ranked:
        proposed = coalition + [i]
        if 3 * sum(original[j] for j in proposed) >= sum(original):
            break
        coalition = proposed
    if sum(weights[i] for i in coalition) >= threshold:
        raise ValueError("coalition fails the reduced access rule")
    return coalition


async def sweep(args):
    source = json.loads(args.input.read_text())
    weights, threshold = validate_input(source)
    original = list(map(int, source["original_weights"]))
    n = len(weights)
    coalition = maximum_coalition(source)
    observers = sorted(set(range(n)) - set(coalition))
    levels = list(range(len(coalition) + 1)) if args.levels is None else sorted(set(args.levels))
    if args.repeats < 1 or not levels or min(levels) < 0 or max(levels) > len(coalition):
        raise ValueError("invalid repeats or out-of-budget fault level")
    fixtures = ("ax-root", "css-corrections") if args.select_fixture else (args.fixture,)
    if args.select_fixture:
        if not coalition or args.levels is not None:
            raise ValueError("selection requires a nonempty coalition and uses only the maximum level")
        levels = [len(coalition)]
    binaries = dict(driver=args.bin_dir / "coin-benchmark-driver", generator=args.bin_dir / "csshashcoin-node")
    settings = dict(tokio_workers=2, prepare_timeout_s=120, coin_timeout_s=180, drain_timeout_s=120,
                    shutdown_timeout_s=30, quiet_seconds=1, drain_sample_seconds=.2,
                    resource_sample_seconds=.25, minimum_free_memory_mib=512,
                    execution=dict(actor_inbox=4096, compute_jobs=1, transport_receive_capacity=1024,
                                   transport_stall_ms=30000))
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    save(args.out / "design.json", dict(source=source["case_id"], input_sha256=digest(args.input),
         binaries={k: digest(v) for k,v in binaries.items()}, settings=settings, levels=levels,
         repeats=args.repeats, coalition=coalition, fixed_honest_observers=observers, order_seed=args.seed,
         coalition_weight=str(sum(original[i] for i in coalition)), total_weight=str(sum(original)),
         dealer_fixtures=fixtures, selection_metric="median honest_reject_remote_bytes in WHCC",
         fault="dealer record only; recovery and control remain active"))
    os.environ["COIN_BULK_AUDIT"] = "1"
    order = random.Random(args.seed)
    rows = []
    with (args.out / "runs.csv").open("x", newline="") as handle:
        writer = None
        for repeat in range(args.repeats):
            schedule = [(r, fixture) for r in levels for fixture in fixtures]
            order.shuffle(schedule)
            for r, fixture in schedule:
                for proto in (("warmup", "whcc") if (repeat + r) % 2 == 0 else ("whcc", "warmup")):
                    prefix = "" if len(fixtures) == 1 and fixture == "ax-root" else fixture + "-"
                    work = args.out / f"{prefix}r{r:02d}-rep{repeat+1}-{proto}"
                    case = dict(case_id=source["case_id"], family=source["chain"], n=n, weights=weights,
                                threshold=threshold, total_weight=sum(weights), protocol=proto,
                                parameters=parameters(proto), weight_policy_sha256=policy_hash(weights, threshold),
                                faulty_dealers=coalition[:r], dealer_fault=fixture)
                    result = await run_case(work, case, binaries, settings)
                    if result["status"] != "success":
                        raise RuntimeError(f"{work}: {result.get('error')}")
                    row = dict(r=r, fixture=fixture, repeat=repeat+1, protocol=proto, **summarize_run(work, case, result, observers))
                    if writer is None:
                        writer = csv.DictWriter(handle, fieldnames=list(row))
                        writer.writeheader()
                    writer.writerow(row)
                    handle.flush()
                    rows.append(row)
                    print(work.name, round(row["mean_observer_bytes"]/1048576, 3), round(row["last_observer_ms"]), flush=True)
    pairs = {(v["fixture"], v["r"], v["repeat"], v["protocol"]): v for v in rows}
    summary = []
    for fixture, r in ((f, level) for f in fixtures for level in levels):
        row = dict(fixture=fixture, r=r, pairs=args.repeats)
        for field in ("mean_all_bytes", "mean_observer_bytes", "last_observer_ms", "last_all_ms",
                      "mean_all_path_bytes", "mean_observer_path_bytes", "last_observer_required_ms"):
            diffs = [pairs[fixture,r,j,"whcc"][field] - pairs[fixture,r,j,"warmup"][field] for j in range(1,args.repeats+1)]
            row.update({field+"_delta_"+label: fn(diffs)
                        for label,fn in (("median",statistics.median),("min", min),("max",max))})
        summary.append(row)
    with (args.out / "paired.csv").open("x", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary[0]))
        writer.writeheader()
        writer.writerows(summary)
    if args.select_fixture:
        medians = {f: statistics.median(v["honest_reject_remote_bytes"] for v in rows
                                        if v["fixture"] == f and v["protocol"] == "whcc") for f in fixtures}
        save(args.out / "selection.json", dict(winner=max(fixtures, key=medians.get),
             score_bytes=medians, metric="median honest rejection certificate payload sent remotely",
             n=n, faulty=len(coalition), repeats=args.repeats, tie_break="ax-root"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=HERE / "inputs/aptos-n16.json")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--bin-dir", type=Path, default=ROOT / "target/release")
    parser.add_argument("--levels", nargs="+", type=int)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261112)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--select-fixture", action="store_true")
    selection.add_argument("--fixture", choices=("ax-root", "css-corrections"), default="ax-root")
    args = parser.parse_args()
    args.bin_dir = args.bin_dir.resolve()
    args.out = args.out.resolve()
    asyncio.run(sweep(args))

"""Prepare, run, or reprocess a complete, fixed-profile three-protocol benchmark."""
import json
from pathlib import Path
import os
import random
import shutil
import subprocess

from common import (ROOT, PROTOCOLS, MODULE, SCHEMA, VIRTUAL_LIMIT, digest, save,
                    policy_hash, validate_input, parameters, static_resource_check,
                    command, make_config, environment, execution_environment)


def smoke_inputs(source_data=None):
    result = []
    for name, w in (("equal4", [3, 3, 3, 3]), ("near4", [3, 4, 4, 4])):
        result.append(dict(case_id=name, n=4, weights=list(map(str, w)), threshold=str((sum(w) + 2) // 3),
                           family=name, group="smoke", provenance="fixed synthetic module-scale input"))
    if source_data:
        path = Path(source_data) / "data/aptos/manifest.json"
        data = json.loads(path.read_text())
        import hashlib
        for seed in range(20261031, 20261287):
            rows = sorted(data["validators"], key=lambda v: hashlib.sha256(json.dumps(
                ["whcc-complete-benchmark-smoke4-v1", seed, v["id"]], separators=(",", ":")).encode()).digest())[:4]
            w = [int(v["weight"]) for v in rows]
            if max(w) < sum(w) // 3:
                result.append(dict(case_id="aptos4", n=4, weights=list(map(str, w)), threshold=str((sum(w) + 2) // 3),
                                   family="aptos4", group="smoke", seed=seed,
                                   party_source_ids=[v["id"] for v in rows], source_sha256=digest(path),
                                   source_manifest=str(path.resolve()), provenance="four real validators; smoke only, outside frozen scalability curves"))
                break
        else:
            raise ValueError("no balanced four-party Aptos smoke sample")
    return result


def manifest_inputs(path):
    path = Path(path).resolve()
    document = json.loads(path.read_text())
    result = []
    for entry in document["cases"]:
        source = (path.parent / entry["input"]).resolve()
        if not source.is_relative_to(path.parent) or digest(source) != entry["sha256"]:
            raise ValueError("dataset provenance mismatch")
        data = json.loads(source.read_text())
        data["family"] = data["chain"] if entry["group"] == "real_source_scalability" else data["case_id"]
        data["source_input_sha256"] = entry["sha256"]
        data["source_input"] = str(source)
        result.append(data)
    return result


def prepare(args, protocol_pairs=None):
    out = args.directory.resolve()
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    artifacts = out / "artifacts"
    artifacts.mkdir()
    release = ROOT / os.environ.get("CARGO_TARGET_DIR", "target") / "release"
    binary_sources = {"driver": release / "coin-benchmark-driver",
                      "generator": release / "csshashcoin-node"}
    binaries = {}
    for name, src in binary_sources.items():
        target = artifacts / src.name
        shutil.copy2(src, target)
        binaries[name] = dict(path=str(target.relative_to(out)), sha256=digest(target))
    inputs = smoke_inputs(args.source_data) if args.smoke else manifest_inputs(args.dataset_plan)
    settings = dict(tokio_workers=args.workers, execution=dict(
        actor_inbox=args.actor_inbox, compute_jobs=args.compute_jobs,
        transport_receive_capacity=args.receive_capacity,
        transport_stall_ms=args.transport_stall_ms))
    execution_environment(settings)
    settings.update(prepare_timeout_s=180, coin_timeout_s=600, drain_timeout_s=120,
                    shutdown_timeout_s=30, quiet_seconds=2.0, drain_sample_seconds=0.2,
                    resource_sample_seconds=0.2, minimum_free_memory_mib=512,
                    profile=False, runs_per_configuration=1)
    env = environment(args.workers)
    env["execution"] = settings["execution"]
    save(out / "environment.json", env)
    jobs = []
    for source in inputs:
        w, T = validate_input(source)
        frozen = out / "inputs" / (source["case_id"] + ".json")
        save(frozen, source)
        planning = out / "planning" / source["case_id"]
        make_config(artifacts / binary_sources["generator"].name, planning / "config", w, T, 18000)
        group = []
        for protocol in PROTOCOLS if protocol_pairs is None else protocol_pairs[source["family"]]:
            case = dict(case_id=source["case_id"], family=source.get("family", source["case_id"]),
                        n=len(w), weights=list(map(str, w)), threshold=str(T), total_weight=str(sum(w)),
                        protocol=protocol, parameters=parameters(protocol), weight_policy_sha256=policy_hash(w, T),
                        input=str(frozen.relative_to(out)), input_sha256=digest(frozen),
                        job_id=source["case_id"] + "--" + protocol, group=source.get("group"),
                        preflight_status="ready")
            parameter_file = planning / (protocol + ".json")
            save(parameter_file, case["parameters"])
            failure = static_resource_check(protocol, w, T)
            if failure:
                case.update(preflight_status="resource_limited", resource_limit=failure)
            else:
                try:
                    proc = command([artifacts / binary_sources["driver"].name, "--protocol", MODULE[protocol],
                                    "--config", planning / "config/node-0.json", "--parameters", parameter_file,
                                    "--describe"], timeout=settings["prepare_timeout_s"])
                    case["description"] = json.loads(proc.stdout)
                    (planning / (protocol + ".describe.stderr.log")).write_text(proc.stderr)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
                    # Unclassified failures are never silently labeled resource limitations.
                    case.update(preflight_status="preflight_failed", error=str(exc),
                                stderr=getattr(exc, "stderr", None))
            group.append(case)
            save(planning / (protocol + ".preflight.json"), case)
        descriptions = {c["protocol"]: c.get("description") for c in group}
        if descriptions.get("whcc") and descriptions.get("warmup"):
            for key in ("gates", "wires", "css_backend", "correction_blocks", "circuit_mode"):
                if descriptions["whcc"][key] != descriptions["warmup"][key]:
                    raise ValueError(f"shared CSS mismatch: {source['case_id']}: {key}")
        jobs.extend(group)
    # Fixed order randomization, before performance observations; larger n follow smaller n.
    rng = random.Random(20261031)
    ordered = []
    for n in sorted({c["n"] for c in jobs}):
        group = [c for c in jobs if c["n"] == n]
        rng.shuffle(group)
        ordered += group
    document = dict(schema=SCHEMA, scope="all-honest single coin; no batching or amortization", settings=settings,
                    inputs_mode="smoke" if args.smoke else "frozen_real_weight_manifest", binaries=binaries,
                    environment_sha256=digest(out / "environment.json"), configurations=ordered,
                    controller_hashes={name: digest(Path(__file__).parent / name) for name in ("common.py", "runner.py", "analyze.py", "run.py")},
                    dataset_manifest_sha256=digest(args.dataset_plan) if args.dataset_plan else None,
                    virtual_share_limit=VIRTUAL_LIMIT)
    save(out / "plan.json", document)
    save(out / "plan_digest.json", dict(sha256=digest(out / "plan.json")))
    print(json.dumps(dict(prepared=str(out), jobs=len(jobs), ready=sum(c["preflight_status"] == "ready" for c in jobs),
                          resource_limited=sum(c["preflight_status"] == "resource_limited" for c in jobs))), flush=True)


def load_plan(directory, check_controller=False):
    directory = Path(directory).resolve()
    require_hash = json.loads((directory / "plan_digest.json").read_text())["sha256"]
    if digest(directory / "plan.json") != require_hash:
        raise ValueError("frozen plan changed")
    plan = json.loads((directory / "plan.json").read_text())
    if digest(directory / "environment.json") != plan["environment_sha256"]:
        raise ValueError("environment record changed")
    for info in plan["binaries"].values():
        if digest(directory / info["path"]) != info["sha256"]:
            raise ValueError("frozen binary changed")
    for case in plan["configurations"]:
        if digest(directory / case["input"]) != case["input_sha256"]:
            raise ValueError("frozen input changed")
    if check_controller:
        for name, expected in plan["controller_hashes"].items():
            if digest(Path(__file__).parent / name) != expected:
                raise ValueError("controller changed; use a new plan, retain old attempts")
    return plan

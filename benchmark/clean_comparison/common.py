"""Shared exact inputs and fixed experiment parameters for three coin protocols."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
PROTOCOLS = ("whcc", "warmup", "hashrand")
MODULE = {"whcc": "whcc", "warmup": "csshashcoin", "hashrand": "hashrand"}
SCHEMA = "complete-coin-benchmark-v1"
VIRTUAL_LIMIT = 8192


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)


def policy_hash(weights, threshold):
    raw = json.dumps([list(map(str, weights)), str(threshold)], separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def validate_input(case):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", case["case_id"]):
        raise ValueError("unsafe case identifier")
    w = list(map(int, case["weights"]))
    T = int(case["threshold"])
    if len(w) != case["n"] or not 2 <= len(w) <= 91 or min(w) <= 0 or not 0 < T <= (sum(w) + 2) // 3:
        raise ValueError("invalid exact weighted policy")
    if case.get("input_policy_sha256", policy_hash(w, T)) != policy_hash(w, T):
        raise ValueError("input policy digest mismatch")
    return w, T


def parameters(protocol):
    p = dict(epoch=0, rounding_bits=40, output_bits=1, compact_binaa=True,
             reuse_local_dealer=True)
    if protocol == "whcc":
        p.update(coverage_bits=40, bulk_block_bytes="min-communication-v1",
                 recovery_mode="sampled", sampling_mode="tight-v1",
                 list_broadcast="fixed-chunks-v1", circuit_mode="clean-v1",
                 short_root_rbc=True, reuse_verified_material=True)
    elif protocol == "warmup":
        p.update(rbc_block_bytes="min-communication-v1", circuit_mode="clean-v1")
    elif protocol == "hashrand":
        p.update(batch_size=1, batches=1, sampling_bits=40, max_virtual_shares=VIRTUAL_LIMIT)
    else:
        raise ValueError("unknown protocol")
    return p


def static_resource_check(protocol, weights, threshold):
    if protocol == "hashrand" and sum(weights) > VIRTUAL_LIMIT:
        return dict(status="resource_limited", reason="max_virtual_shares",
                    required_virtual_shares=str(sum(weights)), configured_limit=VIRTUAL_LIMIT,
                    threshold=str(threshold), scope="configured implementation limit, not an impossibility theorem")
    return None


def command(args, timeout=120):
    return subprocess.run(list(map(str, args)), cwd=ROOT, capture_output=True, text=True,
                          timeout=timeout, check=True)


def make_config(generator, directory, weights, threshold, base):
    command([generator, "generate-local", "--directory", directory, "--weights",
             ",".join(map(str, weights)), "--threshold", threshold, "--base-port", base])
    for path in Path(directory).glob("*.json"):
        path.chmod(0o600)


def reserve_ports(n):
    for _ in range(100):
        base = 12000 + secrets.randbelow(20000)
        held = []
        try:
            for port in range(base, base + 7 * n):
                sock = socket.socket()
                held.append(sock)
                sock.bind(("127.0.0.1", port))
            return base, held
        except OSError:
            for sock in held:
                sock.close()
    raise RuntimeError("could not reserve protocol ports")


def source_hashes():
    result = {}
    for name in ("consensus", "vendor", "crypto", "config", "network", "recovery", "types", "benchmark/coin_driver"):
        for path in (ROOT / name).rglob("*.rs"):
            result[str(path.relative_to(ROOT))] = digest(path)
    return result


EXECUTION_ENV = {
    "actor_inbox": "HASHWC_ACTOR_INBOX",
    "compute_jobs": "HASHWC_COMPUTE_JOBS",
    "transport_receive_capacity": "HASHWC_RECEIVE_CAPACITY",
    "transport_stall_ms": "HASHWC_TRANSPORT_STALL_MS",
}


def execution_environment(settings):
    # Explicitly override inherited tuning. Old plans retain historical defaults;
    # old measured binaries ignore the new variables.
    legacy = dict(actor_inbox=4096, compute_jobs=2,
                  transport_receive_capacity=1024, transport_stall_ms=5000)
    values = settings.get("execution", legacy)
    if set(values) != set(EXECUTION_ENV):
        raise ValueError("incomplete execution profile")
    limits = dict(actor_inbox=65536, compute_jobs=64,
                  transport_receive_capacity=65536, transport_stall_ms=3600000)
    if any(type(v) is not int or not 0 < v <= limits[k] for k, v in values.items()):
        raise ValueError("invalid execution setting")
    return {name: str(values[key]) for key, name in EXECUTION_ENV.items()}


def environment(workers):
    def git(*args):
        if not (ROOT / ".git").exists() or not shutil.which("git"):
            return None
        return command(["git", *args]).stdout.strip()

    return dict(utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                display_timezone="Asia/Shanghai", platform=platform.platform(), python=platform.python_version(),
                cpu=next(line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                         if line.startswith("model name")),
                affinity=sorted(os.sched_getaffinity(0)), meminfo=Path("/proc/meminfo").read_text(),
                git_head=git("rev-parse", "HEAD"),
                git_status=git("status", "--short"),
                rustc=command(["rustc", "--version"]).stdout.strip(),
                cargo_lock_sha256=digest(ROOT / "Cargo.lock"), source_hashes=source_hashes(),
                tokio_workers=workers, profiling=False, network="Linux loopback TCP",
                measurement="all physical parties output; all-honest application obligations plus ACK and quiet observation")

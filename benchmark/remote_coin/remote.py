"""WSL controller for the release coin driver. Workers require SSH and Ubuntu userland."""
import argparse
import asyncio
import ipaddress
import json
from pathlib import Path
import re
import shlex
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "clean_comparison"))
from common import MODULE, ROOT, digest, execution_environment, make_config, save, validate_input
from analyze import analyze_run, network_signature


class SSHTransportError(RuntimeError):
    """The SSH connection failed during a remote operation."""


async def command(*args, timeout=180):
    p = await asyncio.create_subprocess_exec(*map(str, args), stdout=asyncio.subprocess.PIPE,
                                             stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(p.communicate(), timeout)
    except TimeoutError as exc:
        if args[0] in ("ssh","scp"):
            raise SSHTransportError(f"{args[0]} timed out") from exc
        raise
    finally:
        if p.returncode is None:
            p.kill()
            await p.wait()
    if p.returncode:
        detail = err.decode(errors="replace").strip()
        connection = re.search(r"connection (?:reset|closed|refused|timed out)|broken pipe|banner exchange|"
                               r"no route to host|network is unreachable|lost connection|connection to .* closed", detail, re.I)
        identity = re.search(r"permission denied|host key verification failed|remote host identification has changed|"
                             r"bad permissions|no such identity|could not resolve hostname",detail,re.I)
        if args[0] in ("ssh","scp") and not identity and (connection or (p.returncode==255 and not detail)):
            raise SSHTransportError(f"{args[0]} transport failed: {detail}")
        raise RuntimeError(f"{args[0]} failed ({p.returncode}): {detail[:500]}")
    return out.decode().strip()


async def parallel(tasks):
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, BaseException):
            raise result
    return results


async def ssh_failures(hosts, seconds=45):
    async def check(slot, host):
        try:
            async with asyncio.timeout(seconds):
                while True:
                    try:
                        await host.shell("true")
                        return None
                    except (RuntimeError, TimeoutError):
                        await asyncio.sleep(3)
        except TimeoutError:
            return slot
    results = await asyncio.gather(*(check(i,h) for i,h in enumerate(hosts)))
    return [i for i in results if i is not None]


async def before_upload(hosts):
    failed = await ssh_failures(hosts)
    if failed:
        raise RuntimeError(f"SSH pre-upload check failed for slots {failed}")


ENA_COUNTERS = ("bw_in_allowance_exceeded", "bw_out_allowance_exceeded", "pps_allowance_exceeded")
ENA_PROBE = """set -e
for dev in /sys/class/net/*; do
    driver=$(readlink "$dev/device/driver") || continue
    [ "${driver##*/}" = ena ] || continue
    printf 'interface %s\n' "${dev##*/}"
    ethtool -S "${dev##*/}" || exit 1
done"""


async def ena_snapshot(host):
    try:
        async with asyncio.timeout(15):
            raw = await host.shell(ENA_PROBE)
        interfaces = {}
        for line in raw.splitlines():
            if line.startswith("interface "):
                current = {}
                interfaces[line.split(maxsplit=1)[1]] = current
            else:
                key, sep, value = line.strip().partition(":")
                if sep and key in ENA_COUNTERS:
                    current[key] = int(value)
        if not interfaces:
            return {"error": "no ENA interface found"}
        return {"interfaces": interfaces}
    except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
        return {"error": repr(exc)}


class Host:
    def __init__(self, ip, args):
        self.ip = str(ipaddress.IPv4Address(ip))
        if not re.fullmatch(r"[a-z_][a-z0-9_-]*", args.user):
            raise ValueError("invalid SSH username")
        self.target = f"{args.user}@{self.ip}"
        opts = ["-i", str(args.key.expanduser()), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=12",
                "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3"]
        self.ssh = ["ssh", *opts, self.target]
        self.scp = ["scp", "-q", *opts]

    async def shell(self, script):
        return await command(*self.ssh, script)

    async def put(self, path, remote):
        await command(*self.scp, path, self.target + ":" + remote)

    async def get(self, remote, path):
        await command(*self.scp, self.target + ":" + remote, path)


async def deploy(host, driver, sha):
    folder = ".hashwc/bin"
    dest = f"{folder}/{sha}"
    tmp = dest + "." + uuid.uuid4().hex
    if await host.shell(f"mkdir -p -m 700 {folder} && if test -x {dest}; then sha256sum {dest}; fi") == f"{sha}  {dest}":
        return
    await host.put(driver, tmp)
    await host.shell(f"echo '{sha}  {tmp}' | sha256sum -c - >/dev/null && chmod 700 {tmp} && {tmp} --help >/dev/null && mv {tmp} {dest}")


def formal_record(record):
    """Keep evidence used by the analyzer and protocol/transport error diagnostics."""
    event = record.get("event", {})
    if event.get("kind") in ("shared", "gathered", "public_delivered", "token_released",
                             "seed_release", "seed_opened", "committee"):
        return None
    if event.get("kind") == "terminal_checked" and event.get("accepted") is True:
        return None
    if event.get("kind") == "reconstructed":
        event.pop("value", None)
    resources = record.get("resources")
    if resources:
        for counters in resources["network"].values():
            for field in list(counters):
                if field.startswith(("io_", "ack_read_", "ack_write_", "receive_")) and field not in (
                    "io_disconnects", "receive_backpressure_waits", "receive_backpressure_ns",
                ):
                    del counters[field]
            counters.pop("ack_sent_bytes", None)
            counters.pop("ack_received_bytes", None)
    return record


LOG_ERROR = re.compile(r'\b(?:ERROR|FATAL|PANIC)\b|^(?i:error|fatal)\s*:|\bpanicked at\b|out of memory|oom-kill')


def worker_command(remote, invoke, flag, nofile=None):
    # Mirror stderr to the SSH channel while retaining the original worker file.
    if nofile is not None:
        if type(nofile) is not int or nofile <= 0:
            raise ValueError("invalid worker nofile soft limit")
        # exec preserves the pipeline child's PID across env and driver exec.
        invoke = f"(ulimit -Sn {nofile} && echo \"$BASHPID\" >worker.pid && exec {invoke}{flag})"
        flag = ""
    return f"cd {remote} && {invoke}{flag} 2> >(tee stderr.log >&2) | tee stdout.jsonl"


async def worker_nofile(host, folder, sha, requested):
    probe = r"""import json, os, pathlib, re, sys
folder, sha = sys.argv[1:]
pid = int((pathlib.Path(folder)/'worker.pid').read_text())
p = pathlib.Path('/proc')/str(pid)
if not os.path.samefile(p/'exe', pathlib.Path.home()/'.hashwc/bin'/sha):
    raise RuntimeError('PID does not match the benchmark executable')
m = re.search(r'^Max open files\s+(\d+)\s+(\d+|unlimited)\s+', (p/'limits').read_text(), re.M)
print(json.dumps(dict(pid=pid, soft=int(m[1]), hard=m[2])))"""
    result = json.loads(await host.shell(shlex.join(["python3","-c",probe,folder,sha])))
    if result["soft"] != requested:
        raise RuntimeError(f"worker {host.ip} RLIMIT_NOFILE {result['soft']}, expected {requested}")
    return result


async def experiment(args, hosts, case, settings, sha, directory):
    n = case["n"]
    mode = settings.get("log_mode", "formal")
    if mode not in ("formal", "debug"):
        raise ValueError(f"unknown log mode: {mode}")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    tag = uuid.uuid4().hex
    remote = f".hashwc/runs/{tag}"
    save(directory / "deployment.json", dict(remote=remote, driver_sha256=sha, peers=[h.ip for h in hosts]))
    save(directory / "case.json", case)
    save(directory / "parameters.json", case["parameters"])
    save(directory / "execution.json", settings["execution"])
    w, threshold = validate_input(case)
    faulty = set(case.get("faulty_dealers", []))
    if faulty or case.get("dealer_fault"):
        if (case.get("dealer_fault") != "css-corrections" or case["protocol"] not in ("warmup", "whcc")
                or not faulty or not faulty <= set(range(n)) or sum(w[i] for i in faulty) >= threshold):
            raise ValueError("invalid CSS benchmark committee")
    make_config(args.generator.resolve(), directory / "config", w, threshold, args.port)
    async def prepare(i, h):
        cfg = directory / f"config/node-{i}.json"
        node = json.loads(cfg.read_text())
        node["net_map"] = {str(j): f"{peer.ip}:{args.port+j}" for j, peer in enumerate(hosts)}
        cfg.write_text(json.dumps(node))
        await h.shell(f"test -x .hashwc/bin/{sha} && mkdir -p -m 700 .hashwc/runs && mkdir -m 700 {remote}")
        await h.put(cfg, f"{remote}/node.json")
        await h.put(directory / "parameters.json", f"{remote}/parameters.json")
    await before_upload(hosts)
    await parallel(prepare(i, h) for i, h in enumerate(hosts))
    env = execution_environment(settings)
    env.update(TOKIO_WORKER_THREADS=str(settings["tokio_workers"]), COIN_PROFILE="0",
               COIN_LOG_MODE=mode, RUST_LOG="debug" if mode == "debug" else "warn")
    if settings.get("bulk_audit"):
        env["COIN_BULK_AUDIT"] = "1"
    invoke = shlex.join(["env", *(f"{k}={v}" for k,v in env.items()), f"../../bin/{sha}",
                         "--protocol", MODULE[case["protocol"]], "--config", "node.json",
                         "--parameters", "parameters.json"])
    procs, readers, counts = {}, [], [0]*n
    queue = asyncio.Queue()
    active = asyncio.current_task()
    monitoring = True
    log_error = None
    origin = time.monotonic_ns()
    now = lambda: time.monotonic_ns() - origin
    control = dict(error=None, phase="prepare", log_mode=mode, quiet_required_s=settings["quiet_seconds"], quiet_observed_s=0,
                   sampled_peak_aggregate_rss_kib=None, returncodes={})
    async def read(i, proc):
        try:
            with (directory / f"party-{i}.jsonl").open("w") as log:
                while line := await proc.stdout.readline():
                    event = json.loads(line)
                    if event.get("party") != i:
                        raise ValueError("wrong party")
                    observed = now()
                    if mode == "formal" and formal_record(event) is None:
                        continue
                    event.update(observer_ns=observed, sequence=counts[i])
                    counts[i] += 1
                    log.write(json.dumps(event, separators=(",", ":")) + "\n")
                    await queue.put((i,event))
        except Exception as exc:
            await queue.put((i,dict(kind="failure",reason=str(exc))))
        finally:
            await queue.put((i,dict(kind="exit")))
    async def watch_stderr(i, proc):
        nonlocal log_error
        # Drain even after the first error so worker shutdown cannot block.
        while line := await proc.stderr.readline():
            message = line.decode(errors="replace").strip()
            if log_error is None and LOG_ERROR.search(message):
                log_error = f"party {i} stderr: {message[:1000]}"
                if monitoring:
                    active.cancel()

    async def launch(i, h):
        flag = " --css-benchmark-dealer" if i in faulty else ""
        script = worker_command(remote, invoke, flag, settings.get("worker_nofile_soft"))
        proc = await asyncio.create_subprocess_exec(*h.ssh, "bash -o pipefail -c " + shlex.quote(script),
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE, limit=4*1024**2)
        procs[i] = proc
        readers.append(asyncio.create_task(read(i,proc)))
        readers.append(asyncio.create_task(watch_stderr(i,proc)))
    async def send(msg):
        for p in procs.values():
            p.stdin.write((msg+"\n").encode())
        await asyncio.gather(*(p.stdin.drain() for p in procs.values()))
    async def collect(kind):
        rows = {}
        while len(rows)<n:
            i,e = await queue.get()
            event_kind = e.get("event",{}).get("kind")
            if e["kind"] in ("exit","failure") or event_kind=="failed":
                raise RuntimeError(f"party {i}: {e}")
            if e["kind"]==kind or (kind=="output" and event_kind in ("coin","beacon")):
                if i in rows:
                    raise RuntimeError(f"duplicate {kind} from {i}")
                rows[i]=e
        return rows
    try:
        async with asyncio.timeout(settings["prepare_timeout_s"]):
            await parallel(launch(i,h) for i,h in enumerate(hosts))
            await collect("ready")
            if "worker_nofile_soft" in settings:
                target = settings["worker_nofile_soft"]
                control["worker_nofile_requested"] = target
                control["worker_nofile_before_start"] = await parallel(
                    worker_nofile(h, remote, sha, target) for h in hosts)
        control["ena_before_start"] = await parallel(ena_snapshot(h) for h in hosts)
        control["start_ns"]=now()
        control["phase"]="send_start"
        async with asyncio.timeout(settings["coin_timeout_s"]):
            await send("start")
            control["phase"]="await_outputs"
            outputs=await collect("output")
            if len({json.dumps(e["event"]["value"]) for e in outputs.values()})!=1:
                raise RuntimeError("outputs disagree")
        control["phase"]="drain"
        previous = None
        async with asyncio.timeout(settings["drain_timeout_s"]):
            while True:
                await send("sample")
                samples=await collect("sample")
                signature,eligible=network_signature(samples, faulty)
                if eligible:
                    if previous!=signature:
                        control["service_start_ns"]=now()
                        control["service_start_sequences"]={str(i):e["sequence"] for i,e in samples.items()}
                    control["quiet_observed_s"]=(now()-control["service_start_ns"])/1e9
                    if control["quiet_observed_s"]>=settings["quiet_seconds"]:
                        break
                previous=signature if eligible else None
                await asyncio.sleep(settings["drain_sample_seconds"])
        control["phase"]="shutdown"
        async with asyncio.timeout(settings["shutdown_timeout_s"]):
            await send("stop")
            await asyncio.gather(*(p.wait() for p in procs.values()))
    except BaseException as exc:
        control["error"]=log_error or repr(exc)
        if log_error:
            raise RuntimeError(log_error) from exc
        raise
    finally:
        monitoring = False
        for p in procs.values():
            p.stdin.close()
        try:
            await asyncio.wait_for(asyncio.gather(*(p.wait() for p in procs.values())), 8)
        except TimeoutError:
            for p in procs.values():
                if p.returncode is None:
                    p.kill()
            await asyncio.gather(*(p.wait() for p in procs.values()))
        await asyncio.gather(*readers)
        if log_error:
            control["error"] = log_error
        control["returncodes"]={str(i):p.returncode for i,p in procs.items()}
        if "ena_before_start" in control:
            control["ena_after_stop"] = await parallel(ena_snapshot(h) for h in hosts)
        save(directory/"control.json",control)
        failed = control["error"] is not None or any(control["returncodes"].values())
        if not getattr(args, "local_log_collection", False):
            await fetch(directory, hosts, remote, stdout=mode == "debug" or failed)
    if log_error:
        raise RuntimeError(log_error)
    try:
        result=analyze_run(directory,case)
    except Exception:
        if mode == "formal" and not failed and not getattr(args, "local_log_collection", False):
            await fetch(directory, hosts, remote)
        raise
    result["max_node_elapsed_to_output_ms"]=max(e["elapsed_us"] for e in outputs.values())/1000
    result["latency_scope"]="latency_all_ms includes controller SSH start and observation delay"
    save(directory/"result.json",result)
    if not getattr(args, "local_log_collection", False):
        await cleanup(hosts,remote)


async def fetch(directory, hosts, remote, stdout=True):
    async def one(i,h,name):
        src=f"{remote}/{name}"
        dst=directory/f"remote-{i}-{name}"
        temp=dst.with_suffix(".partial")
        for attempt in range(1,6):
            try:
                checksum=(await h.shell(f"sha256sum {src}")).split()[0]
                if not re.fullmatch("[a-f0-9]{64}",checksum):
                    raise ValueError("invalid checksum")
                if dst.is_file() and digest(dst)==checksum:
                    return
                await h.get(src,temp)
                if digest(temp)!=checksum:
                    raise ValueError("checksum mismatch")
                temp.replace(dst)
                return
            except (RuntimeError, TimeoutError, OSError, IndexError, ValueError) as exc:
                print(f"fetch slot={i} file={name} attempt={attempt}: {exc}",file=sys.stderr,flush=True)
                if attempt==5:
                    raise RuntimeError(f"could not verify {src} at slot {i}") from exc
                await asyncio.sleep(2**(attempt-1))
    names = ("stdout.jsonl", "stderr.log") if stdout else ("stderr.log",)
    await parallel(one(i,h,name) for i,h in enumerate(hosts) for name in names)


async def cleanup(hosts,remote):
    if not re.fullmatch(r"\.hashwc/runs/[0-9a-f]{32}",remote):
        raise ValueError("unexpected remote path")
    await parallel(h.shell(f"rm -f {remote}/stdout.jsonl {remote}/stderr.log {remote}/node.json {remote}/parameters.json {remote}/worker.pid && rmdir {remote}") for h in hosts)


async def main(args):
    rows=sorted((r for r in json.loads(args.inventory.read_text()) if r["state"]=="running"),key=lambda r:r["slot"])
    if [r["slot"] for r in rows]!=list(range(len(rows))) or not rows or len({r["public_ip"] for r in rows})!=len(rows):
        raise ValueError("need contiguous running slots and distinct public IPs from fleet.py info")
    hosts=[Host(r["public_ip"],args) for r in rows]
    if args.action=="fetch":
        saved=json.loads((args.out/"deployment.json").read_text())
        peers=saved["peers"]
        if peers!=[h.ip for h in hosts[:len(peers)]] or not re.fullmatch(r"\.hashwc/runs/[0-9a-f]{32}",saved["remote"]):
            raise ValueError("inventory differs from recorded deployment")
        await fetch(args.out,hosts[:len(peers)],saved["remote"])
        return
    sha=digest(args.driver)
    if args.action=="deploy":
        await before_upload(hosts)
        await parallel(deploy(h,args.driver,sha) for h in hosts)
        return
    plan=json.loads(args.plan.read_text())
    if args.debug_logs:
        plan["settings"]["log_mode"] = "debug"
    cases=[c for c in plan["configurations"] if c["protocol"]==args.protocol and c["case_id"]==args.case]
    if len(cases)!=1 or cases[0]["preflight_status"]!="ready":
        raise ValueError("case missing, ambiguous or skipped by frozen preflight")
    case=cases[0]
    if len(hosts)<case["n"] or not 1<=args.port<=65536-7*case["n"] or args.repeat<1:
        raise ValueError("invalid host count, port range or repeats")
    for i in range(args.repeat):
        await experiment(args,hosts[:case["n"]],case,plan["settings"],sha,
                         args.out.resolve()/f"repeat-{i+1}")


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=["deploy","run","fetch"])
    parser.add_argument("--inventory",type=Path,required=True)
    parser.add_argument("--key",type=Path,default=Path("~/.ssh/whcc-aws"))
    parser.add_argument("--user",default="ubuntu")
    parser.add_argument("--driver",type=Path,default=ROOT/"target/release/coin-benchmark-driver")
    parser.add_argument("--generator",type=Path,default=ROOT/"target/release/csshashcoin-node")
    parser.add_argument("--port",type=int,default=21000)
    parser.add_argument("--plan",type=Path)
    parser.add_argument("--case")
    parser.add_argument("--protocol",choices=MODULE)
    parser.add_argument("--out",type=Path)
    parser.add_argument("--repeat",type=int,default=1)
    parser.add_argument("--debug-logs", action="store_true", help="retain verbose worker logs")
    args=parser.parse_args()
    if args.action=="run" and not all((args.plan,args.case,args.protocol,args.out)):
        parser.error("run requires --plan --case --protocol --out")
    if args.action=="fetch" and not args.out:
        parser.error("fetch requires --out <repeat directory>")
    asyncio.run(main(args))

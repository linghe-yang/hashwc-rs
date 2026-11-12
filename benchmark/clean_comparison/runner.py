"""Complete-process controller. Every timeout is an external experiment failure."""
import asyncio
import json
import os
from pathlib import Path
import re
import time

from common import ROOT, MODULE, make_config, reserve_ports, save, execution_environment
from analyze import analyze_run, network_signature


async def run_case(directory, case, binaries, settings):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    save(directory / "case.json", case)
    save(directory / "parameters.json", case["parameters"])
    save(directory / "execution.json", settings.get("execution"))
    processes, tasks, traces, errors = {}, [], {}, []
    queue = asyncio.Queue()
    stop_monitor = asyncio.Event()
    control = dict(error=None, returncodes={}, start_ns=None, service_start_sequences={},
                   service_start_ns=None, quiet_required_s=settings["quiet_seconds"],
                   quiet_observed_s=0, sampled_peak_aggregate_rss_kib=0)
    origin = time.perf_counter_ns()
    held = []

    def now():
        return time.perf_counter_ns() - origin

    async def read(party, proc):
        try:
            with (directory / f"party-{party}.jsonl").open("w") as output:
                while raw := await proc.stdout.readline():
                    event = json.loads(raw)
                    if event.get("party") != party:
                        raise ValueError("stdout identity mismatch")
                    event.update(observer_ns=now(), sequence=len(traces[party]))
                    output.write(json.dumps(event, separators=(",", ":")) + "\n")
                    output.flush()
                    traces[party].append(event)
                    await queue.put((party, event))
            await queue.put((party, dict(kind="process_exit", returncode=await proc.wait())))
        except Exception as exc:
            await queue.put((party, dict(kind="reader_failure", reason=str(exc))))

    async def monitor():
        with (directory / "resource_samples.jsonl").open("w") as output:
            while not stop_monitor.is_set():
                values = {}
                for i, p in processes.items():
                    try:
                        status = Path(f"/proc/{p.pid}/status").read_text()
                        match = re.search(r"^VmRSS:\s+(\d+)", status, re.M)
                        if match:
                            values[str(i)] = int(match[1])
                    except (FileNotFoundError, ProcessLookupError):
                        pass
                total = sum(values.values())
                control["sampled_peak_aggregate_rss_kib"] = max(control["sampled_peak_aggregate_rss_kib"], total)
                output.write(json.dumps(dict(observer_ns=now(), rss_kib=values, total_rss_kib=total)) + "\n")
                output.flush()
                available = int(re.search(r"MemAvailable:\s+(\d+)", Path("/proc/meminfo").read_text())[1])
                if available < settings["minimum_free_memory_mib"] * 1024:
                    await queue.put((-1, dict(kind="resource_limit", available_kib=available)))
                    return
                await asyncio.sleep(settings["resource_sample_seconds"])

    async def receive():
        party, event = await queue.get()
        if event["kind"] in ("process_exit", "reader_failure", "resource_limit"):
            raise RuntimeError(f"{party}: {event}")
        if event.get("event", {}).get("kind") == "failed":
            raise RuntimeError(f"protocol Failed: {party}: {event['event']}")
        return party, event

    async def send(command):
        for p in processes.values():
            p.stdin.write(command.encode() + b"\n")
        await asyncio.gather(*(p.stdin.drain() for p in processes.values()))

    try:
        base, held = reserve_ports(case["n"])
        make_config(binaries["generator"], directory / "config", list(map(int, case["weights"])), int(case["threshold"]), base)
        for sock in held:
            sock.close()
        held = []
        origin = time.perf_counter_ns()  # Configuration generation is separately outside process timings.
        for i in range(case["n"]):
            traces[i] = []
            err = (directory / f"party-{i}.stderr.log").open("wb")
            errors.append(err)
            processes[i] = await asyncio.create_subprocess_exec(
                str(binaries["driver"]), "--protocol", MODULE[case["protocol"]],
                "--config", str(directory / f"config/node-{i}.json"),
                "--parameters", str(directory / "parameters.json"),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=err,
                cwd=ROOT, env={**os.environ, "TOKIO_WORKER_THREADS": str(settings["tokio_workers"]),
                               "COIN_PROFILE": "0", "RUST_LOG": "warn",
                               **execution_environment(settings)}, limit=4 * 1024**2)
            tasks.append(asyncio.create_task(read(i, processes[i])))
        monitor_task = asyncio.create_task(monitor())
        async with asyncio.timeout(settings["prepare_timeout_s"]):
            ready = set()
            while len(ready) < case["n"]:
                i, e = await receive()
                if e["kind"] == "ready":
                    if i in ready:
                        raise RuntimeError("duplicate ready")
                    if "execution" in settings and e.get("execution") != settings["execution"]:
                        raise RuntimeError("process execution settings differ from frozen plan")
                    ready.add(i)
                elif e["kind"] != "preparing":
                    raise RuntimeError("unexpected event before START")
        control["start_ns"] = now()
        await send("start")
        outputs = {}
        control["phase"] = "await_outputs"
        async with asyncio.timeout(settings["coin_timeout_s"]):
            while len(outputs) < case["n"]:
                i, e = await receive()
                if e.get("event", {}).get("kind") in ("coin", "beacon"):
                    if i in outputs:
                        raise RuntimeError("duplicate single-coin output")
                    outputs[i] = e["event"]["value"]
        control["phase"] = "drain"
        if any(v != next(iter(outputs.values())) for v in outputs.values()):
            raise RuntimeError("honest outputs disagree")
        previous, since = None, None
        async with asyncio.timeout(settings["drain_timeout_s"]):
            while True:
                await send("sample")
                samples = {}
                while len(samples) < case["n"]:
                    i, e = await receive()
                    if e.get("event", {}).get("kind") in ("coin", "beacon"):
                        raise RuntimeError("duplicate output after completion")
                    if e["kind"] == "sample":
                        if i in samples:
                            raise RuntimeError("duplicate sample")
                        samples[i] = e
                signature, eligible = network_signature(samples)
                current = now()
                if not eligible:
                    since = None
                elif since is None or signature != previous:
                    since = current
                    control["service_start_ns"] = current
                    control["service_start_sequences"] = {str(i): e["sequence"] for i, e in samples.items()}
                previous = signature
                if eligible and (current - since) / 1e9 >= settings["quiet_seconds"]:
                    control["quiet_observed_s"] = (current - since) / 1e9
                    break
                await asyncio.sleep(settings["drain_sample_seconds"])
        await send("stop")
        await asyncio.wait_for(asyncio.gather(*(p.wait() for p in processes.values())), settings["shutdown_timeout_s"])
        await asyncio.gather(*tasks)
        if any(p.returncode != 0 for p in processes.values()):
            raise RuntimeError("nonzero process exit")
    except Exception as exc:
        control["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for sock in held:
            sock.close()
        for p in processes.values():
            if p.returncode is None:
                try:
                    p.terminate()
                except ProcessLookupError:
                    pass
        for p in processes.values():
            if p.returncode is None:
                try:
                    await asyncio.wait_for(p.wait(), 5)
                except asyncio.TimeoutError:
                    p.kill()
                    await p.wait()
        stop_monitor.set()
        if "monitor_task" in locals():
            await monitor_task
        await asyncio.gather(*tasks, return_exceptions=True)
        for err in errors:
            err.close()
        control["returncodes"] = {str(i): p.returncode for i, p in processes.items()}
        control["wall_ns"] = now()
        save(directory / "control.json", control)
    try:
        result = analyze_run(directory, case)
    except Exception as exc:
        result = dict(status="failed", error=f"{type(exc).__name__}: {exc}",
                      case_id=case["case_id"], protocol=case["protocol"], n=case["n"],
                      failure_measurements_are_not_success_metrics=True)
        save(directory / "failure.json", dict(result=result, controller_error=control["error"]))
    save(directory / "result.json", result)
    return result

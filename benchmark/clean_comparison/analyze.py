"""Recompute measurements from raw events, never from a success flag alone."""
import json
from pathlib import Path
from common import SCHEMA


def require(condition, message):
    if not condition:
        raise ValueError(message)


def cpu(resource):
    return resource["user_us"] + resource["system_us"]


def subtract(a, b):
    require(a >= b, "counter moved backwards")
    return a - b


def validate_coin(value, bits):
    require(isinstance(value, dict) and value.get("bits") == bits, "wrong output width")
    encoded = value.get("hex", "")
    require(len(encoded) == 2 + (bits + 3) // 4 and encoded.startswith("0x"), "invalid coin encoding")
    require(all(x in "0123456789abcdef" for x in encoded[2:]), "noncanonical output encoding")
    require(0 <= int(encoded, 16) < 1 << bits, "coin out of range")


def service_complete(sample, invalid_ax=False):
    p = sample.get("service_progress")
    require(isinstance(p, dict) and p.get("schema_version") == 1, "missing service observation")
    pending = p.get("pending")
    require(isinstance(pending, dict) and pending, "missing pending obligations")
    require(all(type(v) is int and v >= 0 for v in pending.values()), "invalid pending count")
    if invalid_ax:
        # This fixture changes only the dealer record. Every actual service obligation still drains.
        return (p.get("output_observed") is True and pending.get("nonhonest_behavior") == 1
                and all(v == 0 for k, v in pending.items() if k != "nonhonest_behavior"))
    return (p.get("output_observed") is True and p.get("all_honest_services_complete") is True
            and all(v == 0 for v in pending.values()))


def network_signature(samples, invalid_ax_dealers=()):
    signature, complete = [], True
    for party, sample in sorted(samples.items()):
        complete &= service_complete(sample, party in invalid_ax_dealers)
        network = sample["resources"]["network"]
        require(bool(network), "missing network counters")
        for name, v in sorted(network.items()):
            fields = ("sent_bytes", "received_bytes", "queued_frames", "acknowledged_frames", "logical_frames", "logical_frame_bytes")
            require(all(type(v.get(k)) is int and v[k] >= 0 for k in fields), "invalid transport counter")
            require(v["acknowledged_frames"] <= v["queued_frames"], "ACK exceeds queued frames")
            complete &= v["queued_frames"] == v["acknowledged_frames"] == v["logical_frames"]
            signature.append((party, name, *(v[k] for k in fields)))
    return tuple(signature), complete


def audit_transport(services):
    """Audit completed logical delivery without equating writes with reads after reconnect.

    The current transport sends no separate handshake: a logical frame's encoded
    bytes and its 32-byte authenticated ACK must each have crossed a successful
    read. A closed connection can discard already accepted socket writes; replay
    then completes the same logical delivery on another connection. Those writes
    remain a measured cost. This is a necessary accounting check, not a proof of
    arbitrary network termination or a claim about TCP/IP wire bytes.
    """
    ledgers = {}
    for name, c in services.items():
        required = ("sent_bytes", "received_bytes", "logical_frame_bytes", "logical_frames",
                    "queued_frames", "acknowledged_frames", "replayed_frames", "connected_streams")
        require(all(type(c.get(k)) is int and c[k] >= 0 for k in required), "invalid final transport counter")
        require(c["queued_frames"] == c["acknowledged_frames"] == c["logical_frames"], "unacknowledged final frames")
        logical = c["logical_frame_bytes"] + 32 * c["logical_frames"]
        require(c["sent_bytes"] >= c["received_bytes"] >= logical,
                "socket counters do not cover logical frames and ACKs")
        if c["replayed_frames"] == 0:
            require(c["sent_bytes"] == c["received_bytes"] == logical,
                    "unexplained socket traffic without replay evidence")
        ledgers[name] = dict(c, logical_with_ack_bytes=logical,
                            socket_write_read_gap_bytes=c["sent_bytes"] - c["received_bytes"],
                            socket_send_overhead_bytes=c["sent_bytes"] - logical)
    return ledgers


def node_statistics(parties, logical_with_ack_bytes):
    """Equal averages over physical processes, never stake or virtual shares.

    Logical bytes are averaged globally: the ACK for a sent frame is written by
    its receiver, so L_i + 32 F_i is not a node's actual outbound logical traffic.
    Actual maximum-node traffic is obtained from that node's socket counters.
    """
    values = list(parties.values())
    require(bool(values), "no physical nodes to summarize")
    n = len(values)
    phases = values[0]["cpu_phases_ms"]
    return dict(
        mean_party_sent_bytes=sum(p["sent_bytes"] for p in values) / n,
        max_party_sent_bytes=max(p["sent_bytes"] for p in values),
        mean_party_received_bytes=sum(p["received_bytes"] for p in values) / n,
        max_party_received_bytes=max(p["received_bytes"] for p in values),
        mean_party_logical_with_ack_bytes=logical_with_ack_bytes / n,
        mean_party_cpu_phases_ms={k: sum(p["cpu_phases_ms"][k] for p in values) / n for k in phases},
        max_party_cpu_phases_ms={k: max(p["cpu_phases_ms"][k] for p in values) for k in phases},
        mean_party_total_cpu_ms=sum(p["total_cpu_ms"] for p in values) / n,
        max_party_total_cpu_ms=max(p["total_cpu_ms"] for p in values),
        latency_mean_ms=sum(p["output_ms"] for p in values) / n,
        per_node_normalization="unweighted arithmetic mean over physical parties; latency mean uses each observed output",
    )


def analyze_run(directory, case):
    directory = Path(directory)
    control = json.loads((directory / "control.json").read_text())
    require(control.get("error") is None, f"controller reported failure: {control.get('error')}")
    require(set(control["returncodes"]) == {str(i) for i in range(case["n"])}, "missing process exit")
    require(all(v == 0 for v in control["returncodes"].values()), "nonzero process exit")
    require(control["quiet_observed_s"] >= control["quiet_required_s"], "short quiet observation")
    execution_file = directory / "execution.json"
    execution = json.loads(execution_file.read_text()) if execution_file.exists() else None
    fixture_dealers = case.get("faulty_dealers", case.get("invalid_ax_dealers", ()))
    parties, coins, sent, received, end_samples, transport = {}, [], {}, {}, {}, {}
    for i in range(case["n"]):
        rows = [json.loads(line) for line in (directory / f"party-{i}.jsonl").read_text().splitlines()]
        require(all(r.get("party") == i for r in rows), "wrong process identity")
        require(all(a["observer_ns"] <= b["observer_ns"] for a, b in zip(rows, rows[1:])), "nonmonotonic log")
        def one(kind):
            values = [r for r in rows if r["kind"] == kind]
            require(len(values) == 1, f"expected exactly one {kind}")
            return values[0]
        preparing, ready, start, stopping, stopped = [one(k) for k in ("preparing", "ready", "started", "stopping", "stopped")]
        if execution is not None:
            require(ready.get("execution") == execution, "wrong local execution profile")
        events = [r for r in rows if r["kind"] == "event"]
        names = [r["event"]["kind"] for r in events]
        require("failed" not in names, "protocol failed event")
        output_name = "beacon" if case["protocol"] == "hashrand" else "coin"
        outputs = [r for r in events if r["event"]["kind"] == output_name]
        require(len(outputs) == 1 and names.count("frozen") == 1, "wrong single-coin event count")
        output = outputs[0]
        require(names.index("frozen") < names.index(output_name), "output before Freeze")
        if case["protocol"] == "hashrand":
            require(names.count("complete") == 1, "HashRand did not complete")
            require(output["event"]["batch"] == 0 and output["event"]["index"] == 0, "not a standalone HashRand coin")
        value = output["event"]["value"]
        validate_coin(value, case["parameters"]["output_bits"])
        coins.append(value)
        boundary = rows[control["service_start_sequences"][str(i)]]
        require(boundary["kind"] == "sample" and service_complete(boundary, i in fixture_dealers), "invalid service boundary")
        last_sample = [r for r in rows if r["kind"] == "sample"][-1]
        require(service_complete(last_sample, i in fixture_dealers), "remaining application work")
        require(preparing["observer_ns"] <= ready["observer_ns"] <= start["observer_ns"]
                <= output["observer_ns"] <= boundary["observer_ns"] <= stopping["observer_ns"]
                <= stopped["observer_ns"], "phase order violation")
        snapshots = [r["resources"] for r in (preparing, ready, start, output, boundary, stopping, stopped)]
        require(all(not r["profile_enabled"] for r in snapshots), "profiling enabled in timing comparison")
        phase_names = ("cold_prepare", "ready_barrier", "online_to_own_output", "post_output_service_observation", "quiet_observation", "shutdown")
        phase = {name: subtract(cpu(b), cpu(a)) / 1000 for name, a, b in zip(phase_names, snapshots, snapshots[1:])}
        phase["startup_before_prepare"] = cpu(snapshots[0]) / 1000
        for service, counts in stopped["resources"]["network"].items():
            require(counts["queued_frames"] == counts["acknowledged_frames"] == counts["logical_frames"], "unacknowledged final frames")
            sent[service] = sent.get(service, 0) + counts["sent_bytes"]
            received[service] = received.get(service, 0) + counts["received_bytes"]
            totals = transport.setdefault(service, {})
            for field in ("sent_bytes", "received_bytes", "logical_frames", "logical_frame_bytes",
                          "queued_frames", "acknowledged_frames", "replayed_frames", "connected_streams"):
                require(type(counts.get(field)) is int and counts[field] >= 0, "invalid final transport counter")
                totals[field] = totals.get(field, 0) + counts[field]
        for service, counts in stopped["resources"]["network"].items():
            for field in ("stall_reconnects", "io_disconnects", "invalid_acks", "connect_failures",
                          "receive_backpressure_waits", "receive_backpressure_ns"):
                if field in counts:
                    require(type(counts[field]) is int and counts[field] >= 0, "invalid retry diagnostic")
                    transport[service][field] = transport[service].get(field, 0) + counts[field]
        # Exclude shutdown/quiet as an opportunity to hide additional communication.
        require(set(boundary["resources"]["network"]) == set(stopped["resources"]["network"]),
                "service set changed after claimed boundary")
        for service, counts in boundary["resources"]["network"].items():
            final = stopped["resources"]["network"][service]
            for field in ("sent_bytes", "received_bytes", "queued_frames", "acknowledged_frames", "logical_frames"):
                require(final[field] == counts[field], "traffic after claimed service boundary")
        end_samples[i] = last_sample
        parties[str(i)] = dict(cpu_phases_ms=phase, total_cpu_ms=cpu(snapshots[-1]) / 1000,
                               output_ms=(output["observer_ns"] - control["start_ns"]) / 1e6,
                               peak_rss_kib=stopped["resources"]["max_rss_kib"],
                               sent_bytes=sum(v["sent_bytes"] for v in stopped["resources"]["network"].values()),
                               received_bytes=sum(v["received_bytes"] for v in stopped["resources"]["network"].values()),
                               resources_at_output=output["resources"], resources_at_service_boundary=boundary["resources"],
                               resources_at_exit=stopped["resources"])
    require(all(v == coins[0] for v in coins), "honest output disagreement")
    _, complete = network_signature(end_samples, fixture_dealers)
    require(complete, "incomplete final observation")
    require(sum(sent.values()) > 0, "missing socket traffic")
    ledgers = audit_transport(transport)
    phases = {name: sum(p["cpu_phases_ms"][name] for p in parties.values()) for name in next(iter(parties.values()))["cpu_phases_ms"]}
    logical_bytes = sum(v["logical_with_ack_bytes"] for v in ledgers.values())
    per_node = node_statistics(parties, logical_bytes)
    return dict(schema=SCHEMA, status="success", execution=execution, case_id=case["case_id"], protocol=case["protocol"], n=case["n"],
                family=case["family"], weight_policy_sha256=case["weight_policy_sha256"],
                total_weight=case["total_weight"], threshold=case["threshold"], agreement=True, coin=coins[0],
                outputs_observed=len(coins), latency_all_ms=max(p["output_ms"] for p in parties.values()),
                latency_first_ms=min(p["output_ms"] for p in parties.values()),
                prepare_wall_ms=control["start_ns"] / 1e6,
                end_to_end_all_ms=control["start_ns"] / 1e6 + max(p["output_ms"] for p in parties.values()),
                service_observed_ms=(control["service_start_ns"] - control["start_ns"]) / 1e6,
                quiet_observed_s=control["quiet_observed_s"], cpu_phases_ms=phases,
                total_cpu_ms=sum(p["total_cpu_ms"] for p in parties.values()),
                peak_party_rss_kib=max(p["peak_rss_kib"] for p in parties.values()),
                sampled_peak_aggregate_rss_kib=control["sampled_peak_aggregate_rss_kib"],
                total_sent_bytes=sum(sent.values()), total_received_bytes=sum(received.values()),
                **per_node,
                per_service_sent_bytes=sent, per_service_received_bytes=received, parties=parties,
                transport_audit_policy="logical-ack-replay-ledger-v2", transport_ledger=ledgers,
                logical_with_ack_bytes=logical_bytes,
                socket_write_read_gap_bytes=sum(v["socket_write_read_gap_bytes"] for v in ledgers.values()),
                socket_send_overhead_bytes=sum(v["socket_send_overhead_bytes"] for v in ledgers.values()),
                replayed_frames=sum(v["replayed_frames"] for v in ledgers.values()),
                scope=("CSS dealer benchmark; complete service observation" if case.get("campaign") == "css-max" else
                       "loopback dealer-only rejection; complete service observation" if "faulty_dealers" in case or "invalid_ax_dealers" in case else
                       "all-honest single coin; complete service observation; not asynchronous termination detection"),
                network_metric="successful socket payload writes incl. protocol framing, MAC, ACK, application retries; excludes TCP/IP headers and kernel retransmissions")

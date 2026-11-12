"""Manage a hashwc-rs experiment fleet with AWS CLI v2. 'plan' is fully offline."""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


REGIONS = ("us-east-1", "us-east-2", "us-west-2", "ap-northeast-1", "eu-west-3")
OWNER = "hashwc-rs-benchmark"


def placement(count):
    if count < 1:
        raise ValueError("count must be positive")
    return {region: list(range(i, count, len(REGIONS))) for i, region in enumerate(REGIONS)}


def aws(region, *args):
    result = subprocess.run(["aws", "ec2", *args, "--region", region, "--output", "json",
                             "--no-cli-pager"], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{region} {args[0]}: {result.stderr.strip()}")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def inventory(fleet, call):
    found = []
    for region in REGIONS:
        response = call(region, "describe-instances", "--filters",
                        f"Name=tag:ManagedBy,Values={OWNER}", f"Name=tag:Fleet,Values={fleet}")
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                if tags.get("ManagedBy") != OWNER or tags.get("Fleet") != fleet:
                    raise ValueError("unexpected instance outside requested fleet")
                found.append((region, instance))
    return found


def slot_of(instance):
    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    return int(tags["Slot"])


def actions(command, instances, count=None):
    result = []
    if command == "start":
        targets = placement(count)
        existing = {}
        for region, inst in instances:
            state = inst["State"]["Name"]
            if state == "terminated":
                continue
            slot = slot_of(inst)
            if slot < 0 or slot in existing or REGIONS[slot % len(REGIONS)] != region:
                raise ValueError("conflicting slot tags; inspect info")
            if state in ("shutting-down", "stopping"):
                raise ValueError("fleet is transitioning; retry after it settles")
            if slot >= count and state != "stopped":
                raise ValueError("more active slots than requested; stop the fleet before downsizing")
            existing[slot] = inst
        for region, slots in targets.items():
            for slot in slots:
                inst = existing.get(slot)
                if inst is None:
                    result.append((region, "create", slot, None))
                elif inst["State"]["Name"] == "stopped":
                    result.append((region, "resume", slot, inst["InstanceId"]))
        return result
    for region, inst in instances:
        state = inst["State"]["Name"]
        if command == "stop" and state == "pending":
            raise ValueError("instances are pending; retry stop after they reach running")
        if ((command == "stop" and state == "running") or
                (command == "destroy" and state in ("pending", "running", "stopping", "stopped"))):
            result.append((region, command, slot_of(inst), inst["InstanceId"]))
    return result


def apply(fleet, planned, config, call):
    # Validate the entire regional configuration before the first mutation.
    for region in {r for r, action, _, _ in planned if action == "create"}:
        opts = config["regions"][region]
        for field, prefix in (("ami", "ami"), ("subnet", "subnet"), ("security_group", "sg")):
            if not re.fullmatch(prefix + r"-[0-9a-f]{8}(?:[0-9a-f]{9})?", opts[field]):
                raise ValueError(f"provide a real {region} {field} in the config")
        if not config["key_name"] or not config["instance_type"]:
            raise ValueError("missing key_name or instance_type")
    methods = {"resume": "start-instances", "stop": "stop-instances", "destroy": "terminate-instances"}
    for region, action, slot, iid in planned:
        if action == "create":
            opts = config["regions"][region]
            tags = [{"Key": k, "Value": v} for k, v in
                    (("ManagedBy", OWNER), ("Fleet", fleet), ("Slot", str(slot)),
                     ("Name", f"hashwc-{fleet}-{slot:03}"))]
            token = hashlib.sha256(f"{OWNER}/{fleet}/{region}/{slot}".encode()).hexdigest()
            response = call(region, "run-instances", "--count", "1", "--image-id", opts["ami"],
                            "--instance-type", config["instance_type"], "--key-name", config["key_name"],
                            "--subnet-id", opts["subnet"], "--security-group-ids", opts["security_group"],
                            "--associate-public-ip-address", "--client-token", token,
                            "--tag-specifications", json.dumps([{"ResourceType": "instance", "Tags": tags}]))
            iid = response["Instances"][0]["InstanceId"]
        else:
            call(region, methods[action], "--instance-ids", iid)
        print(f"{region} {action} slot={slot} {iid}", file=sys.stderr, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "start", "info", "stop", "destroy"):
        sub = commands.add_parser(name)
        if name in ("start", "plan"):
            sub.add_argument("count", type=int)
        if name != "plan":
            sub.add_argument("--fleet", required=True, help="unique ID for this fleet lifetime")
        if name in ("start", "stop", "destroy"):
            sub.add_argument("--apply", action="store_true", help="execute the displayed operation")
        if name == "start":
            sub.add_argument("--config", type=Path, default=Path(__file__).with_name("fleet.json"))
        if name == "info":
            sub.add_argument("--raw", action="store_true", help="full regional EC2 instance inventory")
    args = parser.parse_args()
    if args.command == "plan":
        print(json.dumps(placement(args.count), indent=2))
        return
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", args.fleet):
        raise ValueError("fleet must contain 1-48 lowercase letters, digits or hyphens")
    if args.command == "start":
        placement(args.count)
    instances = inventory(args.fleet, aws)
    if args.command == "info":
        rows = []
        for region, inst in instances:
            if args.raw:
                rows.append(dict(region=region, instance=inst))
            else:
                rows.append(dict(region=region, slot=slot_of(inst), id=inst["InstanceId"],
                                 state=inst["State"]["Name"], type=inst["InstanceType"],
                                 az=inst["Placement"]["AvailabilityZone"], key=inst.get("KeyName"),
                                 public_ip=inst.get("PublicIpAddress"), private_ip=inst.get("PrivateIpAddress")))
        print(json.dumps(sorted(rows, key=lambda r: r.get("slot", 0)), indent=2))
        return
    planned = actions(args.command, instances, getattr(args, "count", None))
    print(json.dumps([dict(region=r, action=a, slot=s, id=i) for r, a, s, i in planned], indent=2), flush=True)
    if args.apply:
        config = {}
        if any(action == "create" for _, action, _, _ in planned):
            config = json.loads(args.config.read_text())
        apply(args.fleet, planned, config, aws)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError) as error:
        sys.exit(str(error))

"""EC2 and SSH operations shared by the paper fleet controller."""
import json
from pathlib import Path
import subprocess
import sys
import time
import remote
from common import ROOT
sys.path.insert(0, str(ROOT / "benchmark/aws_fleet"))
import fleet

def ec2(region, *args):
    p = subprocess.run(["aws", "ec2", *args, "--region", region, "--no-cli-pager", "--output", "json"],
                       capture_output=True, text=True, timeout=45)
    if p.returncode:
        raise RuntimeError(f"{region} {args[0]}: {p.stderr.strip()}")
    return json.loads(p.stdout or "{}")


def describe(region, fleet_id):
    response = ec2(region, "describe-instances", "--filters",
                   f"Name=tag:Fleet,Values={fleet_id}", f"Name=tag:ManagedBy,Values={fleet.OWNER}")
    return [i for r in response["Reservations"] for i in r["Instances"]]


def wait_for(probe, timeout, what):
    deadline = time.monotonic() + timeout
    while True:
        value = probe()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise TimeoutError(what)
        time.sleep(4)


def connections(args, rows, directory):
    hosts = [remote.Host(r["public_ip"],args) for r in rows]
    if getattr(args,"ssh_proxy",False):
        for h in hosts:
            opt=["-o","ProxyCommand=nc -X connect -x 127.0.0.1:7890 %h %p"]
            h.ssh[1:1]=opt
            h.scp[1:1]=opt
    if args.trust_first_use:
        options = ["-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={directory}/known_hosts"]
        for row,h in zip(rows,hosts):
            host_options = options + ["-o", f"HostKeyAlias={row['id']}"]
            h.ssh[1:1] = host_options
            h.scp[1:1] = host_options
    return hosts


def retire(row):
    region, iid = row["region"], row["id"]
    def status():
        found=ec2(region,"describe-instances","--instance-ids",iid)
        return found["Reservations"][0]["Instances"][0]["State"]["Name"]
    ec2(region,"terminate-instances","--instance-ids",iid)
    wait_for(lambda: status()=="terminated",300,f"terminate {iid}")



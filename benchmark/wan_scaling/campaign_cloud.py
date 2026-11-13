"""A progressively grown EC2 fleet. Calls are made only by the explicit apply/cleanup paths."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/"remote_coin"))
import pilot4 as p
from common import save

REGIONS=p.fleet.REGIONS
MAX_N=64
BASE=21000


class Cloud:
    def __init__(self,out,cfg,args,state):
        self.out,self.cfg,self.args,self.state=out,cfg,args,state
        self.name=state["fleet"]
        self.journal=out/"campaign.json"
        self.write()

    def write(self):
        save(self.journal,self.state)

    def preflight(self):
        for r in REGIONS:
            opt=self.cfg["regions"][r]
            sub,=p.ec2(r,"describe-subnets","--subnet-ids",opt["subnet"])["Subnets"]
            az=sub["AvailabilityZone"]
            sg,=p.ec2(r,"describe-security-groups","--group-ids",opt["security_group"])["SecurityGroups"]
            if sg["VpcId"]!=sub["VpcId"] or sg["GroupName"]!="whcc-benchmark":
                raise ValueError(f"{r}: expected dedicated fixed group")
            count=len(p.fleet.placement(self.state.get("max_nodes", MAX_N))[r])
            if sub["AvailableIpAddressCount"]<count:
                raise RuntimeError(f"{r}: insufficient free subnet addresses")
            offer=p.ec2(r,"describe-instance-type-offerings","--location-type","availability-zone",
                        "--filters",f"Name=instance-type,Values={self.cfg['instance_type']}",f"Name=location,Values={az}")
            if not offer["InstanceTypeOfferings"]:
                raise RuntimeError(f"{self.cfg['instance_type']} unavailable in {az}")
            p.ec2(r,"describe-key-pairs","--key-names",self.cfg["key_name"])
            image,=p.ec2(r,"describe-images","--image-ids",opt["ami"])["Images"]
            root=next(d for d in image["BlockDeviceMappings"] if d["DeviceName"]==image["RootDeviceName"])
            if image["State"]!="available" or image["Architecture"]!="x86_64" or not root["Ebs"].get("DeleteOnTermination"):
                raise RuntimeError(f"{r}: incompatible AMI")
            # Fail before allocating nodes when even the account's total vCPU quota is insufficient.
            quota=json.loads(subprocess.check_output(["aws","service-quotas","get-service-quota","--region",r,
                "--service-code","ec2","--quota-code","L-1216C47A","--output","json","--no-cli-pager"],timeout=45))
            if quota["Quota"]["Value"]<2*count:
                raise RuntimeError(f"{r}: need at least {2*count} Standard On-Demand vCPUs")
            self.state["regions"][r]=dict(vpc=sub["VpcId"],fixed=sg["GroupId"],az=az)
        self.write()

    def ensure_groups(self):
        # Split the 64 peer /32 rules over two attached groups, avoiding the common
        # 60-rule limit without widening access or replacing the permanent SSH group.
        for r,entry in self.state["regions"].items():
            entry["group_requested"]=True
            self.write()
            entry["aux"]=p.ec2(r,"create-security-group","--vpc-id",entry["vpc"],
                "--group-name",self.name,"--description","Temporary overflow group for peer IPv4 rules",
                "--tag-specifications",f"ResourceType=security-group,Tags=[{{Key=Fleet,Value={self.name}}}]")["GroupId"]
            self.write()

    def launch(self,r,slot,gen=0):
        def call(region,*args):
            cmd=list(args)
            if "cpu_credits" in self.cfg:
                cmd.extend(["--credit-specification", "CpuCredits="+self.cfg["cpu_credits"]])
            idx=cmd.index("--security-group-ids")+2
            cmd.insert(idx,self.state["regions"][r]["aux"])
            idx=cmd.index("--client-token")+1
            token=hashlib.sha256(f"{self.name}/{r}/{slot}/{gen}".encode()).hexdigest()
            cmd[idx]=token
            request=dict(slot=slot,region=r,generation=gen,token=token)
            self.state["requests"].append(request)
            self.write()
            try:
                data=p.ec2(region,*cmd)
            except RuntimeError as error:
                if any(code in str(error) for code in ("VcpuLimitExceeded","InstanceLimitExceeded","UnauthorizedOperation","InsufficientInstanceCapacity")):
                    request["rejected"]=True
                    self.write()
                raise
            request["id"]=data["Instances"][0]["InstanceId"]
            self.write()
            return data
        p.fleet.apply(self.name,[(r,"create",slot,None)],self.cfg,call)

    def inventory(self,n):
        active={q["slot"]:q for q in self.state["requests"] if q.get("id") and not q.get("retired")}
        rows=[]
        for r in REGIONS:
            for i in p.describe(r,self.name):
                s=p.fleet.slot_of(i)
                if s in active and active[s]["id"]==i["InstanceId"] and i["State"]["Name"]=="running" and i.get("PublicIpAddress"):
                    rows.append(dict(slot=s,region=r,id=i["InstanceId"],public_ip=i["PublicIpAddress"],private_ip=i.get("PrivateIpAddress",i["PublicIpAddress"])))
        rows.sort(key=lambda x:x["slot"])
        return rows if [x["slot"] for x in rows]==list(range(n)) else None

    def sync_rules(self,rows):
        for r,entry in self.state["regions"].items():
            for bucket,gid in enumerate([entry["fixed"],entry["aux"]]):
                split = (self.state.get("max_nodes", MAX_N) + 1) // 2
                desired={i["public_ip"]+"/32" for i in rows if i["slot"]//split==bucket}
                owned=p.ec2(r,"describe-security-group-rules","--filters",f"Name=group-id,Values={gid}",
                    f"Name=tag:Pilot,Values={self.name}")["SecurityGroupRules"]
                old={x["CidrIpv4"]:x["SecurityGroupRuleId"] for x in owned if not x["IsEgress"] and x.get("FromPort")==BASE}
                stale=[old[ip] for ip in old.keys()-desired]
                if stale:
                    p.ec2(r,"revoke-security-group-ingress","--group-id",gid,"--security-group-rule-ids",*stale)
                missing=sorted(desired-old.keys())
                if missing:
                    perm=dict(IpProtocol="tcp",FromPort=BASE,ToPort=BASE+7*self.state.get("max_nodes", MAX_N)-1,IpRanges=[dict(CidrIp=x) for x in missing])
                    p.ec2(r,"authorize-security-group-ingress","--group-id",gid,"--ip-permissions",json.dumps([perm]),
                          "--tag-specifications",f"ResourceType=security-group-rule,Tags=[{{Key=Pilot,Value={self.name}}}]")

        # Job-scoped keys allow SSH only from the fixed AWS controller host.
        controller=rows[0]
        desired={controller['public_ip']+'/32',controller.get('private_ip',controller['public_ip'])+'/32'}
        for r,entry in self.state['regions'].items():
            gid=entry['fixed']
            owned=p.ec2(r,'describe-security-group-rules','--filters',f'Name=group-id,Values={gid}',
                        f'Name=tag:Pilot,Values={self.name}')['SecurityGroupRules']
            old={x['CidrIpv4']:x['SecurityGroupRuleId'] for x in owned if not x['IsEgress'] and x.get('FromPort')==22}
            stale=[old[ip] for ip in old.keys()-desired]
            if stale:p.ec2(r,'revoke-security-group-ingress','--group-id',gid,'--security-group-rule-ids',*stale)
            missing=sorted(desired-old.keys())
            if missing:
                perm=dict(IpProtocol='tcp',FromPort=22,ToPort=22,IpRanges=[dict(CidrIp=x) for x in missing])
                p.ec2(r,'authorize-security-group-ingress','--group-id',gid,'--ip-permissions',json.dumps([perm]),
                      '--tag-specifications',f'ResourceType=security-group-rule,Tags=[{{Key=Pilot,Value={self.name}}}]')

    def grow(self,n,previous,stage):
        async def upload(hosts):
            # Keep startup file copies from saturating the local SSH proxy.
            slots=asyncio.Semaphore(8)
            async def one(i,h):
                async with slots:
                    try:
                        await p.remote.deploy(h,self.args.driver,self.state["driver_sha256"])
                    except p.remote.SSHTransportError as exc:
                        print(f"Startup upload SSH failure on slot {i}: {exc}",flush=True)
                        return i
                return None
            results=await p.remote.parallel(one(i,h) for i,h in enumerate(hosts))
            return [i for i in results if i is not None]

        for slot in range(previous,n):
            self.launch(REGIONS[slot%len(REGIONS)],slot)
        while True:
            rows=p.wait_for(lambda:self.inventory(n),360,"missing running instances at expansion")
            save(stage/"inventory.json",rows)
            hosts=p.connections(self.args,rows,self.out)
            failures=asyncio.run(p.remote.ssh_failures(hosts,self.args.boot_ssh_seconds))
            if not failures:
                failures=asyncio.run(upload(hosts))
                if not failures:
                    break
            for s in failures:
                req=next(q for q in self.state["requests"] if q.get("id")==rows[s]["id"])
                print(f"Replacing SSH-unreachable slot {s} ({rows[s]['id']})",flush=True)
                p.retire(rows[s])
                req["retired"]=True
                self.write()
                self.launch(rows[s]["region"],s,req["generation"]+1)
        self.sync_rules(rows)
        return rows

    def cleanup_region(self,r):
        entry=self.state["regions"][r]
        requests=[q for q in self.state["requests"] if q["region"]==r and not q.get("retired")]
        if requests:
            instances=p.describe(r,self.name)
            known={i["InstanceId"]:i["State"]["Name"] for i in instances}
            missing=[q for q in requests if not q.get("id") and not q.get("rejected")]
            unresolved=[]
            for q in missing:
                for attempt in range(5):
                    matches=p.ec2(r,"describe-instances","--filters",f"Name=client-token,Values={q['token']}",
                                  f"Name=tag:Fleet,Values={self.name}")["Reservations"]
                    if matches: break
                    if attempt<4: time.sleep(5)
                if not matches:
                    unresolved.append(q["token"])
                for res in matches:
                    for i in res["Instances"]:
                        known[i["InstanceId"]]=i["State"]["Name"]
            ids={q["id"] for q in requests if q.get("id") and known.get(q["id"])!="terminated"}
            ids.update(i for i,s in known.items() if s!="terminated")
            if ids:
                running=[i for i in ids if known.get(i)=="running"]
                if running:
                    try:
                        p.ec2(r,"stop-instances","--instance-ids",*sorted(running))
                        p.wait_for(lambda:all(i["State"]["Name"]!="stopping" and i["State"]["Name"]!="running"
                            for i in p.describe(r,self.name) if i["InstanceId"] in running),90,"stopping")
                    except (RuntimeError, TimeoutError, subprocess.TimeoutExpired): pass
                p.ec2(r,"terminate-instances","--instance-ids",*sorted(ids))
                p.wait_for(lambda:ids.issubset({i["InstanceId"] for i in p.describe(r,self.name)
                           if i["State"]["Name"]=="terminated"}),360,"terminate")
        else:
            unresolved=[]
        if entry.get("group_requested"):
            rules=p.ec2(r,"describe-security-group-rules","--filters",f"Name=group-id,Values={entry['fixed']}",
                        f"Name=tag:Pilot,Values={self.name}")["SecurityGroupRules"]
            ids=[x["SecurityGroupRuleId"] for x in rules if not x["IsEgress"]]
            if ids:
                p.ec2(r,"revoke-security-group-ingress","--group-id",entry["fixed"],"--security-group-rule-ids",*ids)
            aux=p.ec2(r,"describe-security-groups","--filters",f"Name=vpc-id,Values={entry['vpc']}",
                      f"Name=tag:Fleet,Values={self.name}",f"Name=group-name,Values={self.name}")["SecurityGroups"]
            for g in aux:
                def delete():
                    try: p.ec2(r,"delete-security-group","--group-id",g["GroupId"])
                    except RuntimeError as exc:
                        if "DependencyViolation" in str(exc): return False
                        raise
                    return True
                p.wait_for(delete,180,"aux group deletion")
        if unresolved:
            raise RuntimeError(f"check launch tokens manually after eventual consistency: {unresolved}")

    def cleanup(self):
        errors={}
        with ThreadPoolExecutor(5) as ex:
            futures={r:ex.submit(self.cleanup_region,r) for r in self.state["regions"]}
            for r,f in futures.items():
                try: f.result()
                except Exception as exc: errors[r]=str(exc)
        save(self.out/"cleanup.json",dict(confirmed=not errors,errors=errors))
        if errors: raise RuntimeError(f"cleanup needs review: {errors}")

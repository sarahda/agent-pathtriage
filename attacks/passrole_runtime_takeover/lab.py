#!/usr/bin/env python3
"""Build or remove the runtime takeover lab.

Three agent runtimes, three execution roles and one attacker principal.

    execA   plainly named. No canary access.
    execB   plainly named. The only role that can read the canary.
    execC   named BedrockAgentCore-apt-<suffix>-execC, identical to execB in
            every way except the name. That name is the variable: the managed
            policy BedrockAgentCoreFullAccess allows iam:PassRole only for
            roles matching *BedrockAgentCore*, which is the shape the AgentCore
            console gives the role it creates.

The attacker holds BedrockAgentCoreFullAccess and nothing else. Cells in
exploit.py add and remove one statement at a time.

The execution role trust policy below is the one in the AgentCore
documentation, unchanged, including an aws:SourceArn that covers every
AgentCore resource in the account rather than one runtime. That is the
vendor's template and it is part of what the lab is showing.

Nothing is hardcoded. The suffix is random, the account and region come from
the caller's session, and teardown finds what setup made by prefix.

    python3 lab.py setup
    ./upload-code.sh
    python3 exploit.py --all
    python3 lab.py teardown

This lab is intentionally insecure. Run it only in an account you control.
"""

from __future__ import annotations

import argparse
import json
import io
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
import sys
import time
import uuid

import boto3
from botocore.exceptions import ClientError

PREFIX = "apt-takeover-"
MANAGED = "arn:aws:iam::aws:policy/BedrockAgentCoreFullAccess"
CANARY_KEY = "sensitive/canary.txt"
RUNTIMES = ("aptAgentA", "aptAgentB", "aptAgentC")


def trust_exec(account, region):
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "AssumeRolePolicy", "Effect": "Allow",
        "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
        "Action": "sts:AssumeRole",
        "Condition": {
            "StringEquals": {"aws:SourceAccount": account},
            "ArnLike": {"aws:SourceArn":
                        f"arn:aws:bedrock-agentcore:{region}:{account}:*"}}}]}


def baseline(account, region, bucket, canary):
    st = [
        {"Effect": "Allow",
         "Action": ["logs:DescribeLogStreams", "logs:CreateLogGroup",
                    "logs:CreateLogStream", "logs:PutLogEvents",
                    "logs:DescribeLogGroups"],
         "Resource": f"arn:aws:logs:{region}:{account}:log-group:*"},
        {"Effect": "Allow",
         "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords",
                    "xray:GetSamplingRules", "xray:GetSamplingTargets"],
         "Resource": "*"},
        {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*",
         "Condition": {"StringEquals": {"cloudwatch:namespace": "bedrock-agentcore"}}},
        {"Effect": "Allow",
         "Action": ["bedrock-agentcore:GetWorkloadAccessToken",
                    "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                    "bedrock-agentcore:GetWorkloadAccessTokenForUserId"],
         "Resource": [
             f"arn:aws:bedrock-agentcore:{region}:{account}:workload-identity-directory/default",
             f"arn:aws:bedrock-agentcore:{region}:{account}:workload-identity-directory/default/workload-identity/*"]},
        {"Effect": "Allow",
         "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
         "Resource": ["arn:aws:bedrock:*::foundation-model/*",
                      f"arn:aws:bedrock:{region}:{account}:*"]},
        {"Sid": "AgentCode", "Effect": "Allow", "Action": ["s3:GetObject"],
         "Resource": f"arn:aws:s3:::{bucket}/code/*"},
    ]
    if canary:
        st.append({"Sid": "CanaryRead", "Effect": "Allow",
                   "Action": ["s3:GetObject"],
                   "Resource": f"arn:aws:s3:::{bucket}/sensitive/*"})
    return {"Version": "2012-10-17", "Statement": st}


def artifact(bucket, key):
    return {"codeConfiguration": {
        "code": {"s3": {"bucket": bucket, "prefix": key}},
        "runtime": "PYTHON_3_12", "entryPoint": ["main.py"]}}


def find_bucket(s3):
    names = [b["Name"] for b in s3.list_buckets()["Buckets"]
             if b["Name"].startswith(PREFIX)]
    return names


def cmd_setup(a):
    region = a.region
    s3 = boto3.client("s3", region_name=region)
    iam = boto3.client("iam")
    ctl = boto3.client("bedrock-agentcore-control", region_name=region)
    account = boto3.client("sts").get_caller_identity()["Account"]

    existing = find_bucket(s3)
    if existing and not a.force:
        print(f"stop: a lab bucket is already there: {existing}. "
              f"Run teardown first, or pass --force to build a second one.")
        return 2

    suffix = "ptk" + uuid.uuid4().hex[:8]
    bucket = f"{PREFIX}{suffix}"
    canary = "APT-TAKEOVER-CANARY-" + uuid.uuid4().hex[:12]
    print(f"account {account}  region {region}")
    print(f"bucket  {bucket}")

    kw = {"Bucket": bucket}
    if region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kw)
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_object(Bucket=bucket, Key=CANARY_KEY, Body=canary.encode(),
                  ContentType="text/plain")
    print(f"canary  {CANARY_KEY}")

    roles = [
        (f"{PREFIX}{suffix}-execA", trust_exec(account, region),
         baseline(account, region, bucket, canary=False)),
        (f"{PREFIX}{suffix}-execB", trust_exec(account, region),
         baseline(account, region, bucket, canary=True)),
        # the same role as execB, named the way the console names one
        (f"BedrockAgentCore-apt-{suffix}-execC", trust_exec(account, region),
         baseline(account, region, bucket, canary=True)),
    ]
    arns = {}
    for name, trust, pol in roles:
        r = iam.create_role(RoleName=name,
                            AssumeRolePolicyDocument=json.dumps(trust),
                            Description="AgentPathTriage runtime takeover lab")
        iam.put_role_policy(RoleName=name, PolicyName="baseline",
                            PolicyDocument=json.dumps(pol))
        arns[name] = r["Role"]["Arn"]
        print(f"role    {name}")

    att = f"{PREFIX}{suffix}-attacker"
    iam.create_role(
        RoleName=att,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                           "Action": "sts:AssumeRole"}]}),
        Description="AgentPathTriage runtime takeover lab, attacker principal")
    iam.attach_role_policy(RoleName=att, PolicyArn=MANAGED)
    print(f"role    {att}  ({MANAGED.rsplit('/', 1)[-1]} only)")

    print("\nwaiting 20s for the new roles to propagate before the runtimes "
          "are created")
    time.sleep(20)

    # The runtimes pull their artifact when they are created, so the real code
    # goes in before them. A placeholder here is a race the caller loses by
    # chaining setup and the cells together: a runtime created against an
    # empty object reaches CREATE_FAILED and no later upload revives it.
    for variant in ("benign", "planted"):
        src = os.path.join(HERE, "agent-src", f"{variant}.py")
        if not os.path.isfile(src):
            raise SystemExit(f"missing {src}")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(src, arcname="main.py")   # the runtime entryPoint
        s3.put_object(Bucket=bucket, Key=f"code/{variant}.zip",
                      Body=buf.getvalue(), ContentType="application/zip")
        print(f"code    code/{variant}.zip  ({buf.tell()} bytes)")
    pairs = [("aptAgentA", f"{PREFIX}{suffix}-execA"),
             ("aptAgentB", f"{PREFIX}{suffix}-execB"),
             ("aptAgentC", f"BedrockAgentCore-apt-{suffix}-execC")]
    for rt_name, role_name in pairs:
        r = ctl.create_agent_runtime(
            agentRuntimeName=rt_name,
            agentRuntimeArtifact=artifact(bucket, "code/benign.zip"),
            roleArn=arns[role_name],
            networkConfiguration={"networkMode": "PUBLIC"},
            description="AgentPathTriage runtime takeover lab")
        print(f"runtime {rt_name}: {r['agentRuntimeId']} ({r['status']})")

    print("\nnext:")
    print("  python3 exploit.py --all")
    print("\n(the code is already uploaded; ./upload-code.sh is only needed")
    print(" to change an agent and push it again)")
    return 0


def cmd_teardown(a):
    region = a.region
    s3 = boto3.client("s3", region_name=region)
    iam = boto3.client("iam")
    ctl = boto3.client("bedrock-agentcore-control", region_name=region)

    for page in ctl.get_paginator("list_agent_runtimes").paginate():
        for rt in page.get("agentRuntimes", []):
            if rt["agentRuntimeName"] in RUNTIMES:
                try:
                    ctl.delete_agent_runtime(agentRuntimeId=rt["agentRuntimeId"])
                    print(f"deleted runtime {rt['agentRuntimeName']}")
                except ClientError as e:
                    print(f"runtime {rt['agentRuntimeName']}: {e}")

    for page in iam.get_paginator("list_roles").paginate():
        for r in page["Roles"]:
            n = r["RoleName"]
            if not (n.startswith(PREFIX) or n.startswith("BedrockAgentCore-apt-")):
                continue
            for p in iam.list_attached_role_policies(RoleName=n)["AttachedPolicies"]:
                iam.detach_role_policy(RoleName=n, PolicyArn=p["PolicyArn"])
            for pn in iam.list_role_policies(RoleName=n)["PolicyNames"]:
                iam.delete_role_policy(RoleName=n, PolicyName=pn)
            iam.delete_role(RoleName=n)
            print(f"deleted role {n}")

    for name in find_bucket(s3):
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=name)
        print(f"deleted bucket {name}")

    print("\nteardown complete")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["setup", "teardown"])
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    ap.add_argument("--force", action="store_true",
                    help="setup: build even if a lab bucket already exists")
    a = ap.parse_args()
    return cmd_setup(a) if a.step == "setup" else cmd_teardown(a)


if __name__ == "__main__":
    sys.exit(main())

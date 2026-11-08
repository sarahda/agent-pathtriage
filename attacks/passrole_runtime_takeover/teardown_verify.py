#!/usr/bin/env python3
"""Confirm the lab left nothing behind.

`lab.py teardown` deletes what setup made and prints what it deleted. This
reads the account back afterwards and reports what is still there, so the
account is known to be clean rather than assumed to be.

Runtime deletion is not immediate, so a runtime still listed as DELETING is
reported as pending rather than as a leftover, and the exit code says which
of the two it is.

  python3 teardown_verify.py
  python3 teardown_verify.py --region us-west-2

exit 0  nothing left
exit 1  deletion still in progress, run again in a minute
exit 2  something is still there
"""
from __future__ import annotations

import argparse
import os
import sys

import boto3
from botocore.exceptions import ClientError

PREFIX = "apt-takeover-"
ROLE_PREFIXES = (PREFIX, "BedrockAgentCore-apt-")
RUNTIMES = ("aptAgentA", "aptAgentB", "aptAgentC")


def runtimes(region):
    ctl = boto3.client("bedrock-agentcore-control", region_name=region)
    out = []
    try:
        for page in ctl.get_paginator("list_agent_runtimes").paginate():
            for rt in page.get("agentRuntimes", []):
                if rt.get("agentRuntimeName") in RUNTIMES:
                    out.append((rt["agentRuntimeName"], rt.get("status")))
    except ClientError as e:
        return None, str(e)
    return out, None


def roles():
    iam = boto3.client("iam")
    out = []
    for page in iam.get_paginator("list_roles").paginate():
        for r in page["Roles"]:
            if r["RoleName"].startswith(ROLE_PREFIXES):
                out.append(r["RoleName"])
    return out


def buckets(region):
    s3 = boto3.client("s3", region_name=region)
    return [b["Name"] for b in s3.list_buckets()["Buckets"]
            if b["Name"].startswith(PREFIX)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    a = ap.parse_args()

    account = boto3.client("sts").get_caller_identity()["Account"]
    print(f"account {account}, region {a.region}\n")

    rts, err = runtimes(a.region)
    if err:
        print(f"runtimes could not be listed: {err}")
        return 2

    pending = [n for n, s in rts if s and "DELET" in str(s).upper()]
    left_rt = [(n, s) for n, s in rts if n not in pending]
    left_roles = roles()
    left_buckets = buckets(a.region)

    for label, items in (("runtimes", left_rt), ("roles", left_roles),
                         ("buckets", left_buckets)):
        if items:
            print(f"{label} still present:")
            for i in items:
                print(f"  {i}")
        else:
            print(f"{label}: none")

    if pending:
        print(f"\ndeletion in progress: {', '.join(pending)}")
        print("run this again in a minute")
        return 1
    if left_rt or left_roles or left_buckets:
        print("\nsomething is still there; see above")
        return 2
    print("\nclean")
    return 0


if __name__ == "__main__":
    sys.exit(main())

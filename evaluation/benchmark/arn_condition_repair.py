#!/usr/bin/env python3
"""
Does pinning iam:PassRole to a role ARN actually refuse the cell that succeeded?

Section 14 of the paper proposes replacing the resource pattern in
BedrockAgentCoreFullAccess with the ARN of the one role an agent is entitled to
pass. That is a proposal until something evaluates it, so this evaluates it
with the same engine that decides the real call: iam:SimulateCustomPolicy.

The shipped statement is read from the live managed policy rather than retyped,
so the input is whatever AWS publishes on the day this runs, and the repaired
statement is built from it by replacing only the Resource element. Nothing is
created, nothing is attached, and no agent runtime is involved.

Three targets, both policies:

  the agent's own role            the pass the agent legitimately needs
  a sibling the console named     the cell that succeeded in Section 9
  a sibling named anything else   the control cell, which was denied

A repair that works has to deny the second while still allowing the first.

Usage:
  python3 arn_condition_repair.py [--json arn_condition_repair.json]
"""
import argparse
import json
import sys

import boto3

POLICY_ARN = "arn:aws:iam::aws:policy/BedrockAgentCoreFullAccess"
SERVICE = "bedrock-agentcore.amazonaws.com"

# role names, not ARNs: the account comes from the caller, never from a literal
OWN_ROLE_NAME = "BedrockAgentCore-apt-ownAgent"
TARGETS = {
    "the_agents_own_role": OWN_ROLE_NAME,
    "sibling_named_by_the_console": "BedrockAgentCore-apt-victimC",
    "sibling_named_anything_else": "apt-execB",
}


def shipped_passrole_statements(iam):
    """The iam:PassRole statements of the managed policy, as published today."""
    pol = iam.get_policy(PolicyArn=POLICY_ARN)["Policy"]
    version = pol["DefaultVersionId"]
    doc = iam.get_policy_version(
        PolicyArn=POLICY_ARN, VersionId=version)["PolicyVersion"]["Document"]
    if isinstance(doc, str):
        doc = json.loads(doc)
    stmts = [
        s for s in doc["Statement"]
        if "iam:PassRole" in ([s["Action"]] if isinstance(s["Action"], str)
                              else s["Action"])
    ]
    if not stmts:
        sys.exit("no iam:PassRole statement in %s %s" % (POLICY_ARN, version))
    return version, doc.get("Version", "2012-10-17"), stmts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default="arn_condition_repair.json")
    args = ap.parse_args()

    iam = boto3.client("iam")
    account = boto3.client("sts").get_caller_identity()["Account"]
    version, lang, shipped = shipped_passrole_statements(iam)

    def role_arn(name):
        return "arn:aws:iam::%s:role/%s" % (account, name)

    repaired = json.loads(json.dumps(shipped))
    for s in repaired:
        s["Resource"] = role_arn(OWN_ROLE_NAME)

    policies = {
        "shipped_%s" % version: {"Version": lang, "Statement": shipped},
        "arn_pinned": {"Version": lang, "Statement": repaired},
    }
    context = [{"ContextKeyName": "iam:PassedToService",
                "ContextKeyType": "string",
                "ContextKeyValues": [SERVICE]}]

    rows = []
    for policy_name, document in policies.items():
        for target_name, role_name in TARGETS.items():
            arn = role_arn(role_name)
            out = iam.simulate_custom_policy(
                PolicyInputList=[json.dumps(document)],
                ActionNames=["iam:PassRole"],
                ResourceArns=[arn],
                ContextEntries=context)
            for res in out["EvaluationResults"]:
                rows.append({
                    "policy": policy_name,
                    "target": target_name,
                    "target_role_name": role_name,
                    "decision": res["EvalDecision"],
                    "matched_statements": len(res.get("MatchedStatements", [])),
                })

    def decision(policy, target):
        for r in rows:
            if r["policy"].startswith(policy) and r["target"] == target:
                return r["decision"]
        return None

    summary = {
        "shipped_allows_sibling": decision("shipped", "sibling_named_by_the_console"),
        "pinned_allows_sibling": decision("arn_pinned", "sibling_named_by_the_console"),
        "pinned_allows_own_role": decision("arn_pinned", "the_agents_own_role"),
    }
    summary["repair_holds"] = (
        summary["shipped_allows_sibling"] == "allowed"
        and summary["pinned_allows_sibling"] != "allowed"
        and summary["pinned_allows_own_role"] == "allowed")

    result = {
        "policy_arn": POLICY_ARN,
        "policy_version": version,
        "passed_to_service": SERVICE,
        "shipped_statement": shipped,
        "rows": rows,
        "summary": summary,
    }
    with open(args.json, "w") as fh:
        json.dump(result, fh, indent=2)
        fh.write("\n")

    width = max(len(r["target"]) for r in rows)
    for r in rows:
        print("%-16s %-*s %s" % (r["policy"], width, r["target"], r["decision"]))
    print()
    print("repair holds:", summary["repair_holds"])
    return 0 if summary["repair_holds"] else 1


if __name__ == "__main__":
    sys.exit(main())

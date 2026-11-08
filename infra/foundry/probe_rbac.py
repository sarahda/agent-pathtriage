#!/usr/bin/env python3
"""
Live RBAC check against the deployed Foundry lab.

What this proves, and what it does not. It queries Azure for the role
assignments each agent identity actually holds, and compares them with what the
analyser read out of Terraform. That confirms the DEPLOYMENT matches the
CONFIGURATION, which is worth confirming: the analyser reads source, and source
can diverge from what is live.

It does NOT prove exploitability. Confirming that agentB holds a Key Vault role
and agentA does not is the precondition for the escalation, not the escalation.
The escalation is agentA reaching the secret THROUGH agentB, and observing that
requires the agent to run and make the call. A laptop cannot stand in for
agentA: a user-assigned managed identity is assumed by an Azure resource, not by
a person with the Azure CLI, so there is no shortcut here.

So this writes `rbac_verified`, never `observed`. `observed` is reserved for an
actual call, and the summary keeps counting a cell as unconfirmed until one
happens. Recording a precondition check as an exploit would be exactly the
overclaim the two fields exist to keep apart.

Usage:
  az login
  python3 probe_rbac.py --tfdir . --out runs/
"""
import argparse, json, os, re, subprocess, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(_HERE)),
                                "agentpathtriage"))
sys.path.insert(0, _HERE)

GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
REDACTED = "00000000-0000-0000-0000-000000000000"


def redact(x):
    return GUID.sub(REDACTED, str(x))


def tf_output(tfdir):
    out = subprocess.check_output(
        ["terraform", f"-chdir={tfdir}", "output", "-json"])
    return {k: v.get("value") for k, v in json.loads(out).items()}


def role_assignments(principal_id):
    try:
        out = subprocess.check_output(
            ["az", "role", "assignment", "list", "--assignee", principal_id,
             "--all", "-o", "json"], stderr=subprocess.STDOUT)
    except FileNotFoundError:
        raise SystemExit("the Azure CLI is not on PATH")
    except subprocess.CalledProcessError as e:
        msg = (e.output or b"").decode("utf-8", "ignore")
        if "AADSTS" in msg or "az login" in msg:
            raise SystemExit("Azure credential expired. Run: az login")
        raise SystemExit(f"az role assignment list failed:\n{msg[-400:]}")
    return [{"role": r.get("roleDefinitionName"), "scope": r.get("scope")}
            for r in json.loads(out)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tfdir", default=".")
    ap.add_argument("--out", default="runs")
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    tf = tf_output(a.tfdir)
    pids = {"agentA": tf.get("agentA_principal_id"),
            "agentB": tf.get("agentB_principal_id")}
    if not all(pids.values()):
        raise SystemExit("terraform output did not carry both principal ids")

    live = {}
    for agent, pid in pids.items():
        roles = role_assignments(pid)
        live[agent] = sorted({f"{r['role']} @ {redact(r['scope'])}" for r in roles})
        print(f"{agent}:")
        for r in live[agent]:
            print(f"   {r}")
        if not live[agent]:
            print("   (none)")

    only_b = set(live["agentB"]) - set(live["agentA"])
    print(f"\nheld by agentB and not by agentA: {len(only_b)}")
    for r in sorted(only_b):
        print(f"   {r}")

    print("\nThis is the precondition, confirmed against live Azure. It is NOT "
          "the escalation: that is agentA reaching one of these THROUGH agentB, "
          "which needs the agent to run. Recorded as rbac_verified, not as "
          "observed.")

    # Which cell is actually standing. The authType alone does not identify it:
    # grant_a is the other deployed factor, and stamping a grant_a=false cell
    # with RBAC read from a grant_a=true deployment would attach the wrong
    # evidence to the wrong cell, which is worse than no evidence.
    deployed_grant_a = bool(live["agentA"])
    rec = {"agentA_roles": live["agentA"], "agentB_roles": live["agentB"],
           "held_only_by_callee": sorted(only_b),
           "connection_auth_type": tf.get("connection_auth_type"),
           "deployed_grant_a": deployed_grant_a}
    print(f"\ndeployed cell: auth={tf.get('connection_auth_type')} "
          f"grant_a={str(deployed_grant_a).lower()}  "
          f"(grant_a read from live RBAC, not from a variable)")

    os.makedirs(a.out, exist_ok=True)
    stamped, skipped = 0, 0
    for name in sorted(os.listdir(a.out)):
        if not name.endswith(".json"):
            continue
        fp = os.path.join(a.out, name)
        cell = json.load(open(fp))
        same_auth = str(cell.get("auth", "")).lower() == str(
            tf.get("connection_auth_type", "")).lower()
        same_grant = bool(cell.get("grant_a")) == deployed_grant_a
        if not (same_auth and same_grant):
            skipped += 1
            continue
        cell["rbac_verified"] = rec
        json.dump(cell, open(fp, "w"), indent=2)
        stamped += 1
    print(f"rbac_verified written to {stamped} cell(s); {skipped} cell(s) left "
          f"alone because they are a different deployment")

    # The reading must agree with what that cell predicted, or one of the two
    # is wrong and that is worth knowing before anything is written up.
    if deployed_grant_a and only_b:
        print("\nWARNING: agentA already holds the role, so there is nothing to "
              "gain, yet the callee holds something the caller does not. Check "
              "the lab.")
    if not deployed_grant_a and not only_b:
        print("\nWARNING: agentA does not hold the role and neither does "
              "agentB hold anything extra. The escalation has no target. "
              "Check that azurerm_role_assignment.agentB_secret applied.")
    if a.json:
        json.dump(rec, open(a.json, "w"), indent=2)
        print(f"written: {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

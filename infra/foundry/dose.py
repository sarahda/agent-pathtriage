#!/usr/bin/env python3
"""
Dose-response: does the size of what is gained track what the callee holds.

The binary matrix shows that passthrough turns the escalation on. It does not
show that the escalation is the callee's permissions flowing to the caller
rather than some artifact of the setting. A reviewer can dismiss one on-off
observation in one lab; a proportional response is much harder to explain away.

But only when the proportionality is MEASURED. Run without a live attempt, the
analyser's `gained` is defined as the callee's roles minus the caller's own, so
with a thin caller it equals the callee's roles and tracks the dose
arithmetically. That tells you the deployment applied what it said and the
state was read correctly; it tells you nothing about Azure. The harness keeps
`gained` and `observed` in separate fields for this reason, and the summary
refuses to let the first be read as the second.

The dose is how many roles agentB holds: 1, then 2, then 3. The prediction,
written before the run:

  passthrough   gained grows by one each step, and every gained role is one
                agentB holds
  OBO           gained stays empty at every dose

A step costs one deployment. The scopes already exist in the lab, so nothing
new is created: only the role assignment.

Usage:
  az login
  python3 dose.py --tfdir . --agents agents.json --out dose/ --auth AccountManagedIdentity
  python3 dose.py --tfdir . --agents agents.json --out dose/ --auth AgentUserImpersonation
  python3 dose.py --out dose/ --summary
"""
import argparse, json, os, subprocess, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(_HERE)),
                                "agentpathtriage"))
sys.path.insert(0, _HERE)

DOSES = (0, 1, 2)          # extra roles beyond the baseline, so 1, 2, 3 total


def apply(tfdir, auth, extra, extra_vars):
    cmd = ["terraform", f"-chdir={tfdir}", "apply", "-auto-approve",
           "-var", f"connection_auth_type={auth}",
           "-var", "grant_agentA_secret_access=false",
           "-var", f"agentB_extra_roles={extra}"]
    for v in extra_vars:
        cmd += ["-var", v]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        raise SystemExit(
            f"terraform apply failed at dose {extra + 1} (exit {e.returncode}). "
            "If the message says RequestDisallowedByAzure, add "
            "--var location=<allowed region>. Doses already recorded are kept; "
            "run the same command again to continue.")
    return json.loads(subprocess.check_output(
        ["terraform", f"-chdir={tfdir}", "show", "-json"]))


def summarise(out_dir):
    rows = []
    for name in sorted(os.listdir(out_dir)):
        if name.endswith(".json"):
            rows.append(json.load(open(os.path.join(out_dir, name))))
    if not rows:
        print("no doses recorded yet")
        return 1

    print(f"{'auth':26s} {'dose':5s} {'callee holds':13s} {'gained':7s} "
          f"{'gained is a subset of what the callee holds'}")
    print("-" * 100)
    for r in sorted(rows, key=lambda x: (x["auth"], x["dose"])):
        held, gained = set(r["callee_roles"]), set(r["gained"])
        subset = "yes" if gained <= held else "NO"
        print(f"{r['auth'][:26]:26s} {r['dose']:<5d} {len(held):<13d} "
              f"{len(gained):<7d} {subset if gained else '-'}")

    print("\nper auth level, does the gained set track the dose:")
    ok = True
    for auth in sorted({r["auth"] for r in rows}):
        series = sorted((r["dose"], len(r["gained"]))
                        for r in rows if r["auth"] == auth)
        doses = [d for d, _ in series]
        gains = [g for _, g in series]
        if all(g == 0 for g in gains):
            verdict = "flat at zero, which is the control"
        elif gains == doses:
            verdict = "one for one with the dose"
        elif all(b >= a for a, b in zip(gains, gains[1:])) and gains[-1] > gains[0]:
            verdict = "rises with the dose but not one for one"
        else:
            verdict = "DOES NOT TRACK, look at this"
            ok = False
        print(f"   {auth:26s} dose {doses} -> gained {gains}   {verdict}")

    n = len({(r['auth'], r['dose']) for r in rows})
    live = sum(1 for r in rows if r.get("observed"))
    print(f"\n{n} cell(s) recorded, {live} with a live attempt.")

    if live < n:
        print("""
READ THIS BEFORE CITING THE TABLE ABOVE.

With no live attempt, the one-for-one column is arithmetic, not evidence. The
analyser computes

    gained = (caller's own roles | callee's roles) - caller's own roles

so when the caller holds nothing, gained EQUALS what the callee holds, by
definition. Raising the callee from 1 role to 3 therefore moves gained from 1
to 3 whatever Azure does, and the control arm sits at zero because `inherited`
is the empty set when the auth type is not passthrough. Neither column can come
out any other way.

What these runs do establish, which is worth something but is not the claim:
Terraform really applied one, two and three distinct roles in a live
subscription, and the analyser read that live state correctly.

The dose becomes evidence when the LIVE side is measured: does agentA actually
reach one, then two, then three resources. Record each with

    python3 matrix.py --out <dir> --observed <cell>:reached|blocked

and only then does the proportionality say anything about the platform rather
than about this program's arithmetic.""")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tfdir")
    ap.add_argument("--agents", default="agents.json")
    ap.add_argument("--out", default="dose")
    ap.add_argument("--auth")
    ap.add_argument("--var", action="append", default=[], metavar="NAME=VALUE")
    ap.add_argument("--summary", action="store_true")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    if a.summary:
        return summarise(a.out)
    if not (a.tfdir and a.auth):
        ap.error("give --tfdir and --auth, or --summary")

    import foundry_cp as F
    import matrix as M
    agents = json.load(open(a.agents))

    for extra in DOSES:
        dose = extra + 1
        path = os.path.join(a.out, f"{a.auth}__dose{dose}.json")
        if os.path.exists(path):
            print(f"=== {a.auth} dose {dose}: already recorded, skipping ===")
            continue
        print(f"\n=== {a.auth}, agentB holds {dose} role(s) ===")
        state = apply(a.tfdir, a.auth, extra, a.var)
        f = M.analyse_cell(state, agents, mediated=False)

        identities, _p2i, roles, _conns = F.parse(state)
        callee = agents["agents"][1]["identity"]
        caller = agents["agents"][0]["identity"]
        held = sorted(F.redact(f"{r} @ {s}")
                      for (r, s) in F.roles_of(callee, identities, roles))
        own = sorted(F.redact(f"{r} @ {s}")
                     for (r, s) in F.roles_of(caller, identities, roles))
        gained = sorted({g for e in f["escalations"] for g in e["gained_roles"]})

        rec = {"auth": a.auth, "dose": dose,
               "expected": ("gained should equal the dose"
                            if M.is_passthrough(a.auth)
                            else "gained should stay empty"),
               "callee_roles": held, "caller_roles": own, "gained": gained,
               "findings": f, "observed": None}
        json.dump(rec, open(path, "w"), indent=2)
        print(f"  callee holds {len(held)}, caller holds {len(own)}, "
              f"gained {len(gained)}")

    print()
    return summarise(a.out)


if __name__ == "__main__":
    sys.exit(main())

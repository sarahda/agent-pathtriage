#!/usr/bin/env python3
"""
Foundry cross-agent matrix: vary one factor at a time and record what flips.

Why a matrix and not repeated runs. Terraform and the analyser are both
deterministic, so running the same configuration twice produces a byte-identical
result. Five identical runs is still n=1, and a reviewer who notices that
discounts the whole table. What buys a causal claim is crossing the factors, so
the effect can be attributed to one of them, and including the cells where the
effect should NOT appear.

Three factors, and only two of them cost a deployment:

  auth      the connection's authType. A Terraform variable, so a deploy.
  grant_a   whether Agent A already holds the sensitive role. A Terraform
            variable, so a deploy. This is the falsification factor: under
            passthrough with grant_a on, there is no GAIN, because A already
            had it. A tool that still reports escalation here is reporting
            passthrough rather than escalation.
  mediated  whether the invocation is brokered per call. This lives in the
            agent topology (agents.json), not in Terraform, so every deployed
            state is analysed under both values at no extra deployment cost.

With 2 auth levels and 2 grant levels that is 4 deployments and 8 cells. Adding
a third auth level costs 2 more deployments and gives 12 cells.

What the matrix does and does not show. It shows which factor the ANALYSER's
verdict depends on. It does not show that the escalation is reachable in a live
call: that needs the exploit probe, recorded separately with --observed, and the
summary marks any cell whose prediction has not been confirmed live.

Usage:
  # enumerate the plan without touching Azure
  python3 matrix.py --plan

  # run it (terraform apply per deployment cell, then analyse both topologies)
  python3 matrix.py --tfdir . --agents agents.json --out runs/

  # record what a live exploit attempt actually did, per cell
  python3 matrix.py --out runs/ --observed auth=AccountManagedIdentity,grant_a=false,mediated=false:reached
  python3 matrix.py --out runs/ --summary
"""
import argparse, itertools, json, os, re, subprocess, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(_HERE)), "agentpathtriage"))

DEFAULT_AUTH = ["AccountManagedIdentity", "AgentUserImpersonation"]
GRANT = [False, True]
MEDIATED = [False, True]


def cells(auth_levels):
    """Every cell, with the deployment it belongs to.

    Cells sharing a deployment key are analysed from one apply.
    """
    out = []
    for auth, grant, med in itertools.product(auth_levels, GRANT, MEDIATED):
        out.append({"auth": auth, "grant_a": grant, "mediated": med,
                    "deploy_key": f"{auth}__grant{int(grant)}"})
    return out


def cell_id(c):
    return f"auth={c['auth']},grant_a={str(c['grant_a']).lower()},mediated={str(c['mediated']).lower()}"


def is_passthrough(auth):
    """Does this authType route the call under the callee's identity.

    Taken from foundry_cp rather than restated here. This is a FACT about
    Azure, not the claim under test, so sharing it is not circular: what
    `expected` must encode independently is the INFERENCE (passthrough and
    unmediated and not already granted implies escalation), and that stays
    below.

    Restating it was a real defect. `auth != "AgentUserImpersonation"` agreed
    with the analyser on the two default levels and disagreed on every other
    one, so adding a third level would have produced a wrong prediction in a
    table whose whole purpose is to compare prediction against result.
    """
    from foundry_cp import auth_class
    return auth_class(auth) == "passthrough"


def auth_is_unknown(auth):
    from foundry_cp import auth_class
    return auth_class(auth) == "unknown"


def expected(c):
    """What the model says should happen, written down BEFORE the run.

    Recording the prediction separately from the result is what makes the table
    a test rather than a description. A cell where observed disagrees with
    expected is the interesting one.
    """
    if auth_is_unknown(c["auth"]):
        # A level whose identity routing is not documented gets no prediction.
        # Writing one anyway would put a guess in the column that exists to be
        # compared against the result.
        return "UNKNOWN: this authType is not classified, run it and see"
    passthrough = is_passthrough(c["auth"])
    if not passthrough:
        return "no gain: the call does not run as the callee"
    if c["mediated"]:
        return "no gain: the invocation is brokered per call"
    if c["grant_a"]:
        return "no gain: A already holds the role, so nothing is gained"
    return "ESCALATION: A inherits B's role"


class DeployFailed(Exception):
    """A terraform failure with the remedy attached, not a stack trace."""


def apply(tfdir, auth, grant, extra_vars=()):
    cmd = ["terraform", f"-chdir={tfdir}", "apply", "-auto-approve",
           "-var", f"connection_auth_type={auth}",
           "-var", f"grant_agentA_secret_access={str(grant).lower()}"]
    for v in extra_vars:
        cmd += ["-var", v]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        raise DeployFailed(
            f"terraform apply failed for auth={auth} grant_a={grant} "
            f"(exit {e.returncode}). If the message above says "
            f"RequestDisallowedByAzure, the location is not one your "
            f"subscription allows: add --var location=<allowed region>. "
            f"A region policy refuses at apply time, so the preflight plan "
            f"cannot catch it.") from None
    except FileNotFoundError:
        raise DeployFailed("terraform is not on PATH") from None
    return json.loads(subprocess.check_output(
        ["terraform", f"-chdir={tfdir}", "show", "-json"]))


def preflight(tfdir, extra_vars=()):
    """Check the credential before spending four deployments discovering it.

    An Azure CLI refresh token lasts hours, and a matrix run takes longer than
    one impatient sitting. Finding out on deployment three that the token died
    costs the two deployments already done, so it is checked once up front.
    """
    try:
        cmd = ["terraform", f"-chdir={tfdir}", "plan",
               "-refresh=true", "-detailed-exitcode"]
        for v in extra_vars:
            cmd += ["-var", v]
        subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        return "terraform is not on PATH"
    except subprocess.CalledProcessError as e:
        out = (e.output or b"").decode("utf-8", "ignore")
        if e.returncode == 2:
            return None               # 2 means there are changes to apply
        if "AADSTS70043" in out or "refresh token has expired" in out:
            m = re.search(r'az login --tenant "([^"]+)"', out)
            tenant = m.group(1) if m else "<your tenant>"
            return ("the Azure CLI token has expired. Run:\n"
                    f'    az logout && az login --tenant "{tenant}" '
                    '--scope "https://management.azure.com/.default"')
        if "building AzureRM Client" in out or "no credentials" in out.lower():
            return "no Azure credentials. Run: az login"
        if "RequestDisallowedByAzure" in out:
            return ("the subscription's region policy refused the location. "
                    "Pass an allowed region, for example:\n"
                    "    --var location=australiaeast")
        tail = "\n      ".join(out.strip().splitlines()[-6:])
        return f"terraform plan failed:\n      {tail}"
    return None


def analyse_cell(state, agents, mediated):
    import foundry_cp as F
    a = json.loads(json.dumps(agents))
    for inv in a.get("invocations", []):
        inv["mediated"] = mediated
    return F.analyse(state, a)


def summarise(out_dir):
    rows = []
    for name in sorted(os.listdir(out_dir)):
        if not name.endswith(".json"):
            continue
        rows.append(json.load(open(os.path.join(out_dir, name))))
    if not rows:
        print("no cells recorded yet")
        return 1

    print(f"{'auth':26s} {'grantA':7s} {'med':6s} {'esc':4s} {'CP-1':5s} "
          f"{'observed':10s} agrees")
    print("-" * 86)
    disagreements, unconfirmed = 0, 0
    for r in sorted(rows, key=lambda x: (x["auth"], x["grant_a"], x["mediated"])):
        esc = r["findings"]["escalations"]
        pred_esc = len(esc) > 0
        obs = r.get("observed")
        if obs is None:
            agrees, unconfirmed = "not run", unconfirmed + 1
        else:
            ok = (obs == "reached") == pred_esc
            agrees = "yes" if ok else "NO"
            disagreements += 0 if ok else 1
        print(f"{r['auth'][:26]:26s} {str(r['grant_a']):7s} {str(r['mediated']):6s} "
              f"{str(pred_esc):4s} {str(r['findings']['cp']['CP-1']):5s} "
              f"{str(obs or '-'):10s} {agrees}")

    print(f"\ncells: {len(rows)}   live-confirmed: {len(rows) - unconfirmed}   "
          f"prediction disagreed with observation: {disagreements}")

    # Which factor the verdict tracks. Two different questions, and conflating
    # them is how a matrix gets over-read: a level that always prevents the
    # escalation is not the same as a level that always causes it.
    print("\nper factor level:")
    for factor in ("auth", "grant_a", "mediated"):
        groups = {}
        for r in rows:
            groups.setdefault(str(r[factor]), set()).add(
                len(r["findings"]["escalations"]) > 0)
        notes = []
        for level, verdicts in sorted(groups.items()):
            if verdicts == {False}:
                notes.append(f"{level}: always prevents")
            elif verdicts == {True}:
                notes.append(f"{level}: always causes")
            else:
                notes.append(f"{level}: depends on the others")
        print(f"   {factor:9s} " + ";  ".join(notes))
    print("\nRead it this way. A level that ALWAYS PREVENTS is sufficient on its "
          "own to stop the escalation, so it is a usable control. A level that "
          "ALWAYS CAUSES would be sufficient on its own to create it. A factor "
          "can be the first without being the second, and usually is: the "
          "escalation needs every precondition at once, while removing any one "
          "of them is enough to stop it. Several independent controls is a "
          "stronger result than one decisive switch, and it is also the claim "
          "to make in the paper, because it is the one the table supports.")
    if unconfirmed:
        print(f"\n{unconfirmed} cell(s) carry a PREDICTION with no live attempt. "
              "Until --observed is recorded they are static analysis, not "
              "measured exploitability, and must be written up that way.")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tfdir")
    ap.add_argument("--agents", default="agents.json")
    ap.add_argument("--out", default="runs")
    ap.add_argument("--auth", help="comma separated auth levels to cross",
                    default=",".join(DEFAULT_AUTH))
    ap.add_argument("--plan", action="store_true", help="print the cells and exit")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--observed", help="CELL_ID:reached|blocked, from a live attempt")
    ap.add_argument("--skip-preflight", action="store_true",
                    help="do not check the credential first")
    ap.add_argument("--force", action="store_true",
                    help="redeploy cells that are already recorded")
    ap.add_argument("--var", action="append", default=[], metavar="NAME=VALUE",
                    help="extra terraform variable, repeatable. The lab's "
                         "location default may not be a region your "
                         "subscription allows: --var location=australiaeast")
    a = ap.parse_args()

    auth_levels = [x.strip() for x in a.auth.split(",") if x.strip()]
    plan = cells(auth_levels)

    if a.plan:
        deploys = sorted({c["deploy_key"] for c in plan})
        print(f"{len(plan)} cells from {len(deploys)} deployments\n")
        for c in plan:
            print(f"  {cell_id(c):62s} {expected(c)}")
        print(f"\ndeployments needed: {len(deploys)}")
        for d in deploys:
            print(f"  {d}")
        return 0

    os.makedirs(a.out, exist_ok=True)

    if a.observed:
        cid, _, verdict = a.observed.partition(":")
        if verdict not in ("reached", "blocked"):
            ap.error("observed must end in :reached or :blocked")
        path = os.path.join(a.out, cid.replace(",", "__").replace("=", "-") + ".json")
        if not os.path.exists(path):
            ap.error(f"no such cell recorded: {path}")
        rec = json.load(open(path))
        rec["observed"] = verdict
        json.dump(rec, open(path, "w"), indent=2)
        print(f"recorded {verdict} for {cid}")
        return 0

    if a.summary:
        return summarise(a.out)

    if not a.tfdir:
        ap.error("give --tfdir to run the matrix, or --plan / --summary")

    agents = json.load(open(a.agents))

    if not a.skip_preflight:
        print("preflight: checking the Azure credential before deploying ...")
        problem = preflight(a.tfdir, a.var)
        if problem:
            print(f"\nPREFLIGHT FAILED: {problem}\n", file=sys.stderr)
            print("Nothing was deployed. Fix the above and run the same command "
                  "again; cells already recorded are kept.", file=sys.stderr)
            return 1
        print("preflight: ok\n")

    by_deploy = {}
    for c in plan:
        by_deploy.setdefault(c["deploy_key"], []).append(c)

    def cell_path(c):
        return os.path.join(a.out,
                            cell_id(c).replace(",", "__").replace("=", "-") + ".json")

    done, failed = 0, None
    for key, group in by_deploy.items():
        # resume: a deployment whose cells are all recorded is not repeated, so
        # a credential that dies midway costs the remaining deployments only
        if all(os.path.exists(cell_path(c)) for c in group) and not a.force:
            print(f"=== {key}: already recorded, skipping (use --force to redo) ===")
            done += 1
            continue
        auth, grant = group[0]["auth"], group[0]["grant_a"]
        print(f"\n=== deploying {key} ===")
        try:
            state = apply(a.tfdir, auth, grant, a.var)
        except DeployFailed as e:
            failed = str(e)
            break
        for c in group:
            f = analyse_cell(state, agents, c["mediated"])
            rec = {"auth": c["auth"], "grant_a": c["grant_a"],
                   "mediated": c["mediated"], "expected": expected(c),
                   "findings": f, "observed": None}
            json.dump(rec, open(cell_path(c), "w"), indent=2)
            print(f"  {cell_id(c):62s} esc={len(f['escalations'])}")
        done += 1

    print()
    if failed:
        print(f"STOPPED: {failed}", file=sys.stderr)
        print(f"{done}/{len(by_deploy)} deployments completed and recorded. "
              f"Re-run the same command to continue from here.", file=sys.stderr)
        summarise(a.out)
        return 1
    return summarise(a.out)


if __name__ == "__main__":
    sys.exit(main())

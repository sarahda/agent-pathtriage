#!/usr/bin/env python3
"""
AgentPathTriage - external benchmark scorer (score_benchmark v2)

Scores the engine against BishopFox IAM-Vulnerable over the whole benchmark rather
than a chosen subset, and against the benchmark author's own tool-testing cases.

What changed from v1 (run_benchmark.py):
  - v1 compared this project's propagate against this project's check, which is the
    same codebase with a feature switched off, and it scored 11 principals chosen in
    advance. v2 scores every privesc path the benchmark ships and states, per class,
    why a path is in or out of scope.
  - v1 needed a deployed account. v2 runs on raw .tf through tf_to_state.
  - the scope class of each path is derived from that path's own policy at scoring
    time, not from a hand-maintained list that can drift away from the benchmark.

Scope rule, stated once and applied mechanically:
  a delegation-reachability model covers escalations where the attacker OBTAINS
  ANOTHER IDENTITY. Classes:

    delegation         iam:PassRole or sts:AssumeRole. IN SCOPE, must be found.
    policy-selfmod     rewriting policy or group membership for an identity the
                       attacker already holds. OUT OF SCOPE: no second identity is
                       obtained, the existing one is widened.
    credential         minting credentials for an existing principal. OUT OF SCOPE
                       for the same reason.
    resource-takeover  seizing an existing resource that already runs as a role, for
                       example lambda:UpdateFunctionCode or glue:UpdateDevEndpoint.
                       OUT OF SCOPE TODAY and reported as the single named coverage
                       gap, because the attacker does obtain another identity's
                       reach here, just not by being handed the identity.

Precision is measured on the benchmark author's designed false positives (fp1 to
fp5), not on cases chosen by this project. The designed false negatives (fn1 to fn4)
are reported one by one, because each names a specific analysis weakness.

Usage:
  python3 tf_to_state.py --tfdir path/to/iam-vulnerable --json iv_state.json
  python3 ../../agentpathtriage/reach.py --state iv_state.json --json iv_reach.json
  python3 score_benchmark.py --state iv_state.json --reach iv_reach.json
"""
import argparse, collections, json, re

DELEGATION = re.compile(r"^(iam:PassRole|sts:AssumeRole)$", re.I)
SELFMOD = re.compile(r"^iam:(CreatePolicyVersion|SetDefaultPolicyVersion|Attach\w+Policy"
                     r"|Put\w+Policy|AddUserToGroup|UpdateAssumeRolePolicy)$", re.I)
CREDENTIAL = re.compile(r"^iam:(CreateAccessKey|CreateLoginProfile|UpdateLoginProfile)$", re.I)
TAKEOVER = re.compile(r"^(lambda:UpdateFunctionCode|lambda:UpdateFunctionConfiguration"
                      r"|glue:UpdateDevEndpoint|cloudformation:UpdateStack|ssm:SendCommand"
                      r"|ssm:StartSession|ec2-instance-connect:\w+"
                      r"|sagemaker:CreatePresignedNotebookInstanceUrl)$", re.I)

IN_SCOPE = "delegation"
OUT_OF_SCOPE = ("policy-selfmod", "credential")
GAP_CLASS = "resource-takeover"


def granted_actions(state):
    """principal name -> the set of allowed action strings, from its own policies."""
    res = []
    root = state.get("values", {}).get("root_module", {})
    res.extend(root.get("resources", []))
    stack = list(root.get("child_modules", []))
    while stack:
        m = stack.pop()
        res.extend(m.get("resources", []))
        stack.extend(m.get("child_modules", []))

    managed = {}
    for r in res:
        if r["type"] == "aws_iam_policy":
            managed[r["values"].get("arn")] = r["values"].get("policy")

    def stmts(doc):
        if not doc:
            return []
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except Exception:
                return []
        s = doc.get("Statement", []) if isinstance(doc, dict) else []
        return s if isinstance(s, list) else [s]

    out = collections.defaultdict(set)
    for r in res:
        v = r["values"]
        t = r["type"]
        if t in ("aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment"):
            owner = v.get("role") or v.get("user")
            if not owner:
                continue
            owner = str(owner).rsplit("/", 1)[-1]
            for s in stmts(managed.get(v.get("policy_arn"))):
                if str(s.get("Effect", "Allow")).lower() != "allow":
                    continue
                a = s.get("Action", [])
                out[owner].update(str(x) for x in (a if isinstance(a, list) else [a]))
        elif t in ("aws_iam_role_policy", "aws_iam_user_policy"):
            owner = str(v.get("role") or v.get("user") or r["name"]).rsplit("/", 1)[-1]
            for s in stmts(v.get("policy")):
                if str(s.get("Effect", "Allow")).lower() != "allow":
                    continue
                a = s.get("Action", [])
                out[owner].update(str(x) for x in (a if isinstance(a, list) else [a]))
    return out


def classify(actions):
    cls = []
    if any(DELEGATION.match(a) for a in actions):
        cls.append("delegation")
    if any(SELFMOD.match(a) for a in actions):
        cls.append("policy-selfmod")
    if any(CREDENTIAL.match(a) for a in actions):
        cls.append("credential")
    if any(TAKEOVER.match(a) for a in actions):
        cls.append("resource-takeover")
    return cls or ["other"]


def path_name(principal):
    """Strip the -user / -role suffix so a path is counted once, not twice."""
    return re.sub(r"-(user|role\d*)$", "", principal)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--reach", required=True)
    ap.add_argument("--json")
    a = ap.parse_args()

    state = json.load(open(a.state))
    reach = json.load(open(a.reach))
    # The benchmark asks whether the tool reports this privilege escalation path, not
    # whether it files it under delegation. A path is found when the tool produces
    # any finding for it, and the two classes are reported separately below so the
    # delegation number stays a delegation number.
    flagged = {r["principal"]: bool(r["Esc"] or r.get("self_escalation"))
               for r in reach["results"]}
    by_delegation = {r["principal"]: bool(r["Esc"]) for r in reach["results"]}
    by_self = {r["principal"]: bool(r.get("self_escalation")) for r in reach["results"]}
    classic = {r["principal"]: r["Esc_classic"] for r in reach["results"]}
    actions = granted_actions(state)

    paths = collections.defaultdict(lambda: {"principals": [], "classes": set()})
    for p in flagged:
        if not p.startswith("privesc") or p.startswith(("privesc-high-priv",)):
            continue
        cls = classify(actions.get(p, set()))
        if cls == ["other"] and not actions.get(p):
            continue
        key = path_name(p)
        paths[key]["principals"].append(p)
        paths[key]["classes"].update(cls)

    rows = []
    for name, info in sorted(paths.items()):
        hit = any(flagged.get(p) for p in info["principals"])
        rows.append({"path": name, "classes": sorted(info["classes"]),
                     "principals": sorted(info["principals"]), "flagged": hit,
                     "flagged_classic": any(classic.get(p) for p in info["principals"])})

    def bucket(r):
        if IN_SCOPE in r["classes"]:
            return "in scope"
        if GAP_CLASS in r["classes"]:
            return "known gap"
        if any(c in OUT_OF_SCOPE for c in r["classes"]):
            return "out of scope"
        return "unclassified"

    print(f"IAM-Vulnerable: {len(rows)} privesc paths found in the benchmark source\n")
    print(f"{'path':56s} {'bucket':13s} {'classes':34s} {'found':>5s} {'old':>4s}")
    print("-" * 118)
    for r in sorted(rows, key=lambda x: (bucket(x), x["path"])):
        print(f"{r['path'][:56]:56s} {bucket(r):13s} {','.join(r['classes'])[:34]:34s} "
              f"{str(r['flagged']):>5s} {str(r['flagged_classic']):>4s}")

    by = collections.defaultdict(lambda: [0, 0])
    for r in rows:
        b = by[bucket(r)]
        b[0] += 1
        b[1] += 1 if r["flagged"] else 0
    print("\nper bucket (paths found / paths present):")
    for k in ("in scope", "known gap", "out of scope", "unclassified"):
        if k in by:
            tot, hit = by[k]
            print(f"   {k:14s} {hit}/{tot}")

    inscope = [r for r in rows if bucket(r) == "in scope"]
    recall = sum(1 for r in inscope if r["flagged"]) / len(inscope) if inscope else 1.0

    fp = [p for p in flagged if re.match(r"^fp\d", p)]
    fp_bad = [p for p in fp if flagged[p]]
    fn = sorted(p for p in flagged if re.match(r"^fn\d", p))
    tp = sum(1 for r in inscope if r["flagged"])
    precision = tp / (tp + len(fp_bad)) if (tp + len(fp_bad)) else 1.0

    print(f"\nin-scope recall:  {recall:.3f}  ({tp}/{len(inscope)} delegation paths)")
    print(f"precision on the author's designed false positives: {precision:.3f} "
          f"({len(fp) - len(fp_bad)}/{len(fp)} fp cases correctly not flagged)")
    if fp_bad:
        print(f"   wrongly flagged: {sorted(fp_bad)}")
    print("\nfinding class of each path that was found:")
    cls = collections.Counter()
    for r in rows:
        if not r["flagged"]:
            continue
        d = any(by_delegation.get(p) for p in r["principals"])
        s = any(by_self.get(p) for p in r["principals"])
        cls["delegation" if d and not s else "self-escalation" if s and not d else "both"] += 1
    for k, v in cls.most_common():
        print(f"   {k:18s} {v}")

    print("\nauthor's designed false negatives, one by one:")
    for p in fn:
        why = "delegation" if by_delegation.get(p) else (
            "self-escalation" if by_self.get(p) else "-")
        print(f"   {p:52s} found={str(flagged[p]):5s} as {why}")
    caught = sum(1 for p in fn if flagged[p])
    print(f"   caught {caught}/{len(fn)}")

    if a.json:
        json.dump({"paths": rows, "in_scope_recall": recall,
                   "fp_precision": precision,
                   "fp_cases": {p: flagged[p] for p in sorted(fp)},
                   "fn_cases": {p: flagged[p] for p in fn}},
                  open(a.json, "w"), indent=2)
        print(f"\nwritten: {a.json}")


if __name__ == "__main__":
    main()

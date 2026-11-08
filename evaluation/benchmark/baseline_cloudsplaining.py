#!/usr/bin/env python3
"""
AgentPathTriage - independent baseline (baseline_cloudsplaining)

The previous baseline was this project's own check.py with propagation switched
off, which is a self-comparison: both arms read a graph this project built, and
the escalating principals in the benchmark are users whose own policy holds no
wildcard action, so the baseline was close to guaranteed to score zero. A reviewer
is right to discount that.

Cloudsplaining (Salesforce, BSD-3) is an independent tool with its own privilege
escalation detector and its own catalogue of named paths. It is a fair comparison
because it is solving a related problem with a different method: it judges one
policy document at a time, while this project reasons over reachability between
principals. Running both on the same configuration shows where the difference
actually lies, rather than asserting it.

Both tools are given exactly the same input: each principal's combined policy
document, built from the same state file.

Usage:
  python3 baseline_cloudsplaining.py --state iv_state.json --reach iv_reach.json
"""
import argparse, collections, json

from cloudsplaining.scan.policy_document import PolicyDocument


def iter_resources(state):
    root = state.get("values", {}).get("root_module", {})
    for r in root.get("resources", []):
        yield r["type"], r["name"], r.get("values", {})
    stack = list(root.get("child_modules", []))
    while stack:
        m = stack.pop()
        for r in m.get("resources", []):
            yield r["type"], r["name"], r.get("values", {})
        stack.extend(m.get("child_modules", []))


def as_doc(policy):
    if isinstance(policy, str):
        try:
            return json.loads(policy)
        except Exception:
            return None
    return policy if isinstance(policy, dict) else None


def combined_policies(state):
    """principal name -> one policy document holding every statement it is granted."""
    managed, inline, attached, kinds = {}, collections.defaultdict(list), \
        collections.defaultdict(list), {}
    rows = list(iter_resources(state))
    for t, n, v in rows:
        if t == "aws_iam_policy":
            managed[v.get("arn")] = as_doc(v.get("policy"))
    for t, n, v in rows:
        if t in ("aws_iam_role", "aws_iam_user"):
            kinds[v.get("name") or n] = "role" if t == "aws_iam_role" else "user"
        elif t in ("aws_iam_role_policy", "aws_iam_user_policy"):
            owner = str(v.get("role") or v.get("user") or n).rsplit("/", 1)[-1]
            d = as_doc(v.get("policy"))
            if d:
                inline[owner].extend(d.get("Statement", []))
        elif t in ("aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment"):
            owner = str(v.get("role") or v.get("user") or "").rsplit("/", 1)[-1]
            if owner:
                attached[owner].append(v.get("policy_arn"))
    out = {}
    for name in kinds:
        stmts = list(inline.get(name, []))
        for arn in attached.get(name, []):
            d = managed.get(arn)
            if d:
                stmts.extend(d.get("Statement", []))
        if stmts:
            out[name] = {"Version": "2012-10-17", "Statement": stmts}
    return out, kinds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--reach", required=True)
    ap.add_argument("--json")
    a = ap.parse_args()

    state = json.load(open(a.state))
    # same counting rule as score_benchmark: a principal is flagged when the tool
    # reports either class of finding, delegation or self escalation. Two scripts
    # answering the same question differently is how numbers drift apart.
    ours = {r["principal"]: bool(r["Esc"] or r.get("self_escalation"))
            for r in json.load(open(a.reach))["results"]}
    docs, kinds = combined_policies(state)

    rows = []
    for name, doc in sorted(docs.items()):
        try:
            pd = PolicyDocument(doc)
            paths = pd.allows_privilege_escalation
        except Exception as exc:                      # a policy it cannot parse
            paths = []
            rows.append({"principal": name, "error": str(exc)})
            continue
        rows.append({"principal": name, "kind": kinds.get(name),
                     "cloudsplaining": bool(paths),
                     "path_types": sorted({p["type"] for p in paths}),
                     "agentpathtriage": bool(ours.get(name))})

    both = [r for r in rows if r.get("cloudsplaining") and r.get("agentpathtriage")]
    only_cs = [r for r in rows if r.get("cloudsplaining") and not r.get("agentpathtriage")]
    only_us = [r for r in rows if r.get("agentpathtriage") and not r.get("cloudsplaining")]

    print(f"principals with a readable policy: {len(docs)}")
    print(f"flagged by Cloudsplaining:   {sum(1 for r in rows if r.get('cloudsplaining'))}")
    print(f"flagged by AgentPathTriage:  {sum(1 for r in rows if r.get('agentpathtriage'))}")
    print(f"   both: {len(both)}   only Cloudsplaining: {len(only_cs)}   only AgentPathTriage: {len(only_us)}\n")

    for label, group in (("found by BOTH", both),
                         ("found ONLY by Cloudsplaining", only_cs),
                         ("found ONLY by AgentPathTriage", only_us)):
        print(f"--- {label} ({len(group)}) ---")
        for r in group:
            types = ",".join(r.get("path_types", [])) or "-"
            print(f"   {r['principal'][:58]:58s} {types[:60]}")
        print()

    if a.json:
        json.dump({"rows": rows, "both": len(both), "only_cloudsplaining": len(only_cs),
                   "only_agentpathtriage": len(only_us)}, open(a.json, "w"), indent=2)
        print(f"written: {a.json}")


if __name__ == "__main__":
    main()

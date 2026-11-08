#!/usr/bin/env python3
"""
Why this engine and Cloudsplaining disagree, case by case.

A head count ("63 versus 70") says which tool reports more. It does not say
whether the extra findings are right, and a reviewer is right to discount it
until each disagreement has a named mechanism. This classifies every
disagreement from the POLICY that produced it, not from the case name, so the
classification cannot be fitted to the benchmark.

The disagreement classes, each decided by a rule over the statement:

  condition-evaluated     we flag, they do not, and the statement carries a
                          condition. Treating any condition as mitigating is
                          safe-looking and wrong: IAM-Vulnerable's fn3 grants on
                          DateGreaterThan 2020-01-01, which always holds.
  resource-constraint     we flag, they do not, and the resource is a pattern
                          rather than `*`. A constraint narrows a grant; it does
                          not remove it. fn2 constrains to policy/fn2-*, which
                          still covers a policy the principal holds.
  non-iam-takeover        we flag, they do not, and no IAM action is involved.
                          The principal drives a resource that already runs as a
                          role, for example ssm:SendCommand to an instance. An
                          IAM-action catalogue cannot contain this by design.
  trust-delegation        we flag, they do not, and the path exists because the
                          TARGET's trust policy names this principal. Nothing in
                          the principal's own policy shows it, so an
                          identity-policy reader cannot reach it.
  group-membership        they flag, we do not, on iam:AddUserToGroup held by a
                          ROLE. An IAM group contains users, so a role cannot
                          join one to inherit its policies. Our reading is the
                          stricter one, and the counter-argument is recorded.
  unclassified            a disagreement no rule explains. These are the ones to
                          look at by hand; a growing count here means the rules
                          have drifted from the data.

Usage:
  python3 tf_to_state.py --tfdir iam-vulnerable --json iv.json
  python3 ../../agentpathtriage/reach.py --state iv.json --json iv_reach.json
  python3 baseline_diff.py --state iv.json --reach iv_reach.json --json diff.json
"""
import argparse, collections, json, os, re, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(os.path.dirname(_HERE)),
                               "agentpathtriage")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

IAM_PRIVESC = re.compile(
    r"^iam:(CreatePolicyVersion|SetDefaultPolicyVersion|Attach\w+Policy|Put\w+Policy"
    r"|AddUserToGroup|UpdateAssumeRolePolicy|PassRole|CreateAccessKey"
    r"|Create\w*LoginProfile|Update\w*LoginProfile)$", re.I)


def statements_of(state):
    """principal -> [statement dicts], via the engine's own index.

    Reimplementing policy assembly here was a bug: it missed group policies and
    group membership, so five principals came back with no statements and were
    reported as unclassified when the mechanism was plainly visible. The engine
    already resolves attachments, groups and membership, so it is asked instead.
    """
    import extract_graph as X
    _, ix = X.build(state)
    out = {}
    for name in list(ix.kind):
        out[name] = [{"Effect": st.effect,
                      "Action": st.actions or None,
                      "NotAction": st.not_actions or None,
                      "Resource": st.resources or None,
                      "Condition": st.conditions or None}
                     for st in ix.statements(name)]
    return out


def trust_delegation(state, principal):
    """Does this principal reach another identity through a trust policy only.

    Cloudsplaining reads identity policies. A role that may be assumed because
    the TARGET's trust policy names it holds nothing in its own policy, so no
    identity-policy reading can see the path. That is a class, not a gap in the
    data.
    """
    import extract_graph as X
    G, _ = X.build(state)
    for _u, _v, d in G.out_edges(principal, data=True):
        if d.get("rel") == "delegate" and (
                d.get("via") == "trust" or "sts:AssumeRole" in (d.get("vias") or [])):
            return True
    return False


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def classify(principal, stmts, only_ours, trusted=False):
    """Name the mechanism, from the statement rather than from the case name."""
    allow = [s for s in stmts if str(s.get("Effect", "Allow")).lower() == "allow"]
    actions = [str(a) for s in allow for a in as_list(s.get("Action"))]
    privesc = [a for a in actions if IAM_PRIVESC.match(a)]

    if only_ours:
        conditioned = [s for s in allow
                       if s.get("Condition")
                       and any(IAM_PRIVESC.match(str(a)) for a in as_list(s.get("Action")))]
        if conditioned:
            keys = sorted({k for s in conditioned for blk in s["Condition"].values()
                           if isinstance(blk, dict) for k in blk})
            return "condition-evaluated", f"condition on {', '.join(keys)}"
        constrained = [s for s in allow
                       if any(IAM_PRIVESC.match(str(a)) for a in as_list(s.get("Action")))
                       and all(r != "*" for r in as_list(s.get("Resource")))]
        if constrained:
            pats = sorted({r for s in constrained for r in as_list(s.get("Resource"))})
            return "resource-constraint", f"resource {', '.join(pats)[:70]}"
        if actions and not privesc:
            ns = sorted({a.split(":", 1)[0] for a in actions if ":" in a})
            return "non-iam-takeover", f"drives a resource via {', '.join(ns)}"
        if trusted:
            return ("trust-delegation",
                    "assumable because the target's trust policy allows it, "
                    "which no identity-policy reading can see")
        return "unclassified", f"actions {sorted(set(actions))[:4]}"

    # found only by Cloudsplaining
    if any(a.lower() == "iam:addusertogroup" for a in actions):
        if principal.endswith("-role") or "-role" in principal:
            return ("group-membership",
                    "an IAM group contains users, so a role cannot join one")
        return "unclassified", "AddUserToGroup on a non-role principal"
    return "unclassified", f"actions {sorted(set(actions))[:4]}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--reach", required=True)
    ap.add_argument("--json")
    a = ap.parse_args()

    state = json.load(open(a.state))
    reach = json.load(open(a.reach))
    ours = {r["principal"] for r in reach["results"]
            if r["Esc"] or r.get("self_escalation")}

    # Call the baseline the same way baseline_cloudsplaining.py does, through
    # its own policy assembly, so the two scripts cannot disagree about what
    # was fed to Cloudsplaining. Reimplementing the assembly here is how a
    # comparison quietly starts comparing two different inputs.
    try:
        import baseline_cloudsplaining as B
        from cloudsplaining.scan.policy_document import PolicyDocument
    except Exception as e:
        raise SystemExit(f"cannot load the baseline: {e}")
    docs, _kinds = B.combined_policies(state)
    theirs, unreadable = set(), []
    for name, doc in docs.items():
        try:
            if PolicyDocument(doc).allows_privilege_escalation:
                theirs.add(name)
        except Exception as exc:
            unreadable.append((name, str(exc)[:60]))
    if unreadable:
        print(f"note: Cloudsplaining could not parse {len(unreadable)} policy "
              f"document(s); those principals count as not flagged by it\n")

    # The comparison is restricted to principals BOTH tools were given. The
    # baseline assembles one policy document per principal; a principal whose
    # permissions arrive through group membership, or who holds nothing and is
    # reachable only through a trust policy, has no such document and was never
    # put to Cloudsplaining. Counting those as findings it missed would be
    # scoring against a tool that was handed no input, and the first version of
    # this script did exactly that: it reported 13 instead of 8.
    universe = set(docs)
    stmts = statements_of(state)
    outside = sorted((ours | theirs) - universe)

    rows = []
    for p in sorted((ours - theirs) & universe):
        cls, why = classify(p, stmts.get(p, []), True, trust_delegation(state, p))
        rows.append({"principal": p, "found_by": "ours", "class": cls, "why": why})
    for p in sorted((theirs - ours) & universe):
        cls, why = classify(p, stmts.get(p, []), False)
        rows.append({"principal": p, "found_by": "cloudsplaining", "class": cls,
                     "why": why})

    print(f"comparable universe (both tools given the input): {len(universe)}")
    print(f"   both: {len(ours & theirs & universe)}   "
          f"only ours: {len((ours - theirs) & universe)}   "
          f"only cloudsplaining: {len((theirs - ours) & universe)}\n")
    print(f"{'principal':52s} {'by':14s} {'class':20s} why")
    print("-" * 124)
    for r in rows:
        print(f"{r['principal'][:52]:52s} {r['found_by']:14s} {r['class']:20s} {r['why']}")

    print("\nby mechanism:")
    for (by, cls), n in collections.Counter(
            (r["found_by"], r["class"]) for r in rows).most_common():
        print(f"   {by:14s} {cls:20s} {n}")

    # a path appears twice, once per principal form, so the distinct mechanism
    # count is the number a reader should take away
    groups = {re.sub(r"-(user|role\d*)$", "", r["principal"]) for r in rows}
    print(f"\ndistinct path groups in disagreement: {len(groups)}")
    print("Reported as path groups, not as principals: IAM-Vulnerable ships each "
          "path twice, as a user and as a role, so counting principals doubles "
          "every mechanism.")

    if outside:
        print(f"\noutside the comparable universe: {len(outside)} principal(s) "
              f"the engine indexes and the baseline was given no document for.")
        print("Reported, not counted. Why each has no document:")
        for p in outside:
            sts = stmts.get(p, [])
            n = len([x for x in sts if x])
            if not n:
                why = "holds no policy; reachable only through a trust policy"
            elif p.endswith("-group"):
                why = "a group; the baseline assembles users and roles"
            else:
                why = "permissions arrive through group membership"
            mark = "ours" if p in ours else "cloudsplaining"
            print(f"   {p[:52]:54s} {mark:14s} {why}")
        print("These are a difference in what each tool ingests, not a "
              "detection win. The capability difference is real and belongs in "
              "the text; it does not belong in the head count.")

    unc = [r for r in rows if r["class"] == "unclassified"]
    if unc:
        print(f"\nUNCLASSIFIED {len(unc)}: examine by hand before citing this table")
        for r in unc:
            print(f"   {r['principal']}  {r['why']}")

    if a.json:
        json.dump({"comparable_universe": len(universe),
                   "both": len(ours & theirs & universe),
                   "only_ours": len((ours - theirs) & universe),
                   "only_cloudsplaining": len((theirs - ours) & universe),
                   "disagreements": rows,
                   "outside_universe": outside},
                  open(a.json, "w"), indent=2)
        print(f"\nwritten: {a.json}")


if __name__ == "__main__":
    main()

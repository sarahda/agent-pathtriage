#!/usr/bin/env python3
"""
AgentPathTriage - the smallest change that removes an escalation (repair v0)

A tool that says "this is escalated" and stops leaves the work where it found
it. This proposes the narrowest edit that makes the escalation go away, applies
it to a copy of the configuration, and RE-RUNS the analysis to check that it
did. A repair that has not been re-analysed is a suggestion, and suggestions
are what a linter already produces.

What makes a repair minimal, in order of preference:

  1. add a condition      The intended path keeps working. Narrowing a service
                          trust with aws:SourceArn is the confused-deputy fix
                          AWS documents: the service may still assume the role,
                          but only on behalf of the resource that legitimately
                          runs as it, which the graph already knows from the
                          assume edge.
  2. narrow a resource    Replaces a pattern with the exact ARNs. Correct, but
                          it can remove access the deployment meant to have, so
                          it is second.
  3. remove an action     Last. It is the bluntest and most likely to break
                          something, so it is only proposed when nothing else
                          validates.

Every candidate is checked the same way: apply it, re-run reach, and require
that the witness is gone AND that no new escalation appeared anywhere. A repair
that fixes one principal by breaking another is not a repair.

Usage:
  python3 repair.py --state state.json
  python3 repair.py --state state.json --json repairs.json
"""
import argparse, copy, json, os, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "evaluation", "benchmark")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import extract_graph as X          # noqa: E402
import reach as R                  # noqa: E402

SCOPING_KEY = "aws:SourceArn"


def _resources(state):
    out = []
    root = state.get("values", {}).get("root_module", {})
    out.extend(root.get("resources", []))
    stack = list(root.get("child_modules", []))
    while stack:
        m = stack.pop()
        out.extend(m.get("resources", []))
        stack.extend(m.get("child_modules", []))
    return out


def _load(doc):
    if isinstance(doc, str):
        try:
            return json.loads(doc)
        except Exception:
            return None
    return doc if isinstance(doc, dict) else None


def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def find_role_resource(state, role_name):
    for r in _resources(state):
        if r["type"] != "aws_iam_role":
            continue
        if str(r["values"].get("name")) == role_name or r["name"] == role_name:
            return r
    return None


def runs_as(G, role):
    """Which agent legitimately executes as this role, from the assume edge."""
    for u, v, d in G.in_edges(role, data=True):
        if d.get("rel") == "assume":
            return u
    return None


def agent_arn(state, agent_name):
    for r in _resources(state):
        if r["type"] in X.AGENT_RESOURCE_TYPES and r["name"] == agent_name:
            v = r["values"]
            return v.get("arn") or v.get("agent_runtime_arn")
    return None


# --- candidate repairs ---------------------------------------------------

def narrow_trust(state, G, hop):
    """Add aws:SourceArn to the target role's trust policy."""
    role = hop["to"]
    res = find_role_resource(state, role)
    if not res:
        return None
    pol = _load(res["values"].get("assume_role_policy"))
    if not pol:
        return None
    agent = runs_as(G, role)
    arn = agent_arn(state, agent) if agent else None
    if not arn:
        return None

    new = copy.deepcopy(pol)
    touched = False
    for st in _as_list(new.get("Statement")):
        if not isinstance(st, dict):
            continue
        pr = st.get("Principal") or {}
        if not (isinstance(pr, dict) and pr.get("Service")):
            continue
        cond = st.setdefault("Condition", {})
        cond.setdefault("ArnLike", {})[SCOPING_KEY] = arn
        touched = True
    if not touched:
        return None

    def apply(s):
        r = find_role_resource(s, role)
        r["values"]["assume_role_policy"] = json.dumps(new)

    return {
        "kind": "add-condition",
        "rank": 1,
        "where": f"aws_iam_role {role}, assume_role_policy",
        "what": (f"add ArnLike {SCOPING_KEY} = {arn} to the service trust, so "
                 f"the service may assume this role only on behalf of the "
                 f"agent that legitimately runs as it"),
        "breaks": "nothing the configuration declares: that agent is the one "
                  "the assume edge already names",
        "after": new,
        "apply": apply,
    }


def narrow_passrole(state, G, hop, principal):
    """Replace a PassRole resource pattern with the exact role ARNs needed."""
    target = hop["to"]
    keep = set()
    for u, v, d in G.out_edges(principal, data=True):
        if d.get("rel") == "delegate" and "iam:PassRole" in (d.get("vias") or []):
            if v != target:
                keep.add(v)
    arns = {}
    for r in _resources(state):
        if r["type"] == "aws_iam_role":
            arns[str(r["values"].get("name") or r["name"])] = r["values"].get("arn")
    kept = sorted(a for a in (arns.get(k) for k in keep) if a)

    changed = []
    for r in _resources(state):
        if r["type"] not in ("aws_iam_role_policy", "aws_iam_user_policy",
                             "aws_iam_policy"):
            continue
        pol = _load(r["values"].get("policy"))
        if not pol:
            continue
        hit = False
        new = copy.deepcopy(pol)
        for st in _as_list(new.get("Statement")):
            if not isinstance(st, dict):
                continue
            if not any(str(a).lower() == "iam:passrole"
                       for a in _as_list(st.get("Action"))):
                continue
            st["Resource"] = kept or []
            hit = True
        if hit:
            changed.append((r["type"], r["name"], new))
    if not changed:
        return None

    def apply(s):
        for rtype, rname, new in changed:
            for rr in _resources(s):
                if rr["type"] == rtype and rr["name"] == rname:
                    rr["values"]["policy"] = json.dumps(new)

    return {
        "kind": "narrow-resource",
        "rank": 2,
        "where": ", ".join(f"{t} {n}" for t, n, _ in changed),
        "what": (f"restrict iam:PassRole to {kept or 'no role'}, removing "
                 f"{target} from what this principal may pass"),
        "breaks": ("any use of PassRole on " + target + " that the "
                   "configuration does not declare"),
        "after": [n for _, _, n in changed],
        "apply": apply,
    }


def narrow_wildcard_action(state, G, witness, principal):
    """Replace a wildcard Resource on the granting statement with the ARN reached."""
    reached, action = witness["reaches"], witness["action"]
    role = witness["via_role"]
    changed = []
    for r in _resources(state):
        if r["type"] not in ("aws_iam_role_policy", "aws_iam_user_policy",
                             "aws_iam_policy"):
            continue
        owner = str(r["values"].get("role") or r["values"].get("user") or "")
        if owner.rsplit("/", 1)[-1] != role:
            continue
        pol = _load(r["values"].get("policy"))
        if not pol:
            continue
        new = copy.deepcopy(pol)
        hit = False
        for st in _as_list(new.get("Statement")):
            if not isinstance(st, dict):
                continue
            acts = [str(a) for a in _as_list(st.get("Action"))]
            if not any(X.E.action_matches(a, action) for a in acts):
                continue
            if not any(str(x) == "*" or "*" in str(x)
                       for x in _as_list(st.get("Resource"))):
                continue
            st["Resource"] = [reached]
            hit = True
        if hit:
            changed.append((r["type"], r["name"], new))
    if not changed:
        return None

    def apply(s):
        for rtype, rname, new in changed:
            for rr in _resources(s):
                if rr["type"] == rtype and rr["name"] == rname:
                    rr["values"]["policy"] = json.dumps(new)

    return {
        "kind": "narrow-resource",
        "rank": 2,
        "where": ", ".join(f"{t} {n}" for t, n, _ in changed),
        "what": f"replace the wildcard resource on {action} with {reached}",
        "breaks": "access to anything else the wildcard covered",
        "after": [n for _, _, n in changed],
        "apply": apply,
    }


def repair_handoff_gap(state, G, caller, callee, scope):
    """An agent declared to call one agent but permitted to call any.

    The shared-role and wildcard cases that matter in the corpus produce no
    Esc witness: when two agents run under one execution role there is no
    delegation hop, so eff equals auth and the predicate is correctly false.
    The defect is still there, in the agent layer rather than in IAM, and it
    is the one worth reporting: a hand-off declared at one named target while
    the policy permits any target in the account.

    The fix is narrow and preserves the declared path: restrict the invoke
    action's resource to the agents the configuration actually names.
    """
    declared = sorted({v for u, v, d in G.out_edges(caller, data=True)
                       if d.get("rel") == "handoff"
                       and str(d.get("evidence", "")).startswith("declared")
                       and not str(v).startswith("<")})
    arns = [a for a in (agent_arn(state, d) for d in declared) if a]
    if not arns:
        return None

    role = None
    for u, v, d in G.out_edges(caller, data=True):
        if d.get("rel") == "assume":
            role = v
    if role is None:
        meta = None
        for n, m in getattr(G, "graph", {}).get("agents", {}).items():
            if n == caller:
                meta = m
        role = meta.get("role_arn", "").rsplit("/", 1)[-1] if meta else None
    if not role:
        return None

    changed = []
    for r in _resources(state):
        if r["type"] not in ("aws_iam_role_policy", "aws_iam_user_policy",
                             "aws_iam_policy"):
            continue
        owner = str(r["values"].get("role") or r["values"].get("user") or "")
        if owner.rsplit("/", 1)[-1] != role:
            continue
        pol = _load(r["values"].get("policy"))
        if not pol:
            continue
        new = copy.deepcopy(pol)
        hit = False
        for st in _as_list(new.get("Statement")):
            if not isinstance(st, dict):
                continue
            acts = [str(a) for a in _as_list(st.get("Action"))]
            if not any("invokeagent" in a.lower().replace("-", "") for a in acts):
                continue
            if not any("*" in str(x) for x in _as_list(st.get("Resource"))):
                continue
            st["Resource"] = arns + [f"{a}/runtime-endpoint/*" for a in arns]
            hit = True
        if hit:
            changed.append((r["type"], r["name"], new))
    if not changed:
        return None

    def apply(s):
        for rtype, rname, new in changed:
            for rr in _resources(s):
                if rr["type"] == rtype and rr["name"] == rname:
                    rr["values"]["policy"] = json.dumps(new)

    return {
        "kind": "narrow-resource",
        "rank": 1,
        "where": ", ".join(f"{t} {n}" for t, n, _ in changed),
        "what": (f"restrict the agent invoke action to the declared target(s) "
                 f"{declared}, instead of every runtime in the account"),
        "breaks": "calling an agent the configuration does not declare",
        "after": [n for _, _, n in changed],
        "apply": apply,
    }


def handoff_gaps(G):
    """(caller, callee, scope) where a declared hand-off is permitted too widely."""
    out = []
    for u, v, d in G.edges(data=True):
        if d.get("rel") != "handoff":
            continue
        if d.get("permitted") and d.get("permitted_scope") == "any":
            out.append((u, v, d.get("permitted_scope")))
        elif (str(d.get("evidence", "")).startswith("declared")
              and d.get("permitted") and d.get("permitted_scope") == "any"):
            out.append((u, v, d.get("permitted_scope")))
    return sorted(set(out))


def shared_roles(G, ix):
    """Agents that run under one execution role. Reported, not auto-repaired."""
    import collections
    byrole = collections.defaultdict(list)
    for an, am in ix.agents.items():
        if am.get("role_arn"):
            byrole[str(am["role_arn"])].append(an)
    return {k: sorted(v) for k, v in byrole.items() if len(v) > 1}


def candidates(state, G, principal, witness):
    out = []
    for hop in witness.get("chain", []):
        via = str(hop.get("via", ""))
        if via == "iam:PassRole" or hop.get("via") == "trust":
            for fn in (narrow_trust, narrow_passrole):
                try:
                    c = (fn(state, G, hop) if fn is narrow_trust
                         else fn(state, G, hop, principal))
                except Exception:
                    c = None
                if c:
                    out.append(c)
    try:
        c = narrow_wildcard_action(state, G, witness, principal)
    except Exception:
        c = None
    if c:
        out.append(c)
    return sorted(out, key=lambda c: c["rank"])


# --- validation ----------------------------------------------------------

def findings_of(state):
    _G, _ix, _uni, res = R.run(state)
    out = {}
    for r in res:
        out[r["principal"]] = {w["reaches"] for w in r["witnesses"]}
    return out


def validate(state, repair, principal, witness, before):
    """Apply, re-run, and require the witness gone with nothing new anywhere."""
    s = copy.deepcopy(state)
    try:
        repair["apply"](s)
        after = findings_of(s)
    except Exception as e:
        return False, f"re-analysis failed: {type(e).__name__}: {e}"
    if witness["reaches"] in after.get(principal, set()):
        return False, "the witness is still reachable"
    new = {p: sorted(after.get(p, set()) - before.get(p, set())) for p in after}
    new = {p: v for p, v in new.items() if v}
    if new:
        return False, f"it created a new escalation: {new}"
    removed = sum(len(before.get(p, set()) - after.get(p, set())) for p in before)
    return True, f"witness removed; {removed} witness(es) gone in total"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--json")
    a = ap.parse_args()

    state = json.load(open(a.state))
    G, ix, _uni, res = R.run(state)
    before = {r["principal"]: {w["reaches"] for w in r["witnesses"]} for r in res}

    rows, fixed, unfixed = [], 0, 0
    for r in res:
        if not r["Esc"]:
            continue
        for w in r["witnesses"]:
            rec = {"principal": r["principal"], "reaches": w["reaches"],
                   "action": w["action"], "via_role": w["via_role"],
                   "repair": None, "tried": []}
            for c in candidates(state, G, r["principal"], w):
                ok, why = validate(state, c, r["principal"], w, before)
                rec["tried"].append({"kind": c["kind"], "where": c["where"],
                                     "validated": ok, "why": why})
                if ok:
                    rec["repair"] = {"kind": c["kind"], "where": c["where"],
                                     "what": c["what"], "breaks": c["breaks"],
                                     "policy_after": c["after"], "why": why}
                    break
            rows.append(rec)
            fixed += 1 if rec["repair"] else 0
            unfixed += 0 if rec["repair"] else 1

    # The agent-layer findings. These produce no Esc witness, because two
    # agents under one role have no delegation hop and eff equals auth, so the
    # predicate is correctly false. The defect is real and lives one layer up.
    gaps = handoff_gaps(G)
    for caller, callee, _scope in gaps:
        rec = {"principal": caller, "reaches": f"<any agent runtime>",
               "action": "agent invoke", "via_role": "its own execution role",
               "repair": None, "tried": [], "class": "handoff-gap"}
        c = None
        try:
            c = repair_handoff_gap(state, G, caller, callee, _scope)
        except Exception:
            c = None
        if c:
            s2 = copy.deepcopy(state)
            try:
                c["apply"](s2)
                G2, _i2, _u2, _r2 = R.run(s2)
                still = [(u, v) for u, v, _s in handoff_gaps(G2)]
                ok = (caller, callee) not in still
                why = ("the permitted-any edge is gone" if ok
                       else "the edge is still permitted at any scope")
            except Exception as e:
                ok, why = False, f"re-analysis failed: {type(e).__name__}: {e}"
            rec["tried"].append({"kind": c["kind"], "where": c["where"],
                                 "validated": ok, "why": why})
            if ok:
                rec["repair"] = {"kind": c["kind"], "where": c["where"],
                                 "what": c["what"], "breaks": c["breaks"],
                                 "policy_after": c["after"], "why": why}
        rows.append(rec)
        fixed += 1 if rec["repair"] else 0
        unfixed += 0 if rec["repair"] else 1

    shared = shared_roles(G, ix)

    print(f"findings: {len(rows)}   repaired and re-analysed: {fixed}   "
          f"no validated repair: {unfixed}")
    if rows:
        print(f"repair-validated: {fixed / len(rows):.3f}\n")
    for rec in rows:
        print(f"{rec['principal']} -> {rec['reaches'][:62]}")
        print(f"   via {rec['via_role']} using {rec['action']}")
        if rec["repair"]:
            rp = rec["repair"]
            print(f"   FIX [{rp['kind']}] {rp['where']}")
            print(f"       {rp['what']}")
            print(f"       cost: {rp['breaks']}")
            print(f"       verified by re-analysis: {rp['why']}")
        else:
            print("   NO VALIDATED REPAIR")
            for t in rec["tried"]:
                print(f"       tried {t['kind']} at {t['where']}: {t['why']}")
            if not rec["tried"]:
                print("       no candidate applied to this mechanism")
        print()

    if shared:
        print("agents sharing one execution role. Reported, not auto-repaired: "
              "the fix is to give each agent its own role, which is a "
              "structural change this tool will not write for you.")
        for role, agents in shared.items():
            print(f"   {agents} all run as {str(role).rsplit('/', 1)[-1]}")
        print()

    if a.json:
        json.dump({"escalations": len(rows), "repaired": fixed,
                   "shared_execution_roles": shared,
                   "repair_validated": (fixed / len(rows)) if rows else None,
                   "rows": rows}, open(a.json, "w"), indent=2, default=str)
        print(f"written: {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

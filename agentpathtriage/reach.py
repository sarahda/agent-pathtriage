#!/usr/bin/env python3
"""
AgentPathTriage - reachability and the escalation predicate (reach v1)

This is the predicate model/formal-spec.md section 4 defines, which the previous
check.py and propagate.py did not implement:

    auth(p) = resources p reaches under its own identity
    eff(p)  = resources p reaches through delegation hops as well
    Esc(p) <=> eff(p) \\ auth(p) != empty

The difference is the whole argument. A role that holds a wildcard permission but
can delegate to nobody has eff = auth, so it is NOT escalated under this predicate,
even though the old wildcard-edge predicate called it escalated. That case is
classic single-identity over-permissioning, which is exactly what this project
claims not to be about, so it must come out false here.

The old predicate is kept and reported beside the new one as `Esc_classic`, so the
change in results is visible rather than silent.

Resource universe
  Set difference needs resources, not resource types, or "reaches its own memory"
  and "reaches another agent's memory" collapse into one label. The universe is
  derived from the deployment: one representative resource of each agentic type per
  principal and per agent, plus every literal resource ARN written in any policy.
  Nothing is added that the configuration does not mention.

The deputy condition
  Holding iam:PassRole over a role is not by itself an escalation. The caller also
  has to be able to make something run as that role. A delegation edge is therefore
  marked `enabled` only when the caller can actually cause the target role to run:

    - sts:AssumeRole, where the target's trust policy admits the caller, or
    - iam:PassRole plus the ability to create or invoke a resource of a service the
      target role trusts, where that trust carries no condition narrowing it.

  The second case is the confused deputy in one line, and it is the mechanism behind
  the published AgentCore cross-agent escalations: an unconditioned service trust
  means the role can be carried by any resource of that service, not only the one it
  was written for.

Usage:
  python3 reach.py --state state.json
  python3 reach.py --state state.json --json reach.json
  python3 reach.py --state state.json --principal sandy
"""
import argparse, json, os, sys
import networkx as nx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import iam_eval as E
import extract_graph as X

# resource type -> (service, arn template, probe actions). Used to build the
# universe and to ask the evaluator the right question about each resource.
RESOURCE_KINDS = {
    "memory": ("bedrock-agentcore", "arn:aws:bedrock-agentcore:{region}:{acct}:memory/{owner}",
               ["bedrock-agentcore:GetMemoryRecord", "bedrock-agentcore:RetrieveMemoryRecords",
                "bedrock-agentcore:ListMemoryRecords", "bedrock-agentcore:CreateEvent"]),
    "runtime": ("bedrock-agentcore", "arn:aws:bedrock-agentcore:{region}:{acct}:runtime/{owner}",
                ["bedrock-agentcore:InvokeAgentRuntime"]),
    "code-interpreter": ("bedrock-agentcore",
                         "arn:aws:bedrock-agentcore:{region}:{acct}:code-interpreter/{owner}",
                         ["bedrock-agentcore:InvokeCodeInterpreter",
                          "bedrock-agentcore:StartCodeInterpreterSession"]),
    "gateway": ("bedrock-agentcore", "arn:aws:bedrock-agentcore:{region}:{acct}:gateway/{owner}",
                ["bedrock-agentcore:GetGatewayTarget", "bedrock-agentcore:ListGatewayTargets"]),
    "browser": ("bedrock-agentcore", "arn:aws:bedrock-agentcore:{region}:{acct}:browser/{owner}",
                ["bedrock-agentcore:InvokeBrowser", "bedrock-agentcore:StartBrowserSession"]),
    "repository": ("ecr", "arn:aws:ecr:{region}:{acct}:repository/{owner}",
                   ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]),
    "knowledge-base": ("bedrock", "arn:aws:bedrock:{region}:{acct}:knowledge-base/{owner}",
                       ["bedrock:Retrieve", "bedrock:RetrieveAndGenerate"]),
}
# Which actions let a caller make a service run something? An earlier version of
# this module answered with a hand-written list, written while looking at a
# benchmark. Removing from that list the actions the benchmark happens to use
# dropped in-scope recall from 11/11 to 1/11, which means the list was carrying the
# result rather than the method. It was the same defect this project criticised in
# gap.py's REQUIRED table.
#
# The question is now answered from AWS's own Service Authorization Reference,
# shipped offline by policy_sentry for 445 service prefixes: a caller can make a
# service act if it holds any Write-level action in that service's namespace. This
# over-approximates, which is the direction model/act-scope.md already commits to:
# flag a candidate rather than miss a path, and report it as a candidate.
_WRITE_CACHE = {}


def write_actions(service):
    """Write-level actions of a service, from the AWS reference, cached."""
    if service in _WRITE_CACHE:
        return _WRITE_CACHE[service]
    try:
        from policy_sentry.querying.actions import get_actions_with_access_level
        acts = get_actions_with_access_level(service, "Write") or []
    except Exception:
        acts = []
    _WRITE_CACHE[service] = acts
    return acts
CONTROL_PLANE = X.CONTROL_PLANE
REGION = "us-east-1"


def literal_resources(ix):
    """Every non-wildcard resource ARN written in any policy in the deployment."""
    out = set()
    for name in ix.kind:
        for st in ix.statements(name):
            for r in st.resources:
                if r and r != "*" and not E.has_wildcard(r) and str(r).startswith("arn:"):
                    out.add(r)
    return out


def concrete_actions_by_service(ix):
    """service -> the concrete action names this deployment actually writes.

    Probe actions have to be real action names: asking the evaluator about
    "s3:Get*" compares a pattern against a pattern and matches nothing. For the
    agentic types the probe list is fixed, but for every other service the probes
    are taken from the deployment's own policies, so nothing is invented and the
    universe stays derived from the configuration.
    """
    out = {}
    for name in ix.kind:
        for st in ix.statements(name):
            for a in list(st.actions) + list(st.not_actions):
                if not a or a == "*" or ":" not in a:
                    continue
                svc, _, verb = a.partition(":")
                if E.has_wildcard(verb) or not verb:
                    continue
                out.setdefault(svc, set()).add(a)
    return {k: sorted(v) for k, v in out.items()}


def build_universe(ix):
    """resource arn -> list of probe actions appropriate to it."""
    owners = sorted(set(ix.kind) | set(ix.agents))
    universe = {}
    for kind, (_svc, template, actions) in RESOURCE_KINDS.items():
        for owner in owners:
            arn = template.format(region=REGION, acct=ix.account, owner=owner)
            universe[arn] = list(actions)
    by_service = concrete_actions_by_service(ix)
    for arn in literal_resources(ix):
        acts = []
        for kind, (_svc, _t, actions) in RESOURCE_KINDS.items():
            if f":{kind}/" in arn:
                acts = list(actions)
                break
        if not acts:
            parts = arn.split(":")
            svc = parts[2] if len(parts) > 2 else ""
            acts = by_service.get(svc, [])
        if acts:
            universe.setdefault(arn, list(acts))
    return universe


def auth_set(ix, principal, universe):
    """{resource arn -> the action that reaches it} under this identity alone."""
    stmts = ix.statements(principal)
    if not stmts:
        return {}
    out = {}
    for arn, actions in universe.items():
        for a in actions:
            d = E.evaluate(stmts, a, arn)
            if d.allowed:
                out[arn] = {"action": a, "conditional": d.conditional}
                break
    if ix.is_admin_managed(principal):
        out[CONTROL_PLANE] = {"action": "* (admin managed)", "conditional": False}
    else:
        d = E.evaluate(stmts, "iam:CreateUser", f"arn:aws:iam::{ix.account}:user/anyone")
        if d.allowed and any(any(p in X.ADMIN_ACTIONS for p in s.actions)
                             and s.resource_is_wildcard() for s in d.allow_statements):
            out[CONTROL_PLANE] = {"action": "* (admin)", "conditional": d.conditional}
    return out


def can_run_service(ix, principal, service):
    """Can this principal make `service` execute something? The deputy test.

    True when the principal holds any Write-level action in the service, judged by
    the real policy evaluator so a Deny still removes it. Returns the first such
    action, which becomes the human-readable reason on the edge.
    """
    stmts = ix.statements(principal)
    if not stmts:
        return None
    wildcard_arn = f"arn:aws:{service}:{REGION}:{ix.account}:*"
    for a in write_actions(service):
        if E.evaluate(stmts, a, "*").allowed or E.evaluate(stmts, a, wildcard_arn).allowed:
            return a
    return None


def trust_admits(ix, caller, target):
    """Does the target role's trust policy let this caller assume it?

    Returns (admitted, reason). Only an AWS principal can be a role or a user.
    A service principal is a different mechanism and is handled by the PassRole
    branch, which also checks that the caller can make that service act.

    The account root is a real admission: naming it delegates the decision to
    identity policies, so a principal in that account holding sts:AssumeRole on
    the role can assume it.
    """
    entries = ix.trust.get(target)
    if not entries:
        return False, "the target has no trust policy in the configuration"
    arn = ix.arn.get(caller) or ""
    root = f"arn:aws:iam::{ix.account}:root"
    services = 0
    for e in entries:
        if str(e.get("kind", "")).lower() != "aws":
            services += 1
            continue
        v = str(e.get("value", ""))
        if v == "*":
            return True, "the trust policy admits any principal"
        if v == root or v == ix.account:
            return True, "the trust policy names the account root"
        if arn and v == arn:
            return True, "the trust policy names this principal"
        if arn and E.glob_match(v, arn):
            return True, "the trust policy matches this principal"
    if services:
        return False, ("the target's trust policy names only a service "
                       "principal, so this principal cannot assume it")
    return False, "no trust policy entry on the target names this principal"


def services_trusting(G, role, unscoped_only=True):
    out = []
    for u, v, d in G.in_edges(role, data=True):
        if d.get("rel") == "trusts" and (not unscoped_only or not d.get("scoped")):
            out.append(u)
    return out


def enable_delegations(G, ix):
    """Mark each delegate edge with whether the caller can actually use it."""
    for u, v, d in G.edges(data=True):
        if d.get("rel") != "delegate":
            continue
        why = None
        if "sts:AssumeRole" in d.get("vias", []) or d.get("via") == "trust":
            # Holding sts:AssumeRole is only half of it. A role can be assumed
            # only by a principal its trust policy names, so an identity policy
            # allowing sts:AssumeRole on * reaches nothing whose trust names a
            # service and no AWS principal. The PassRole branch below already
            # tests the trust side. This branch did not, and sts:AssumeRole on
            # * is common enough in real configurations that the missing test
            # produced an edge from such a principal to every role in the
            # template. An edge that fails here is kept and marked, not
            # dropped, so "the grant is there and no trust accepts it" stays
            # visible.
            if d.get("via") == "trust":
                # this edge was built from the trust side, so it is admitted
                why = "assume-role"
            else:
                ok, reason = trust_admits(ix, u, v)
                if ok:
                    why = f"assume-role ({reason})"
                else:
                    d["blocked_by"] = reason
        if why is None:
            # rewriting an identity's permissions, minting its credentials, joining
            # a group or rewriting a role's trust needs no further ability: the
            # identity is obtained by the action itself
            direct = next((v for v in d.get("vias", []) if str(v).split(":")[0]
                           in ("control", "become", "join", "retrust")), None)
            if direct:
                why = str(direct)
        if why is None and any(str(v).startswith("takeover:") for v in d.get("vias", [])):
            # the deputy already exists and already runs as the target role, so no
            # further ability to start the service is required
            act = next(v for v in d["vias"] if str(v).startswith("takeover:"))
            why = f"{act} on {d.get('takeover_resource')}"
        if why is None and "iam:PassRole" in d.get("vias", []):
            for svc in services_trusting(G, v, unscoped_only=True):
                service = svc.split(".")[0]
                act = can_run_service(ix, u, service)
                if act:
                    why = f"passrole + {act} on {svc} (trust not narrowed)"
                    break
        d["enabled"] = why is not None
        d["enabled_by"] = why


def reachable(G, start):
    """BFS over enabled delegate edges. Returns {role: [hop, ...]}."""
    seen = {start}
    frontier = [(start, [])]
    out = {}
    while frontier:
        node, path = frontier.pop(0)
        for _, tgt, d in G.out_edges(node, data=True):
            if d.get("rel") != "delegate" or tgt in seen or not d.get("enabled"):
                continue
            seen.add(tgt)
            hop = {"from": node, "to": tgt, "via": "/".join(d.get("vias", [])),
                   "scope": d.get("scope"), "enabled_by": d.get("enabled_by")}
            out[tgt] = path + [hop]
            frontier.append((tgt, path + [hop]))
    return out


SELF_ESCALATION_MARK = "(via iam:"

# Walk hand-off edges as well as delegate edges. Off by default so the figure
# published before 2026-11-01 stays reproducible; `--invoke-reach` turns it on.
INVOKE_REACH = False


def agent_arns(ix):
    """Every ARN that is an agent runtime, so one can be told from a prize."""
    out = set()
    for meta in ix.agents.values():
        raw = meta.get("raw") or {}
        for key in ("arn", "agent_runtime_arn", "agent_arn"):
            if raw.get(key):
                out.add(str(raw[key]))
    return out


def invocation_hops(G, ix, principal):
    """Roles reachable from this one by invoking agents, transitively.

    A delegate hop borrows an identity. An invocation hop does not: the caller
    stays itself and the callee acts with its own authority on the caller's
    behalf. Reach grows either way, which is what the predicate is about, so
    the two are merged in `analyse` and each hop records which kind it was.

    Only a hand-off the caller is permitted to make is taken. A declared
    hand-off without the permission fails at run time and is not reach.
    """
    role_of_agent, agents_of_role = {}, {}
    for name, meta in ix.agents.items():
        ref = meta.get("role_arn")
        if not ref:
            continue
        role = ix._owner_name(ref)
        role_of_agent[name] = role
        agents_of_role.setdefault(role, []).append(name)

    out, seen = {}, {principal}
    frontier = [(principal, [])]
    while frontier:
        role, path = frontier.pop(0)
        for agent in agents_of_role.get(role, []):
            if agent not in G:
                continue
            for _, callee, d in G.out_edges(agent, data=True):
                if d.get("rel") != "handoff" or not d.get("permitted"):
                    continue
                target = role_of_agent.get(callee)
                if not target or target in seen:
                    continue
                seen.add(target)
                hop = {"from": role, "to": target, "via": "invoke",
                       "scope": d.get("permitted_scope"),
                       "kind": "invocation",
                       "caller_agent": agent, "callee_agent": callee,
                       "evidence": d.get("evidence"),
                       "enabled_by": d.get("permitted_action")}
                out[target] = path + [hop]
                frontier.append((target, path + [hop]))
    return out


def control_plane_edges(G, principal):
    """Wildcard act edges this principal has to the control plane, from the graph.

    auth_set evaluates policies; the graph also records reach that comes from being
    able to rewrite one's own permissions. Those are the same question answered in
    two places, so the graph's answer is folded in here rather than recomputed.
    """
    if principal not in G:
        return []
    return [d for _, t, d in G.out_edges(principal, data=True)
            if d.get("rel") == "act" and d.get("wildcard") and t == CONTROL_PLANE]


def analyse(G, ix, principal, universe, auth_cache):
    auth = auth_cache.setdefault(principal, auth_set(ix, principal, universe))
    cp = control_plane_edges(G, principal)
    if cp and CONTROL_PLANE not in auth:
        auth[CONTROL_PLANE] = {"action": cp[0].get("action", "*"),
                               "conditional": bool(cp[0].get("conditional"))}
    hops = reachable(G, principal)
    if INVOKE_REACH:
        # A role reachable both ways keeps the shorter path, so a finding
        # names the cheapest way the reach was obtained.
        for role, path in invocation_hops(G, ix, principal).items():
            if role not in hops or len(path) < len(hops[role]):
                hops[role] = path
    eff = dict(auth)
    gained = {}
    for role, path in hops.items():
        a = auth_cache.setdefault(role, auth_set(ix, role, universe))
        for arn, meta in a.items():
            if arn in auth:
                continue
            if arn not in gained or len(path) < len(gained[arn]["chain"]):
                gained[arn] = {"via_role": role, "chain": path, "action": meta["action"],
                               "conditional": meta["conditional"]}
            eff[arn] = meta
    classic = any(
        d.get("rel") == "act" and d.get("wildcard")
        for _, _, d in G.out_edges(principal, data=True)) if principal in G else False

    # an escalation whose extent cannot be measured from configuration: a role the
    # principal can reach carries an AWS-managed policy whose document is not in the
    # config, and the principal does not already carry it
    own_unreadable = set(ix.unreadable_managed(principal))
    unreadable_gained = {}
    for role in hops:
        extra = set(ix.unreadable_managed(role)) - own_unreadable
        if extra:
            unreadable_gained[role] = sorted(extra)

    # Rewriting one's own permissions reaches everything, but it reaches it under
    # this identity, so eff equals auth and Esc is correctly false. It is still an
    # escalation and still has to be reported, as its own class: the delegation
    # predicate answers "did a hand-off give this principal more", and this answers
    # "can this principal give itself more". Keeping them apart is what lets the
    # delegation number stay about delegation.
    self_esc = [d.get("action") for d in cp if SELF_ESCALATION_MARK in str(d.get("action"))]

    # Reaching another agent is a hop, not a prize. A three-tier orchestrator
    # where each tier may invoke the next and no tier holds anything else is
    # not two escalations, and counting agent runtimes as witnesses would make
    # it two. The agents reached are still reported, because the path matters.
    agents = agent_arns(ix)
    gained_agents = {a: w for a, w in gained.items() if a in agents}
    gained_data = {a: w for a, w in gained.items() if a not in agents}

    # A universe entry is either a resource the configuration writes or one
    # synthesised per owner to probe how broad a grant is. A witness naming a
    # synthesised resource says the grant would cover such a resource, not that
    # one exists, so the two are counted apart and a finding can quote only the
    # ones that exist. Computed once per index rather than per principal.
    lits = getattr(ix, "_literal_resources", None)
    if lits is None:
        lits = literal_resources(ix)
        try:
            ix._literal_resources = lits
        except Exception:
            pass
    gained_literal = {a: w for a, w in gained_data.items() if a in lits}

    return {
        "principal": principal,
        "kind": ix.kind.get(principal),
        "n_auth": len(auth),
        "n_eff": len(eff),
        "Esc": len(gained_data) > 0,
        "invoke_reach": INVOKE_REACH,
        "n_gained_agents": len(gained_agents),
        "agents_reached": sorted(gained_agents),
        "n_gained_literal": len(gained_literal),
        "n_gained_probe": len(gained_data) - len(gained_literal),
        "gained_literal": sorted(gained_literal),
        "self_escalation": bool(self_esc),
        "self_escalation_via": sorted(set(self_esc)),
        "Esc_unquantified": bool(unreadable_gained) and not gained,
        "unreadable_managed_gained": unreadable_gained,
        "Esc_classic": classic,
        "changed_vs_classic": (len(gained) > 0) != classic,
        "delegation_hops": len(hops),
        "witnesses": [
            {"reaches": arn, "action": w["action"], "via_role": w["via_role"],
             "hops": len(w["chain"]), "chain": w["chain"],
             "conditional": w["conditional"],
             "via_invocation": any(h.get("kind") == "invocation"
                                   for h in w["chain"]),
             "literal": arn in lits}
            for arn, w in sorted(gained_data.items())
        ],
    }


def run(state, managed=None):
    G, ix = X.build(state, managed)
    enable_delegations(G, ix)
    universe = build_universe(ix)
    cache = {}
    results = [analyse(G, ix, p, universe, cache) for p in sorted(ix.kind)]
    return G, ix, universe, results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--principal")
    ap.add_argument("--json")
    ap.add_argument("--invoke-reach", action="store_true", dest="invoke_reach",
                    help="also follow permitted hand-off edges, so a caller "
                         "that can invoke a more privileged agent gains its "
                         "reach. Off by default, because the figures "
                         "published before 2026-11-01 were produced without "
                         "it and have to stay reproducible")
    ap.add_argument("--expand-managed", nargs="?", const="default",
                    dest="expand_managed", metavar="SNAPSHOT",
                    help="expand AWS managed policies from a snapshot, so a "
                         "role attaching one is credited with what it grants. "
                         "With no path, the snapshot shipped in "
                         "agentpathtriage/data is used. Off by default, "
                         "because the figures published before 2026-11-02 were "
                         "produced without it and have to stay reproducible")
    a = ap.parse_args()
    if a.invoke_reach:
        globals()["INVOKE_REACH"] = True
    state = json.load(open(a.state))

    # A run that meant to expand and quietly did not would report the old
    # number under a new name, so a missing snapshot is an error here.
    managed = None
    if a.expand_managed:
        import managed_policies as MP
        snap = MP.load(a.expand_managed, required=True)
        managed = snap.statements
        print(f"managed policy expansion: {snap.describe()}")
        print()

    G, ix, universe, results = run(state, managed)

    if a.principal:
        results = [r for r in results if r["principal"] == a.principal]

    print(f"resource universe: {len(universe)} resources derived from the deployment")
    shared = X.shared_trust_groups(G)
    for svc, roles in shared.items():
        print(f"shared unconditioned trust: {svc} -> {len(roles)} roles")
    print()
    print(f"{'principal':46s} {'kind':5s} {'auth':>5s} {'eff':>5s} {'Esc':>6s} {'classic':>8s}")
    print("-" * 82)
    for r in results:
        flag = "  <-- differs" if r["changed_vs_classic"] else ""
        print(f"{r['principal'][:46]:46s} {str(r['kind']):5s} {r['n_auth']:5d} "
              f"{r['n_eff']:5d} {str(r['Esc']):>6s} {str(r['Esc_classic']):>8s}{flag}")
    print()
    unq = [r for r in results if r.get("Esc_unquantified")]
    if unq:
        print("escalations whose extent cannot be measured from configuration")
        print("(the reached role carries an AWS-managed policy whose document is not in the config):")
        for r in unq:
            for role, pols in r["unreadable_managed_gained"].items():
                print(f"   {r['principal']} reaches {role}, which carries {', '.join(pols)}")
        print()

    for r in results:
        if not r["Esc"]:
            continue
        print(f"{r['principal']}: Esc = True, {len(r['witnesses'])} resource(s) reached only via delegation")
        for w in r["witnesses"][:6]:
            chain = " ".join(f"{h['from']} =={h['via']}[{h['scope']}]==> {h['to']}"
                             for h in w["chain"])
            print(f"    {chain}  --{w['action']}-->  {w['reaches']}")
            if w["chain"]:
                print(f"       enabled by: {w['chain'][-1]['enabled_by']}")
        if len(r["witnesses"]) > 6:
            print(f"    ... and {len(r['witnesses']) - 6} more")
    if a.json:
        json.dump({"n_universe": len(universe),
                   "shared_trust": {k: sorted(v) for k, v in shared.items()},
                   "results": results}, open(a.json, "w"), indent=2)
        print(f"\nwritten: {a.json}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
AgentPathTriage - findings report (report v1)

The engine already computes more than it says out loud. This turns its output into
the thing that distinguishes it from a policy linter: not a flag, but the resources
a principal can reach, the identity it reaches them through, and the hand-off that
makes the reach possible.

Five things a linter cannot give, and this does:

  1. the reached resources, named, per principal
  2. risk split into what the principal already holds under its own identity, and
     what only exists because of delegation. The first is what a linter finds and
     this report says so plainly. The second is the contribution.
  3. relationships between roles, in particular roles that are interchangeable
     because one service trusts all of them with nothing narrowing the grant
  4. admin-grade principals marked as such and dropped from the chain findings,
     because an identity that already reaches everything gains nothing by chaining.
     This falls out of the predicate rather than being a special case: eff equals
     auth, so the difference is empty.
  5. for every finding, the chain that produced it

Findings are ranked by what they would cost: how many resources are gained, then how
few hops it takes, then whether the reach is unconditional.

Usage:
  python3 report.py --state state.json
  python3 report.py --state state.json --json findings.json --md findings.md
"""
import argparse, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extract_graph as X
import reach as R

CONTROL_PLANE = X.CONTROL_PLANE


def own_policy_risk(ix, principal, G):
    """What a single-policy linter would see: wildcard-scoped grants this principal
    holds under its own identity, with no delegation involved."""
    out = []
    for _, tgt, d in G.out_edges(principal, data=True):
        if d.get("rel") == "act" and d.get("wildcard"):
            out.append({"reaches_type": tgt,
                        "actions": d.get("actions", [d.get("action")]),
                        "scope": d.get("scope")})
    return out


def is_admin(ix, principal, auth_resources):
    return CONTROL_PLANE in auth_resources or ix.is_admin_managed(principal)


def build(state):
    G, ix = X.build(state)
    R.enable_delegations(G, ix)
    universe = R.build_universe(ix)
    cache = {}
    results = [R.analyse(G, ix, p, universe, cache) for p in sorted(ix.kind)]
    shared = X.shared_trust_groups(G)

    trust_of = {}
    for svc, roles in shared.items():
        for r in roles:
            trust_of.setdefault(r, []).append(svc)

    findings = []
    for r in results:
        p = r["principal"]
        auth = cache.get(p, {})
        admin = is_admin(ix, p, auth)
        own = own_policy_risk(ix, p, G)
        gained = r["witnesses"]
        min_hops = min((w["hops"] for w in gained), default=None)
        unconditional = any(not w["conditional"] for w in gained)
        findings.append({
            "principal": p,
            "kind": r["kind"],
            "admin": admin,
            # carried through rather than recomputed: self escalation is a
            # separate finding class, and anything building on this list (the
            # SARIF writer, the baseline) would otherwise have to re-run the
            # analysis to see it
            "self_escalation": bool(r.get("self_escalation")),
            "self_escalation_via": sorted(r.get("self_escalation_via") or []),
            "reaches_alone": r["n_auth"],
            "reaches_in_total": r["n_eff"],
            "own_policy_risk": own,
            "own_policy_risk_count": len(own),
            "delegation_only_risk": gained,
            "delegation_only_count": len(gained),
            "min_hops": min_hops,
            "unconditional": unconditional,
            "shared_trust_services": sorted(trust_of.get(p, [])),
            "unreadable_managed_gained": r.get("unreadable_managed_gained", {}),
            "unquantified": bool(r.get("Esc_unquantified")),
            "rank": (len(gained), -(min_hops if min_hops is not None else 99),
                     1 if unconditional else 0),
        })
    findings.sort(key=lambda f: f["rank"], reverse=True)
    return findings, shared, ix


def chain_text(w):
    if not w["chain"]:
        return "direct"
    return "  ".join(f"{h['from']} =={h['via']}[{h['scope']}]==> {h['to']}"
                     for h in w["chain"])


def render(findings, shared, limit_resources=8):
    lines = []
    deleg = [f for f in findings if f["delegation_only_count"]]
    own_only = [f for f in findings if not f["delegation_only_count"]
                and f["own_policy_risk_count"]]
    admins = [f for f in findings if f["admin"]]
    unq = [f for f in findings if f["unquantified"]]

    lines.append("AgentPathTriage findings")
    lines.append("=" * 72)
    lines.append(f"principals analysed:              {len(findings)}")
    lines.append(f"reachable only through delegation: {len(deleg)}   <- what this tool adds")
    lines.append(f"risk visible in the principal's own policy: {len(own_only)}"
                 "   (a policy linter finds these too)")
    lines.append(f"admin-grade, chain adds nothing:   {len(admins)}")
    if unq:
        lines.append(f"escalation of unmeasurable extent: {len(unq)}")
    lines.append("")

    if shared:
        lines.append("Roles that are interchangeable to a service")
        lines.append("-" * 72)
        lines.append("A service trusted by more than one role, with no condition narrowing")
        lines.append("who may use it, can carry any of those roles. Anything able to make")
        lines.append("that service act can therefore choose among them.")
        for svc, roles in sorted(shared.items()):
            lines.append(f"  {svc}")
            for r in sorted(roles):
                lines.append(f"      {r}")
        lines.append("")

    lines.append("Findings, most reach gained first")
    lines.append("-" * 72)
    if not deleg:
        lines.append("  none")
    for f in deleg:
        tag = " [admin]" if f["admin"] else ""
        lines.append(f"\n{f['principal']}{tag}  ({f['kind']})")
        lines.append(f"  reaches alone: {f['reaches_alone']}    "
                     f"reaches in total: {f['reaches_in_total']}    "
                     f"gained by delegation: {f['delegation_only_count']}")
        if f["shared_trust_services"]:
            lines.append(f"  participates in shared trust: "
                         f"{', '.join(f['shared_trust_services'])}")
        if f["own_policy_risk_count"]:
            lines.append(f"  own-policy risk (a linter sees this): "
                         f"{f['own_policy_risk_count']} wildcard-scoped grant(s)")
        lines.append("  gained only through delegation:")
        for w in f["delegation_only_risk"][:limit_resources]:
            cond = " (conditional)" if w["conditional"] else ""
            lines.append(f"      {w['reaches']}{cond}")
            lines.append(f"         via {w['via_role']} using {w['action']}")
            lines.append(f"         {chain_text(w)}")
            if w["chain"] and w["chain"][-1].get("enabled_by"):
                lines.append(f"         possible because: {w['chain'][-1]['enabled_by']}")
        extra = f["delegation_only_count"] - limit_resources
        if extra > 0:
            lines.append(f"      ... and {extra} more resource(s)")

    if unq:
        lines.append("\nEscalations whose extent cannot be measured from configuration")
        lines.append("-" * 72)
        for f in unq:
            for role, pols in f["unreadable_managed_gained"].items():
                lines.append(f"  {f['principal']} reaches {role}, which carries "
                             f"{', '.join(pols)}")
                lines.append("     the document for that policy lives at AWS, not in "
                             "the configuration, so the reach gained is real but "
                             "not measurable here")

    if admins:
        lines.append("\nAdmin-grade principals, excluded from chain findings")
        lines.append("-" * 72)
        lines.append("These already reach everything under their own identity, so no "
                     "hand-off adds to their reach. They are over-permissioned, which "
                     "is a separate and already well covered problem.")
        for f in admins:
            lines.append(f"  {f['principal']}")

    if own_only:
        lines.append("\nRisk visible without any delegation")
        lines.append("-" * 72)
        lines.append("Reported for completeness and attributed honestly: a policy "
                     "linter finds these, and they are not this project's contribution.")
        for f in own_only[:20]:
            types = ", ".join(sorted({w["reaches_type"] for w in f["own_policy_risk"]}))
            lines.append(f"  {f['principal']:52s} {types}")
        if len(own_only) > 20:
            lines.append(f"  ... and {len(own_only) - 20} more")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--json")
    ap.add_argument("--md")
    a = ap.parse_args()
    findings, shared, _ = build(json.load(open(a.state)))
    text = render(findings, shared)
    print(text)
    if a.json:
        json.dump({"shared_trust": {k: sorted(v) for k, v in shared.items()},
                   "findings": findings}, open(a.json, "w"), indent=2)
        print(f"\nwritten: {a.json}")
    if a.md:
        open(a.md, "w").write("```\n" + text + "\n```\n")
        print(f"written: {a.md}")


if __name__ == "__main__":
    main()

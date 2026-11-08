#!/usr/bin/env python3
"""
AgentPathTriage - propagate (v1)

Multi-hop reachability over delegation edges. This is the core technical
contribution: it recovers escalations that single-hop `check` structurally
cannot see.

eff(p): the effective act-reach of a principal p is the union of p's own act
edges and the act edges of every role reachable from p by following delegation
(iam:PassRole / sts:AssumeRole) edges, transitively.

Esc_multi(p) is TRUE iff eff(p) contains a wildcard (cross-agent) act edge,
whether that edge is p's own or inherited through the chain.

The interesting set is {p : Esc_multi(p) and not Esc_single(p)} - principals a
single-hop analyser calls safe, but that are escalated once the delegation chain
is followed. The PassRole two-hop scenario lands exactly here, matching the
mutation-testing false negative `hard_passrole_two_hop`.

Nothing is hardcoded: every edge comes from `extract`, which reads it from the
deployed Terraform state. `check.py` is left unchanged on purpose, so the
single-hop verdict this module compares against is the real one.

Usage:
    python3 propagate.py --graph delegation_graph.json
    python3 propagate.py --graph delegation_graph.json --principal apt-lab-roleA-thin
    python3 propagate.py --graph delegation_graph.json --json propagate_results.json
"""
import argparse, json, sys
import networkx as nx


def load_graph(path) -> nx.DiGraph:
    return nx.node_link_graph(json.load(open(path)), directed=True)


def roles_in(G):
    return [n for n, d in G.nodes(data=True) if d.get("kind") == "role"]


def wildcard_act_edges(G, role):
    """Wildcard (cross-agent) act edges out of `role`."""
    return [(t, d) for _, t, d in G.out_edges(role, data=True)
            if d.get("rel") == "act" and d.get("wildcard")]


def reachable_via_delegation(G, start):
    """BFS over delegation edges. Returns list of (role, path), where path is the
    list of delegation hops {from, to, via} taken to reach `role`. Cycles are
    handled by the visited set, so PassRole loops terminate."""
    seen = {start}
    frontier = [(start, [])]
    out = []
    while frontier:
        node, path = frontier.pop(0)
        for _, tgt, d in G.out_edges(node, data=True):
            if d.get("rel") != "delegate" or tgt in seen:
                continue
            seen.add(tgt)
            vias = d.get("vias", [d.get("via")])
            hop = {"from": node, "to": tgt, "via": "/".join(v for v in vias if v)}
            newpath = path + [hop]
            out.append((tgt, newpath))
            frontier.append((tgt, newpath))
    return out


def analyse(G, p) -> dict:
    # single-hop: p's own wildcard act edges (this is what check.py sees)
    own = wildcard_act_edges(G, p)
    esc_single = len(own) > 0

    witnesses = []
    for t, d in own:
        witnesses.append({"hops": 0, "chain": [], "via_role": p,
                          "reaches": t, "action": d.get("action")})
    # inherited reach through the delegation chain
    for role, path in reachable_via_delegation(G, p):
        for t, d in wildcard_act_edges(G, role):
            witnesses.append({"hops": len(path), "chain": path, "via_role": role,
                              "reaches": t, "action": d.get("action")})

    esc_multi = len(witnesses) > 0
    return {
        "principal": p,
        "Esc_single": esc_single,
        "Esc_multi": esc_multi,
        "recovered_by_propagate": esc_multi and not esc_single,
        "witnesses": witnesses,
    }


def chain_str(w, principal):
    if w["hops"] == 0:
        return f"{principal} --act[{w['action']}]--> {w['reaches']}"
    parts = [f"{h['from']} =={h['via']}==> {h['to']}" for h in w["chain"]]
    parts.append(f"{w['via_role']} --act[{w['action']}]--> {w['reaches']}")
    return "  ".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", required=True)
    ap.add_argument("--principal", help="single principal; default = all roles")
    ap.add_argument("--json", help="write results to this file")
    a = ap.parse_args()

    G = load_graph(a.graph)
    targets = [a.principal] if a.principal else roles_in(G)
    results = [analyse(G, p) for p in targets if p in G]

    recovered = []
    for r in results:
        tag = "ESCALATED (multi-hop)" if r["Esc_multi"] else "not escalated"
        note = "   <-- RECOVERED by propagate (single-hop missed it)" if r["recovered_by_propagate"] else ""
        print(f"\n{r['principal']}: Esc_single={r['Esc_single']}  Esc_multi={r['Esc_multi']}  [{tag}]{note}")
        for w in r["witnesses"]:
            kind = "direct" if w["hops"] == 0 else f"{w['hops']}-hop"
            print(f"    [{kind}] {chain_str(w, r['principal'])}")
        if r["recovered_by_propagate"]:
            recovered.append(r["principal"])

    print("\n" + "=" * 64)
    print(f"Recovered ONLY by multi-hop propagate: {recovered or 'none'}")
    print("=" * 64)

    if a.json:
        json.dump(results, open(a.json, "w"), indent=2)
        print(f"results: {a.json}")

    # exit 0 if propagate recovered at least one escalation single-hop missed
    sys.exit(0 if recovered else 1)


if __name__ == "__main__":
    main()

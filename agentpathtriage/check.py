#!/usr/bin/env python3
"""
AgentPathTriage — check (v1)

Decides the escalation predicate Esc(p) over a delegation graph produced by
`extract`, and returns the witness path. This is the RQ1/RQ3 decision step: it
reasons only over the recovered graph, so if `extract` recovered the config
faithfully, `check` recovers the documented escalations without being told what
to look for (that is what E1 measures).

Definition used:
    A role r is escalated if it has an outgoing `act` edge whose resource scope
    is a wildcard over an agentic resource type. That edge is reach into a
    resource the role's own agent does not own -> Esc is TRUE, witness = edge.

Nothing is hardcoded to the lab: the verdict is read off the graph's edges.

Usage:
    python3 check.py --graph delegation_graph.json                 # all principals
    python3 check.py --graph delegation_graph.json --principal apt-lab-roleA-overprivileged
    python3 check.py --graph delegation_graph.json --json results.json
"""
import argparse, json, sys
import networkx as nx


def load_graph(path) -> nx.DiGraph:
    data = json.load(open(path))
    return nx.node_link_graph(data, directed=True)


def witnesses_for(G, role) -> list[dict]:
    """Return the cross-agent (wildcard) act edges out of `role`. Each is a
    witness: role reaches a resource it does not own."""
    out = []
    for _, tgt, d in G.out_edges(role, data=True):
        if d.get("rel") == "act" and d.get("wildcard"):
            out.append({"reaches": tgt, "action": d.get("action"),
                        "why": "wildcard resource scope -> cross-agent reach"})
    return out


def check_principal(G, role) -> dict:
    w = witnesses_for(G, role)
    return {
        "principal": role,
        "Esc": len(w) > 0,           # escalated iff at least one cross-agent witness
        "num_witnesses": len(w),
        "witnesses": w,
    }


def roles_in(G):
    return [n for n, d in G.nodes(data=True) if d.get("kind") == "role"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", required=True)
    ap.add_argument("--principal", help="a single role to check; default = all roles")
    ap.add_argument("--json", help="write results to this file")
    a = ap.parse_args()

    G = load_graph(a.graph)
    targets = [a.principal] if a.principal else roles_in(G)

    results = [check_principal(G, r) for r in targets if r in G]
    for res in results:
        verdict = "ESCALATED" if res["Esc"] else "not escalated"
        print(f"\n{res['principal']}: Esc = {res['Esc']}  ({verdict}, {res['num_witnesses']} witness)")
        for w in res["witnesses"]:
            print(f"    witness: reaches '{w['reaches']}' via {w['action']}  [{w['why']}]")

    if a.json:
        json.dump(results, open(a.json, "w"), indent=2)
        print(f"\nresults: {a.json}")

    # exit 0 if any principal is escalated (useful for scripting)
    sys.exit(0 if any(r["Esc"] for r in results) else 1)


if __name__ == "__main__":
    main()

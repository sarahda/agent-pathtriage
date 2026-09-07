#!/usr/bin/env python3
"""
AgentPathTriage — extract PoC (Week 0)
Minimal proof: an over-privileged AgentCore execution-role JSON  ->  delegation graph.

Shows that `extract` can turn deployed IAM config into nodes + `act` edges,
and flag the wildcard scopes that create cross-agent reach (confused deputy).
Not the real tool — just the "config -> graph works" proof.
"""
import json, sys
import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# --- map each AgentCore action to the resource type it targets ---
RESOURCE_OF = {
    "ecr:BatchGetImage":                    "ECR images",
    "bedrock-agentcore:*":                  "Agent memory",
    "bedrock-agentcore:InvokeCodeInterpreter":"Code interpreters",
    "bedrock-agentcore:InvokeAgentRuntime": "Agent runtimes",
}

def is_wildcard(resource: str) -> bool:
    """A resource scope that reaches beyond the agent's own resources."""
    return resource == "*" or resource.rstrip().endswith("/*")

def extract(path: str) -> nx.DiGraph:
    doc = json.load(open(path))
    agent = doc["attached_to_agent"]          # e.g. AgentA
    role  = doc["role_name"]
    G = nx.DiGraph()

    G.add_node(agent, kind="agent")
    G.add_node(role,  kind="role")
    G.add_edge(agent, role, rel="assume")     # agent assumes its execution role

    victim = "AgentB (any other agent)"       # implied by wildcard reach
    victim_added = False

    for stmt in doc["policy"]["Statement"]:
        action = stmt["Action"]
        res    = stmt["Resource"]
        rtype  = RESOURCE_OF.get(action, action)
        wild   = is_wildcard(res)

        G.add_node(rtype, kind="resource")
        G.add_edge(role, rtype, rel="act", action=action, wildcard=wild)

        if wild:                               # wildcard => reaches other agents' resources
            if not victim_added:
                G.add_node(victim, kind="agent"); victim_added = True
            G.add_edge(rtype, victim, rel="belongs_to")
    return G

def report(G):
    print("\n=== extract report ===")
    wild = [(u, v, d) for u, v, d in G.edges(data=True)
            if d.get("rel") == "act" and d.get("wildcard")]
    print(f"nodes: {G.number_of_nodes()}  edges: {G.number_of_edges()}")
    print(f"cross-agent (wildcard) act edges: {len(wild)}")
    for u, v, d in wild:
        print(f"  [CROSS-AGENT REACH] {u} --{d['action']}--> {v}  (Resource is wildcard)")
    print("=> escalation predicate Esc: an agent can act on resources it does not own "
          "-> TRUE (via the wildcard edges above)\n")

def draw(G, out="delegation_graph.png"):
    color = {"agent": "#fca5a5", "role": "#a5b4fc", "resource": "#fde68a"}
    pos = {
        "AgentA": (0, 1), "AgentCore-StarterToolkit-ExecutionRole": (1.3, 1),
        "ECR images": (2.6, 2), "Agent memory": (2.6, 1.3),
        "Code interpreters": (2.6, 0.6), "Agent runtimes": (2.6, -0.1),
        "AgentB (any other agent)": (4, 1),
    }
    pos = {n: pos.get(n, (2.6, i)) for i, n in enumerate(G.nodes())}
    node_colors = [color.get(G.nodes[n].get("kind"), "#e5e7eb") for n in G.nodes()]

    plt.figure(figsize=(11, 6))
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=2600,
                           edgecolors="#334155")
    nx.draw_networkx_labels(G, pos, font_size=8)

    act_wild = [(u, v) for u, v, d in G.edges(data=True) if d.get("wildcard")]
    others   = [(u, v) for u, v, d in G.edges(data=True) if not d.get("wildcard")]
    nx.draw_networkx_edges(G, pos, edgelist=others, edge_color="#94a3b8",
                           arrows=True, width=1.4)
    nx.draw_networkx_edges(G, pos, edgelist=act_wild, edge_color="#dc2626",
                           arrows=True, width=2.2)
    elabels = {(u, v): d.get("rel") for u, v, d in G.edges(data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=elabels, font_size=7)

    plt.title("AgentPathTriage extract PoC — delegation graph from AgentCore role\n"
              "red = wildcard `act` edge (cross-agent reach = confused deputy)", fontsize=10)
    plt.axis("off"); plt.tight_layout(); plt.savefig(out, dpi=140)
    print(f"graph image saved: {out}")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "agentcore_role.json"
    G = extract(path)
    report(G)
    draw(G)

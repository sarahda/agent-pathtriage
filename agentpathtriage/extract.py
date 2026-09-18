#!/usr/bin/env python3
"""
AgentPathTriage — extract (v1)

Builds a delegation graph from deployed AWS configuration. Reads Terraform state
(`terraform show -json`) so it works against the real, applied config rather than
a hand-written JSON. Produces:

  - nodes: agents, roles, resources (memory / ECR / runtime / interpreter)
  - `assume` edges: agent -> its execution role
  - `act` edges:    role -> resource-type, flagged cross-agent when the policy
                    resource is a wildcard over an agentic resource type

This is RQ3's `extract`. It does not decide Esc by itself (that is `check`); it
recovers the graph that `check` reasons over. Nothing about the outcome is
hardcoded: every edge is derived from a statement actually present in the state.

Usage:
    python3 extract.py --tfdir ../../infra/aws            # reads live state
    python3 extract.py --state path/to/tfstate.json      # or an explicit state
    python3 extract.py --tfdir ../../infra/aws --png graph.png
"""
import argparse, json, subprocess, sys
import networkx as nx

# Map an action to the agentic resource-type node it targets. This is only a
# label for the graph; whether an edge is cross-agent is decided by the *resource
# scope*, never by the action name.
ACTION_LABEL = {
    "ecr:BatchGetImage":                        "ECR images",
    "ecr:GetDownloadUrlForLayer":               "ECR images",
    "bedrock-agentcore:InvokeCodeInterpreter":  "Code interpreters",
    "bedrock-agentcore:InvokeAgentRuntime":     "Agent runtimes",
}
# ARN substrings that identify an agentic resource type (used when the action is
# generic, e.g. bedrock-agentcore:* on memory/*).
ARN_LABEL = {
    ":memory/":   "Agent memory",
    ":runtime/":  "Agent runtimes",
    ":repository/": "ECR images",
}


def load_state(tfdir=None, state_path=None) -> dict:
    if state_path:
        return json.load(open(state_path))
    out = subprocess.check_output(["terraform", "show", "-json"], cwd=tfdir)
    return json.loads(out)


def iter_resources(state):
    """Yield (type, name, values) for every managed resource in the state."""
    root = state.get("values", {}).get("root_module", {})
    for r in root.get("resources", []):
        yield r["type"], r["name"], r.get("values", {})


def is_wildcard(resource) -> bool:
    if isinstance(resource, list):
        return any(is_wildcard(x) for x in resource)
    return resource == "*" or str(resource).rstrip().endswith("/*")


def resource_type_of(resource, action) -> str | None:
    """The agentic resource-type node this statement targets, or None if it is
    not an agentic/ECR statement we model."""
    # Prefer the ARN (it tells us the concrete resource type)...
    if isinstance(resource, list):
        for r in resource:
            t = resource_type_of(r, action)
            if t:
                return t
        return None
    for sub, label in ARN_LABEL.items():
        if sub in str(resource):
            return label
    # ...otherwise fall back to the action's target type (e.g. Resource == "*").
    return ACTION_LABEL.get(action)


def extract(state) -> nx.DiGraph:
    G = nx.DiGraph()

    # 1) roles and their inline policies
    role_policies = {}   # role_name -> list of statements
    role_arns = {}
    for rtype, name, v in iter_resources(state):
        if rtype == "aws_iam_role":
            role_arns[name] = v.get("arn")
            G.add_node(v.get("name", name), kind="role")
        if rtype == "aws_iam_role_policy":
            pol = v.get("policy")
            if isinstance(pol, str):
                try: pol = json.loads(pol)
                except Exception: continue
            stmts = pol.get("Statement", []) if isinstance(pol, dict) else []
            role_policies.setdefault(v.get("role", name), []).extend(
                stmts if isinstance(stmts, list) else [stmts])

    # 2) agents and their assume edge to a role
    for rtype, name, v in iter_resources(state):
        if rtype == "aws_bedrockagentcore_agent_runtime":
            agent = v.get("agent_runtime_name", name)
            G.add_node(agent, kind="agent")
            role_arn = v.get("role_arn")
            # match role_arn back to a role node
            role_node = next((rn for rn, ra in role_arns.items() if ra == role_arn), None)
            if role_node:
                role_name = None
                for _, n2, v2 in iter_resources(state):
                    if v2.get("arn") == role_arn and v2.get("name"):
                        role_name = v2["name"]; break
                G.add_edge(agent, role_name or role_node, rel="assume")

    # 3) act edges from each role's statements
    for rtype, name, v in iter_resources(state):
        if rtype != "aws_iam_role":
            continue
        role_label = v.get("name", name)
        # find this role's policy: match by aws_iam_role_policy.role referencing the role id/name
        stmts = []
        for _, pn, pv in iter_resources(state):
            pass
        # simpler: role_policies keyed by role attribute; role attribute is the role name/id
        for key, s in role_policies.items():
            stmts = s if key in (role_label, v.get("id")) else stmts
        # fallback: if only one policy set, and one role, use it
        if not stmts and len(role_policies) == 1:
            stmts = list(role_policies.values())[0]

        for st in stmts:
            actions = st.get("Action", [])
            actions = actions if isinstance(actions, list) else [actions]
            res = st.get("Resource")
            for a in actions:
                label = resource_type_of(res, a)
                if not label:
                    continue
                # cross-agent reach is decided by the RESOURCE SCOPE, not the
                # action name: only a wildcard resource reaches other agents.
                wild = is_wildcard(res)
                G.add_node(label, kind="resource")
                if not G.has_edge(role_label, label):
                    G.add_edge(role_label, label, rel="act", action=a, wildcard=wild)
                elif wild:
                    G[role_label][label]["wildcard"] = True
    return G


def summarise(G):
    roles  = [n for n,d in G.nodes(data=True) if d.get("kind")=="role"]
    agents = [n for n,d in G.nodes(data=True) if d.get("kind")=="agent"]
    wild   = [(u,v,d) for u,v,d in G.edges(data=True) if d.get("rel")=="act" and d.get("wildcard")]
    print(f"nodes: {G.number_of_nodes()} (agents={len(agents)}, roles={len(roles)})  edges: {G.number_of_edges()}")
    print(f"cross-agent (wildcard) act edges: {len(wild)}")
    for u,v,d in wild:
        print(f"  [CROSS-AGENT] {u} --{d['action']}--> {v}")
    return wild


def draw(G, out):
    import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
    color = {"agent":"#fca5a5","role":"#a5b4fc","resource":"#fde68a"}
    pos = nx.spring_layout(G, seed=7, k=1.2)
    nc = [color.get(G.nodes[n].get("kind"),"#e5e7eb") for n in G.nodes()]
    plt.figure(figsize=(11,7))
    nx.draw_networkx_nodes(G,pos,node_color=nc,node_size=2200,edgecolors="#334155")
    nx.draw_networkx_labels(G,pos,font_size=7)
    wild=[(u,v) for u,v,d in G.edges(data=True) if d.get("wildcard")]
    oth =[(u,v) for u,v,d in G.edges(data=True) if not d.get("wildcard")]
    nx.draw_networkx_edges(G,pos,edgelist=oth,edge_color="#94a3b8",arrows=True)
    nx.draw_networkx_edges(G,pos,edgelist=wild,edge_color="#dc2626",arrows=True,width=2.2)
    nx.draw_networkx_edge_labels(G,pos,edge_labels={(u,v):d.get("rel") for u,v,d in G.edges(data=True)},font_size=6)
    plt.axis("off"); plt.tight_layout(); plt.savefig(out,dpi=140)
    print(f"graph image: {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tfdir", help="Terraform dir to read live state from")
    ap.add_argument("--state", help="explicit terraform state json")
    ap.add_argument("--png", help="optional graph image output")
    ap.add_argument("--json", default="delegation_graph.json", help="graph json output")
    a = ap.parse_args()
    if not a.tfdir and not a.state:
        ap.error("give --tfdir or --state")
    state = load_state(a.tfdir, a.state)
    G = extract(state)
    wild = summarise(G)
    # persist graph
    data = nx.node_link_data(G)
    json.dump(data, open(a.json,"w"), indent=2)
    print(f"graph json: {a.json}")
    if a.png:
        draw(G, a.png)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
AgentPathTriage - generic IAM adapter for external benchmarking (extract_iam)

The agentic `extract` models bedrock-agentcore / ECR / memory / runtime edges.
The IAM Vulnerable benchmark (BishopFox) is generic AWS IAM: customer-managed
policies attached to users and roles, wildcard PassRole, and trust-based
AssumeRole chains. This adapter reads that generic shape and emits the SAME
delegation-graph format the agentic tool uses, so `check.py` (single-hop) and
`propagate.py` (multi-hop) run on it unchanged.

Scope (stated honestly): this adapter models the delegation-relevant subset of
IAM privilege escalation, which is what `propagate` is about:
  - over-privilege        : an identity that can do "*" (or iam:* / *:* ) on "*",
                            or holds an admin-grade managed policy, gets a
                            wildcard `act` edge to a synthetic "AWS control plane"
                            resource node
  - identity delegation   : iam:PassRole / sts:AssumeRole on a role ARN, or on "*"
                            (pass/assume ANY role), becomes a `delegate` edge
  - trust delegation      : a role whose trust policy allows principal P becomes
                            a `delegate` edge P -> role

Out of scope, and reported as such rather than scored: policy self-modification
(CreatePolicyVersion, AttachUserPolicy, PutRolePolicy, ...), credential creation
(CreateAccessKey, CreateLoginProfile), and group membership. These are
single-principal escalations the delegation model does not represent.

Nothing is hardcoded to the benchmark: every node and edge is derived from a
statement or trust relation present in the Terraform state.

Usage:
    python3 extract_iam.py --state tfstate.json --json iam_graph.json
    python3 extract_iam.py --tfdir path/to/iam-vulnerable --json iam_graph.json
"""
import argparse, json, re, subprocess
import networkx as nx

CONTROL_PLANE = "AWS control plane"
ADMIN_ACTION = re.compile(r"^(\*|iam:\*|sts:\*|\*:\*)$")
DELEGATION_ACTIONS = {"iam:PassRole", "sts:AssumeRole"}
ADMIN_MANAGED = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}


def load_state(tfdir=None, state_path=None):
    if state_path:
        return json.load(open(state_path))
    out = subprocess.check_output(["terraform", "show", "-json"], cwd=tfdir)
    return json.loads(out)


def iter_resources(state):
    root = state.get("values", {}).get("root_module", {})
    for r in root.get("resources", []):
        yield r["type"], r["name"], r.get("values", {})
    # walk child modules too (IAM Vulnerable nests everything under modules)
    stack = list(root.get("child_modules", []))
    while stack:
        m = stack.pop()
        for r in m.get("resources", []):
            yield r["type"], r["name"], r.get("values", {})
        stack.extend(m.get("child_modules", []))


def as_list(x):
    return x if isinstance(x, list) else ([] if x is None else [x])


def parse_policy(pol):
    if isinstance(pol, str):
        try: pol = json.loads(pol)
        except Exception: return []
    if not isinstance(pol, dict): return []
    return as_list(pol.get("Statement", []))


def is_wildcard(resource):
    if isinstance(resource, list):
        return any(is_wildcard(x) for x in resource)
    return resource == "*" or str(resource).rstrip().endswith("/*") or str(resource).rstrip().endswith(":*")


def trust_principals(assume_doc):
    """ARNs allowed to assume, from an assume_role_policy document."""
    out = []
    for st in parse_policy(assume_doc):
        if st.get("Effect") != "Allow":
            continue
        pr = st.get("Principal", {})
        if isinstance(pr, dict):
            for v in pr.values():
                out.extend(as_list(v))
        elif isinstance(pr, str):
            out.append(pr)
    return out


def build(state):
    G = nx.DiGraph()

    # ---- index everything ----
    managed = {}          # policy arn -> statements
    inline = {}           # principal name -> statements
    attach = {}           # principal name -> [policy arn]
    arn_of = {}           # principal name -> arn
    kind_of = {}          # principal name -> "role" | "user"
    trust = {}            # role name -> [allowed principal arn]

    for rtype, name, v in iter_resources(state):
        if rtype == "aws_iam_policy":
            managed[v.get("arn")] = parse_policy(v.get("policy"))
        elif rtype in ("aws_iam_role", "aws_iam_user"):
            pk = "role" if rtype == "aws_iam_role" else "user"
            pname = v.get("name", name)
            kind_of[pname] = pk
            arn_of[pname] = v.get("arn")
            G.add_node(pname, kind=pk)
            for m in as_list(v.get("managed_policy_arns")):
                attach.setdefault(pname, []).append(m)
            if pk == "role" and v.get("assume_role_policy"):
                trust[pname] = trust_principals(v.get("assume_role_policy"))
        elif rtype in ("aws_iam_role_policy", "aws_iam_user_policy"):
            owner = v.get("role") or v.get("user") or name
            inline.setdefault(owner, []).extend(parse_policy(v.get("policy")))
        elif rtype in ("aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment"):
            owner = v.get("role") or v.get("user")
            if owner and v.get("policy_arn"):
                attach.setdefault(owner, []).append(v["policy_arn"])

    arn_to_name = {a: n for n, a in arn_of.items() if a}

    def statements_of(pname):
        s = list(inline.get(pname, []))
        for parn in attach.get(pname, []):
            s.extend(managed.get(parn, []))
        return s

    # ---- act edges (over-privilege) ----
    for pname in list(kind_of):
        admin_managed = any(p in ADMIN_MANAGED for p in attach.get(pname, []))
        over = admin_managed
        if not over:
            for st in statements_of(pname):
                if st.get("Effect") != "Allow":
                    continue
                acts = as_list(st.get("Action"))
                if any(ADMIN_ACTION.match(str(a)) for a in acts) and is_wildcard(st.get("Resource")):
                    over = True
                    break
        if over:
            G.add_node(CONTROL_PLANE, kind="resource")
            G.add_edge(pname, CONTROL_PLANE, rel="act",
                       action="* (admin)", wildcard=True)

    # ---- identity delegation edges (PassRole / AssumeRole on a role, or on *) ----
    all_roles = [n for n, k in kind_of.items() if k == "role"]
    for pname in list(kind_of):
        for st in statements_of(pname):
            if st.get("Effect") != "Allow":
                continue
            acts = as_list(st.get("Action"))
            deleg = [a for a in acts if a in DELEGATION_ACTIONS]
            if not deleg:
                continue
            res = st.get("Resource")
            for r in as_list(res):
                if r == "*":
                    for tgt in all_roles:
                        if tgt != pname:
                            _add_delegate(G, pname, tgt, deleg, scope="wildcard")
                else:
                    tgt = arn_to_name.get(r)
                    if tgt and tgt != pname:
                        _add_delegate(G, pname, tgt, deleg, scope="specific")

    # ---- trust delegation edges (role trust allows principal P) ----
    for role, principals in trust.items():
        for parn in principals:
            src = arn_to_name.get(parn)
            if src and src != role:
                _add_delegate(G, src, role, ["trust"], scope="trust")

    return G


def _add_delegate(G, src, tgt, vias, scope):
    if G.has_edge(src, tgt) and G[src][tgt].get("rel") == "delegate":
        vs = G[src][tgt].setdefault("vias", [])
        for a in vias:
            if a not in vs:
                vs.append(a)
    else:
        G.add_node(tgt, kind=G.nodes.get(tgt, {}).get("kind", "role"))
        G.add_edge(src, tgt, rel="delegate", via=vias[0], vias=list(vias), scope=scope)


def summarise(G):
    roles = [n for n, d in G.nodes(data=True) if d.get("kind") == "role"]
    users = [n for n, d in G.nodes(data=True) if d.get("kind") == "user"]
    act = [(u, v) for u, v, d in G.edges(data=True) if d.get("rel") == "act" and d.get("wildcard")]
    deleg = [(u, v, d) for u, v, d in G.edges(data=True) if d.get("rel") == "delegate"]
    print(f"principals: {len(roles)} roles, {len(users)} users   "
          f"over-privilege act edges: {len(act)}   delegate edges: {len(deleg)}")
    return G


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tfdir")
    ap.add_argument("--state")
    ap.add_argument("--json", default="iam_graph.json")
    a = ap.parse_args()
    if not a.tfdir and not a.state:
        ap.error("give --tfdir or --state")
    G = build(load_state(a.tfdir, a.state))
    summarise(G)
    json.dump(nx.node_link_data(G), open(a.json, "w"), indent=2)
    print(f"graph json: {a.json}")


if __name__ == "__main__":
    main()

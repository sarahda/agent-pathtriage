#!/usr/bin/env python3
"""
AgentPathTriage - Foundry CP determination (foundry_cp)

The Microsoft Foundry analogue of extract + check. Reads the deployed Foundry
config (`terraform show -json`, or an explicit state) plus the agent-layer
topology (agents.json), and decides:

  - eff(agent) / auth(agent) and Esc(agent)  - cross-agent escalation
  - which cross-agent primitives CP-1..CP-5 are present

The crux is OBO vs managed identity. A connection whose authType is
`ProjectManagedIdentity` routes a call under the project's managed identity
instead of the caller's delegated (OBO) token. So when Agent A invokes Agent B
over such a path, A executes with B's role assignments - a confused deputy. If
authType is caller-OBO (AAD / delegated), A's own roles gate the call and there
is no escalation. Nothing here is hardcoded: every decision is read from the
state and topology.

Usage:
    python3 foundry_cp.py --tfdir infra/foundry --agents infra/foundry/agents.json
    python3 foundry_cp.py --state state.json --agents agents.json
"""
import argparse, json, subprocess

PASSTHROUGH_AUTH = {"projectmanagedidentity", "managedidentity", "systemassignedidentity"}
# roles broad enough that holding one is a meaningful privilege a thin caller lacks
BROAD_ROLES = {
    "key vault secrets user", "key vault administrator", "key vault secrets officer",
    "cognitive services user", "azure ai developer", "storage blob data contributor",
    "storage blob data owner", "contributor", "owner",
}


def load_state(tfdir=None, state_path=None):
    if state_path:
        return json.load(open(state_path))
    out = subprocess.check_output(["terraform", "show", "-json"], cwd=tfdir)
    return json.loads(out)


def iter_resources(state):
    root = state.get("values", {}).get("root_module", {})
    for r in root.get("resources", []):
        yield r.get("type"), r.get("name"), r.get("values", {})
    # azapi resources can also appear with their body already expanded
    for child in root.get("child_modules", []):
        for r in child.get("resources", []):
            yield r.get("type"), r.get("name"), r.get("values", {})


def parse(state):
    identities = {}          # identity_name -> principal_id
    principal_to_identity = {}
    roles = []               # (principal_id, role_name, scope)
    connections = []         # (project_parent_id, authType)
    for rtype, name, v in iter_resources(state):
        if rtype == "azurerm_user_assigned_identity":
            pid = v.get("principal_id")
            identities[v.get("name", name)] = pid
            principal_to_identity[pid] = v.get("name", name)
        if rtype == "azurerm_role_assignment":
            roles.append((v.get("principal_id"),
                          (v.get("role_definition_name") or "").strip().lower(),
                          v.get("scope")))
        if rtype == "azapi_resource":
            body = v.get("body")
            if isinstance(body, str):
                try: body = json.loads(body)
                except Exception: body = {}
            props = (body or {}).get("properties", {}) if isinstance(body, dict) else {}
            if "authType" in props:
                connections.append((v.get("parent_id"), str(props.get("authType", "")).lower()))
    return identities, principal_to_identity, roles, connections


def roles_of(identity_name, identities, roles):
    pid = identities.get(identity_name)
    return {(rn, sc) for (p, rn, sc) in roles if p == pid}


def analyse(state, agents):
    identities, p2i, roles, connections = parse(state)
    # any passthrough (managed-identity) connection present in the deployment?
    passthrough = any(a in PASSTHROUGH_AUTH for (_parent, a) in connections)
    conn_auth = sorted({a for (_p, a) in connections}) or ["<none>"]

    agent_identity = {a["name"]: a["identity"] for a in agents["agents"]}
    findings = {"escalations": [], "cp": {f"CP-{i}": False for i in range(1, 6)},
                "connection_auth": conn_auth, "passthrough": passthrough}

    # --- Esc per invocation (CP-1 + CP-2) ---
    for inv in agents.get("invocations", []):
        caller, callee = inv["caller"], inv["callee"]
        mediated = inv.get("mediated", True)
        auth_caller = roles_of(agent_identity.get(caller, ""), identities, roles)
        roles_callee = roles_of(agent_identity.get(callee, ""), identities, roles)
        # effective roles of the caller: own, plus the callee's IF the call runs
        # under the callee's managed identity (passthrough) without per-call OBO.
        inherited = roles_callee if (passthrough and not mediated) else set()
        eff_caller = auth_caller | inherited
        gained = eff_caller - auth_caller
        if gained:
            findings["escalations"].append({
                "caller": caller, "callee": callee,
                "gained_roles": sorted(f"{r} @ {s}" for (r, s) in gained),
                "via": "ProjectManagedIdentity passthrough" if passthrough else "unknown",
                "mediated": mediated,
            })
            findings["cp"]["CP-1"] = True            # credential inheritance
            if not mediated:
                findings["cp"]["CP-2"] = True        # unmediated invocation

    # --- CP-3 shared-memory poisoning ---
    sm = agents.get("shared_memory", [])
    if any(len(e.get("agents", [])) > 1 for e in sm):
        findings["cp"]["CP-3"] = True

    # --- CP-4 tool scope over-grant: a managed identity holds a broad role ---
    for ident in set(agent_identity.values()):
        if any(rn in BROAD_ROLES for (rn, _sc) in roles_of(ident, identities, roles)):
            findings["cp"]["CP-4"] = True

    # --- CP-5 substrate reuse: one identity attached to >1 agent/project ---
    counts = {}
    for a in agents["agents"]:
        counts[a["identity"]] = counts.get(a["identity"], 0) + 1
    if any(c > 1 for c in counts.values()):
        findings["cp"]["CP-5"] = True

    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tfdir")
    ap.add_argument("--state")
    ap.add_argument("--agents", required=True)
    ap.add_argument("--json", default="foundry_findings.json")
    a = ap.parse_args()
    if not a.tfdir and not a.state:
        ap.error("give --tfdir or --state")
    state = load_state(a.tfdir, a.state)
    agents = json.load(open(a.agents))
    f = analyse(state, agents)

    print(f"connection authType: {', '.join(f['connection_auth'])}   passthrough={f['passthrough']}")
    print(f"cross-agent escalations: {len(f['escalations'])}")
    for e in f["escalations"]:
        print(f"  [ESC] {e['caller']} -> {e['callee']}  gains {e['gained_roles']}  (via {e['via']}, mediated={e['mediated']})")
    print("cross-agent primitives:")
    for cp, present in f["cp"].items():
        print(f"  {cp}: {'PRESENT' if present else '-'}")
    json.dump(f, open(a.json, "w"), indent=2)
    print(f"written: {a.json}")


if __name__ == "__main__":
    main()

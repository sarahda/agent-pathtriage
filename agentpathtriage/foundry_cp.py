#!/usr/bin/env python3
"""
AgentPathTriage - Foundry CP determination (foundry_cp)

The Microsoft Foundry analogue of extract + check. Reads the deployed Foundry
config (`terraform show -json`, or an explicit state) plus the agent-layer
topology (agents.json), and decides:

  - eff(agent) / auth(agent) and Esc(agent)  - cross-agent escalation
  - which cross-agent primitives CP-1..CP-5 are present

Two mechanisms produce Esc and both are evaluated. Identity passthrough is
below: a connection whose authType names a managed identity makes the caller
borrow another principal's assignments. Delegated invocation is in
foundry_delegation.py: the caller keeps its own identity, a role assignment
authorises it to call the callee, and the callee does the privileged work, so
reach grows without any role set being borrowed. The agent layer that carries
the second one is not in Terraform state, so it is read from the agents file's
`observed` block, which `infra/foundry/lab_a2a.py snapshot` writes.

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
import argparse, json, re, subprocess

try:
    from .foundry_delegation import analyse_delegation
except ImportError:                      # run as a script, not as a module
    from foundry_delegation import analyse_delegation

# A tenant or subscription id is a GUID, and an Azure resource id carries the
# subscription id in its first segment. The findings file is a committed artifact,
# so the identifier is removed where the finding is BUILT rather than afterwards:
# a redaction applied to the output file comes back on the next run. The AWS side
# does the same thing with account 000000000000.
GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
REDACTED_GUID = "00000000-0000-0000-0000-000000000000"
# A GUID that is already a placeholder. The snapshot writer uses one
# placeholder per distinct GUID, so its scopes carry 0001, 0002 and so on.
# Replacing those with the single placeholder below would make a scope printed
# here disagree with the same scope in the file it was read from, and would
# merge principals the snapshot deliberately kept apart.
ALREADY_PLACEHOLDER = re.compile(r"^0{8}-0{4}-0{4}-0{4}-[0-9]{12}$")
REDACT = True


def redact(text):
    """Replace every GUID with a fixed placeholder.

    Comparison still works: two scopes in the same subscription stay equal after
    redaction, because the placeholder is constant. What is lost is only the
    ability to name the real tenant, which is what should be lost.
    """
    if not REDACT or text is None:
        return text

    def one(m):
        g = m.group(0)
        return g if ALREADY_PLACEHOLDER.match(g) else REDACTED_GUID

    return GUID.sub(one, str(text))

# Which authType routes the call under the CALLEE's identity. Everything here
# names a managed identity belonging to the account, project or resource, so
# the caller's token is not what gates the downstream call.
PASSTHROUGH_AUTH = {"accountmanagedidentity", "projectmanagedidentity",
                    "managedidentity", "systemassignedidentity"}

# Which authType routes the call under the CALLER's identity. Both names say so
# explicitly: the user is impersonated, or the call is made on behalf of the
# user. These are the control levels.
CALLER_AUTH = {"agentuserimpersonation", "agentonbehalfofuser", "aad"}

# Azure's own enumeration, from the provider's validation error when an invalid
# value is sent for an AzureKeyVault connection (2025-06-01):
#   AccountManagedIdentity, AgentUserImpersonation, AgentOnBehalfOfUser,
#   AgenticIdentityToken, AgenticUser
# Worth recording because it is authoritative and short. Note that
# ProjectManagedIdentity is NOT valid for this connection category, so it
# cannot be used as a matrix level here even though it is a real Foundry
# authType elsewhere.
KEYVAULT_CONNECTION_AUTH_TYPES = ("AccountManagedIdentity", "AgentUserImpersonation",
                                  "AgentOnBehalfOfUser", "AgenticIdentityToken",
                                  "AgenticUser")


def auth_class(auth):
    """passthrough, caller, or unknown.

    Unknown is a real answer and is reported as one. `AgenticIdentityToken` and
    `AgenticUser` are valid for this connection category but it is not
    documented here which identity they resolve to, and guessing would put a
    made-up prediction in a table whose purpose is to compare prediction with
    result.
    """
    a = str(auth).lower()
    if a in PASSTHROUGH_AUTH:
        return "passthrough"
    if a in CALLER_AUTH:
        return "caller"
    return "unknown"
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

    # Optional. An agent taken from a live snapshot has an instance identity
    # and no Terraform identity, and the two are different principals: using
    # the Terraform name for such an agent would test the wrong one. The
    # passthrough block below simply has nothing to say about those agents.
    agent_identity = {a["name"]: a.get("identity") for a in agents["agents"]
                      if a.get("identity")}
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
                "gained_roles": sorted(redact(f"{r} @ {s}") for (r, s) in gained),
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
        # Whichever principal this agent actually runs as. A snapshot names the
        # instance identity; a configuration names the user assigned one.
        key = a.get("identity") or a.get("instance_principal_id")
        if not key:
            continue
        counts[key] = counts.get(key, 0) + 1
    if any(c > 1 for c in counts.values()):
        findings["cp"]["CP-5"] = True

    # --- CP-2 delegated invocation ---
    # The second mechanism, in its own module. The caller keeps its own
    # identity, a role assignment lets it call the callee, and the callee does
    # the privileged work. No role set is borrowed, so the passthrough block
    # above cannot see it. Kept separate in the output because the two have
    # different fixes: remove the passthrough authType, or remove the invoke
    # grant.
    deleg = analyse_delegation(agents, identities)
    findings["delegated"] = deleg
    if deleg["escalations"]:
        findings["cp"]["CP-2"] = True

    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tfdir")
    ap.add_argument("--state")
    ap.add_argument("--agents", required=True)
    ap.add_argument("--json", default="foundry_findings.json")
    ap.add_argument("--no-redact", action="store_true",
                    help="keep real subscription and tenant ids in the output. "
                         "For local debugging only: the result must not be committed")
    a = ap.parse_args()
    if a.no_redact:
        globals()["REDACT"] = False
    if not a.tfdir and not a.state:
        ap.error("give --tfdir or --state")
    state = load_state(a.tfdir, a.state)
    agents = json.load(open(a.agents))
    f = analyse(state, agents)

    # Say where the connections were read from. The lab's A2A connection is a
    # runtime object and is not in Terraform state, so `<none>` from state
    # alone is not the same claim as no connection existing.
    snap_conns = sorted({str(c.get("auth_type") or c.get("authType"))
                         for c in ((agents.get("observed") or {}).get(
                             "connections") or agents.get("connections") or [])
                         if c.get("auth_type") or c.get("authType")})
    print(f"connection authType in terraform state: "
          f"{', '.join(f['connection_auth'])}   passthrough={f['passthrough']}")
    print(f"connection authType in the agent snapshot: "
          f"{', '.join(snap_conns) or '<none>'}")
    print(f"cross-agent escalations: {len(f['escalations'])}")
    for e in f["escalations"]:
        print(f"  [ESC] {e['caller']} -> {e['callee']}  gains {e['gained_roles']}  (via {e['via']}, mediated={e['mediated']})")
    d = f.get("delegated", {})
    print(f"delegated-invocation escalations: {len(d.get('escalations', []))}"
          f"   (invocation edges: {len(d.get('edges', []))})")
    for e in d.get("escalations", []):
        through = ", ".join(" -> ".join(t["path"]) for t in e["through"]) or "-"
        print(f"  [ESC] {e['caller']} gains {len(e['gained'])} resource(s) "
              f"it cannot reach on its own, through {through}")
        for g in e["gained"]:
            print(f"          {redact(g)}")
    for e in d.get("edges", []):
        # Not `a`: that is the parsed arguments, and rebinding it here cost the
        # output file on the first end to end run.
        for grant in e["authorised_by"]:
            print(f"  [edge] {e['caller']} may invoke {e['callee']}: "
                  f"{grant['role']} at {redact(grant['scope'])}")
            print(f"           decided by: {grant['basis']}")
        for carrier in e.get("carried_by", []):
            print(f"           carried by: {carrier['connection']}, authType "
                  f"{carrier['auth_type']} ({carrier['basis']})")
    for u in d.get("undecidable", []):
        print(f"  [undecidable] {u.get('caller')} -> {u.get('callee')}: "
              f"{u['why']}")

    print("cross-agent primitives:")
    for cp, present in f["cp"].items():
        print(f"  {cp}: {'PRESENT' if present else '-'}")
    json.dump(f, open(a.json, "w"), indent=2)
    print(f"written: {a.json}")


if __name__ == "__main__":
    main()

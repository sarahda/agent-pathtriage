#!/usr/bin/env python3
"""
AgentPathTriage - delegated invocation on Microsoft Foundry (CP-2)

The second cross-agent mechanism, and the one the lab on 2026-10-26 and
2026-10-31 actually demonstrated.

`foundry_cp.py` already implements identity passthrough: a connection whose
authType names a managed identity runs the downstream call under that identity,
so the caller borrows another principal's role assignments and `eff` grows
because `auth` of someone else is used. The caller ends up holding the callee's
permissions.

Delegated invocation is different, and no rule fired on it before this module.
The caller authenticates as itself. A role assignment authorises it to invoke
the callee. The callee then performs the privileged work with its own identity
and returns the result. The caller never holds the callee's role assignments.
It gains the callee's reach. `Esc(p)` is true under the same definition and for
a different reason, and a rule that only looks for a passthrough authType
returns zero on it.

  auth(p)  the (role, scope) assignments p holds directly
  eff(p)   auth(p), plus auth(q) for every q that p may invoke, transitively
  Esc(p)   eff(p) \\ auth(p) is not empty

Two conditions must both hold for an invocation edge p -> q:

  1. p's principal holds a role at a scope that contains q, and that role
     carries an agent invoke action.
  2. the connection that carries the call runs under p's OWN identity. If it
     runs under a managed identity, that is the passthrough mechanism and the
     other rule owns it. If it runs on behalf of an end user, then the user's
     authorisation gates the call and the finding is not about the two agents.

Which roles carry an invoke action is not guessed. The action strings and the
built-in roles that contain them are published:

  Microsoft.CognitiveServices/accounts/AIServices/endpoints/interact/action
  Microsoft.CognitiveServices/accounts/AIServices/applications/invoke/action
  https://learn.microsoft.com/en-us/azure/foundry/agents/concepts/hosted-agent-permissions
  https://learn.microsoft.com/en-us/azure/foundry/concepts/rbac-foundry

When the snapshot carries the role definitions' own actions, those are used and
the names are not consulted at all. The documented names are the fallback for a
snapshot that did not capture definitions, and every finding records which of
the two decided it, so a reader can tell an exact answer from a fallback one.

Where the inputs do not settle a question, the answer is `undecidable` and is
reported as such rather than as "no escalation". An agent with no recorded
scope, an authType whose identity is not documented and was not measured, and a
role whose definition is unknown and whose name is not a documented one all
produce an undecidable edge.

Nothing about any particular deployment is written into this file. Every
principal, scope, role and authType comes from the state or the snapshot.
"""

from __future__ import annotations

import re

# The data actions that authorise calling an agent. Either one is enough for an
# invocation edge: the endpoint action covers an agent endpoint, which is what
# an A2A connection targets, and the application action covers an agent
# application.
#
# Two spellings are accepted because the two authoritative sources disagree.
# The permissions reference writes the endpoint action without an `agents`
# segment; the role definitions this project captured from the subscription on
# 2026-10-25 write agent endpoint actions with one. Accepting only the
# documented spelling would match no real role definition.
#
# The leaf is restricted to `interact` and `invoke` on purpose.
# `agents/endpoints/UserIdentityImpersonation/action` is a real action on this
# path and is NOT here: it authorises calling an agent while impersonating a
# user, which is the user-delegated path. A finding resting on a user's
# permissions is not a finding about two agents.
INVOKE_ACTIONS = (
    "microsoft.cognitiveservices/accounts/aiservices/endpoints/interact/action",
    "microsoft.cognitiveservices/accounts/aiservices/agents/endpoints/interact/action",
    "microsoft.cognitiveservices/accounts/aiservices/applications/invoke/action",
    "microsoft.cognitiveservices/accounts/aiservices/agents/applications/invoke/action",
)

# Built-in roles documented as able to interact with an agent endpoint or invoke
# an agent application, used only when the snapshot carries no role definition.
# Owner and Contributor are deliberately absent: the permissions reference marks
# both as not granting agent interaction, which is unusual enough that assuming
# otherwise would be a false positive on most deployments.
DOCUMENTED_INVOKE_ROLES = {
    "foundry agent consumer",      # endpoints only, per the reference
    "foundry user",
    "foundry project manager",
    "foundry owner",
}

# An authType whose call executes as the calling AGENT's own identity, so the
# caller's own role assignment is what authorises the invocation. This is the
# class the rule fires on.
#
# `AgenticIdentityToken` is here on measurement, not on documentation. The lab
# granted Foundry Agent Consumer to the caller agent's instance identity and the
# call reached the callee; the grant was withdrawn and the same call was blocked;
# the grant was restored and it reached again. The published reference does not
# say which identity this authType resolves to, so the basis is recorded on
# every finding rather than presented as vendor documentation.
AGENT_IDENTITY_AUTH = {
    "agenticidentitytoken": (
        "measured in this project's lab on 2026-10-26 and 2026-10-31, not "
        "stated in the vendor reference"),
}

# An authType that runs the call under a managed identity. The passthrough rule
# in foundry_cp.py owns these, and this rule must not also fire on them, or one
# deployment would be counted as two different escalations.
MANAGED_IDENTITY_AUTH = {
    "accountmanagedidentity", "projectmanagedidentity",
    "managedidentity", "systemassignedidentity",
}

# An authType that runs the call on behalf of an end user. The user's own
# authorisation gates the downstream call, so a role assignment held by the
# caller agent is not what makes the call succeed and this is not a cross-agent
# finding.
USER_DELEGATED_AUTH = {"agentuserimpersonation", "agentonbehalfofuser", "aad"}


def normalise_scope(scope: str | None) -> str | None:
    """Lower case, no trailing separator. Azure resource ids are not case
    sensitive, and a trailing slash would break containment."""
    if not scope:
        return None
    s = str(scope).strip().rstrip("/")
    return s.lower() or "/"


def scope_contains(outer: str | None, inner: str | None) -> bool:
    """Does an assignment at `outer` apply to the resource at `inner`?

    Azure RBAC inherits downward along the resource id path, so containment is
    a path prefix and not a string prefix. The separator is required, otherwise
    a grant on `/resourceGroups/rg-a` would appear to cover `/rg-ab`.
    """
    o, i = normalise_scope(outer), normalise_scope(inner)
    if o is None or i is None:
        return False
    if o in ("", "/"):
        return True
    return i == o or i.startswith(o + "/")


def auth_identity_class(auth_type: str | None) -> tuple[str, str]:
    """Which identity executes the call, and on what basis.

    Returns one of agent, managed-identity, user-delegated, unknown, together
    with a sentence naming the source of the answer.
    """
    a = str(auth_type or "").strip().lower()
    if not a:
        return "unknown", "the snapshot records no authType for the connection"
    if a in AGENT_IDENTITY_AUTH:
        return "agent", AGENT_IDENTITY_AUTH[a]
    if a in MANAGED_IDENTITY_AUTH:
        return ("managed-identity",
                "the authType names a managed identity, so the passthrough "
                "rule owns this path")
    if a in USER_DELEGATED_AUTH:
        return ("user-delegated",
                "the authType runs the call on behalf of an end user, so the "
                "user's authorisation gates it")
    return "unknown", f"authType {auth_type!r} is not classified"


def role_invokes_agents(role_name: str | None,
                        role_definitions: dict | None) -> tuple[bool | None, str]:
    """Can a principal holding this role call an agent?

    Prefers the role definition's own actions, which is an exact answer. Falls
    back to the documented role names. Returns None when neither settles it, so
    an unknown custom role is undecidable instead of silently absent.
    """
    name = str(role_name or "").strip().lower()
    defs = {str(k).strip().lower(): v for k, v in (role_definitions or {}).items()}
    d = defs.get(name)
    if d:
        granted = _collect(d, ("actions", "data_actions", "dataActions"))
        excluded = _collect(d, ("not_actions", "notActions",
                                "not_data_actions", "notDataActions"))
        # An exclusion wins over a grant, wildcard grants included. A role can
        # hold dataActions ["*"] and still be denied the invoke action, which
        # is how Cognitive Services User is written.
        for pattern in excluded:
            hit = _covers(pattern)
            if hit:
                return False, (f"role definition excludes {hit} through "
                               f"{pattern}")
        for pattern in granted:
            hit = _covers(pattern)
            if hit:
                return True, f"role definition grants {hit} through {pattern}"
        return False, "role definition carries no agent invoke action"
    if name in DOCUMENTED_INVOKE_ROLES:
        return True, "documented built-in role, no definition in the snapshot"
    if not name:
        return None, "the assignment records no role name"
    return None, (f"role {role_name!r} is not a documented built-in role and "
                  "its definition is not in the snapshot")


def _collect(definition: dict, keys) -> list[str]:
    """Action strings under any of these keys, lower cased.

    Both spellings of each key are accepted, because az returns camelCase and
    the snapshot writer stores snake_case.
    """
    out = []
    for k in keys:
        for v in definition.get(k) or []:
            s = str(v).strip().lower()
            if s:
                out.append(s)
    return out


def _covers(pattern: str) -> str | None:
    """Which invoke action this action string covers, if any.

    An exact match, or a wildcard whose fixed part is a prefix of one. `*` on
    its own covers everything, which is how Owner is written.
    """
    for want in INVOKE_ACTIONS:
        if pattern == want:
            return want
        if pattern.endswith("*") and want.startswith(pattern[:-1]):
            return want
    return None


def _principal_of(agent: dict, identities: dict) -> str | None:
    """The principal whose grants authorise this agent's outbound calls.

    An agent created in the data plane carries its own instance identity, which
    never enters Terraform state, so the snapshot may name it directly. When it
    does not, the user assigned identity from the configuration is used.
    """
    pid = agent.get("instance_principal_id") or agent.get("principal_id")
    if pid:
        return str(pid)
    return identities.get(agent.get("identity"))


def _assignments_by_principal(assignments) -> dict:
    out: dict[str, list] = {}
    for a in assignments or []:
        if isinstance(a, dict):
            pid = a.get("principal_id") or a.get("principalId")
            role = a.get("role_definition_name") or a.get("roleDefinitionName")
            scope = a.get("scope")
        else:
            pid, role, scope = a
        if not pid:
            continue
        out.setdefault(str(pid), []).append(
            {"role": (role or "").strip(), "scope": scope})
    return out


def _agent_target_scopes(agent: dict) -> list[str]:
    """Every scope that names this agent, so a grant on any of them is an
    authorisation to call it. The agent application id and the endpoint id are
    different resources and a deployment may use either."""
    out = []
    for key in ("scope", "application_id", "applicationId",
                "endpoint_scope", "endpointScope", "id"):
        v = agent.get(key)
        if v:
            out.append(str(v))
    return out


def _connection_reaches(conn: dict, callee: dict) -> bool:
    """Does this connection carry calls to this callee?

    Matched on the connection target against the callee's scopes and name. A
    target is a URL and a scope is a resource id, so the agent name is the part
    they share.
    """
    # A connection that states a category which is not A2A is a tool, not a
    # carrier of an agent to agent call. Without this, a tool connection whose
    # target happens to contain the callee's name would be read as the path
    # the invocation travels on.
    blob = " ".join(str(conn.get(k) or "").lower()
                    for k in ("category", "type", "connection_type"))
    if blob.strip() and "a2a" not in blob:
        return False
    target = str(conn.get("target") or conn.get("id") or "").lower()
    if not target:
        return False
    for s in _agent_target_scopes(callee):
        tail = normalise_scope(s).rsplit("/", 1)[-1] if s else ""
        if tail and tail in target:
            return True
    name = str(callee.get("name") or "").lower()
    return bool(name) and re.search(rf"(^|[/_.-]){re.escape(name)}([/_.-]|$)",
                                    target) is not None


def invoke_edges(agents: dict, identities: dict) -> tuple[list, list]:
    """The invocation edges the inputs support, and the ones they cannot settle.

    An edge needs an authorising role assignment AND a connection that executes
    as the caller agent. Both are reported with the facts that decided them.
    """
    observed = agents.get("observed") or {}
    assignments = _assignments_by_principal(
        observed.get("role_assignments") or agents.get("role_assignments"))
    role_defs = observed.get("role_definitions") or agents.get("role_definitions")
    conns = observed.get("connections") or agents.get("connections") or []
    by_name = {a["name"]: a for a in agents.get("agents", [])}

    edges, undecidable = [], []
    for inv in agents.get("invocations", []):
        caller = by_name.get(inv.get("caller"))
        callee = by_name.get(inv.get("callee"))
        if not caller or not callee:
            undecidable.append({
                "caller": inv.get("caller"), "callee": inv.get("callee"),
                "why": "one of the two agents is not declared in the snapshot"})
            continue

        targets = _agent_target_scopes(callee)
        if not targets:
            undecidable.append({
                "caller": caller["name"], "callee": callee["name"],
                "why": ("the callee has no recorded scope, so no assignment can "
                        "be tested for containment of it")})
            continue

        pid = _principal_of(caller, identities)
        if not pid:
            undecidable.append({
                "caller": caller["name"], "callee": callee["name"],
                "why": "the caller's principal is not in the state or snapshot"})
            continue

        authorising, unknown_roles = [], []
        for a in assignments.get(pid, []):
            if not any(scope_contains(a["scope"], t) for t in targets):
                continue
            ok, basis = role_invokes_agents(a["role"], role_defs)
            if ok is True:
                authorising.append({"role": a["role"], "scope": a["scope"],
                                    "basis": basis})
            elif ok is None:
                unknown_roles.append({"role": a["role"], "scope": a["scope"],
                                      "basis": basis})

        carrying = [c for c in conns if _connection_reaches(c, callee)]
        classes = [auth_identity_class(c.get("auth_type") or c.get("authType"))
                   for c in carrying]
        agent_borne = [(c, b) for c, (k, b) in zip(carrying, classes)
                       if k == "agent"]
        unknown_borne = [(c, b) for c, (k, b) in zip(carrying, classes)
                         if k == "unknown"]

        if authorising and agent_borne:
            edges.append({
                "caller": caller["name"], "callee": callee["name"],
                "authorised_by": authorising,
                "carried_by": [{"connection": c.get("name") or c.get("id"),
                                "auth_type": c.get("auth_type") or c.get("authType"),
                                "basis": b} for c, b in agent_borne],
            })
            continue

        if not carrying:
            undecidable.append({
                "caller": caller["name"], "callee": callee["name"],
                "why": ("the snapshot records no connection from the caller to "
                        "the callee, so nothing says which identity a call "
                        "would execute as")})
        elif unknown_borne and authorising:
            undecidable.append({
                "caller": caller["name"], "callee": callee["name"],
                "why": ("the caller is authorised to call the callee, but the "
                        "connection's authType is not classified: "
                        + unknown_borne[0][1])})
        elif unknown_roles and agent_borne:
            undecidable.append({
                "caller": caller["name"], "callee": callee["name"],
                "why": ("the connection executes as the caller agent, but "
                        "whether its role authorises the call is unknown: "
                        + unknown_roles[0]["basis"])})
    return edges, undecidable


def _is_a2a(conn: dict) -> bool:
    """Is this connection an agent to agent link rather than a tool?

    An A2A connection is an invocation edge and is handled as one. Counting it
    as reach as well would report a single deployment as two findings.
    """
    blob = " ".join(str(conn.get(k) or "").lower()
                    for k in ("category", "type", "connection_type"))
    return "a2a" in blob


def _conn_resource(conn: dict) -> str | None:
    """The resource a connection reaches, as a resource id where possible.

    A role assignment names a resource id and a connection names a URL, and
    the two have to compare equal or an API key route and a role route to the
    same resource look like different reach. Azure connections carry the
    resource id in metadata, so it is used when present and the target is the
    fallback.
    """
    for key in ("resource_id", "resourceId"):
        v = conn.get(key)
        if v:
            return normalise_scope(v)
    md = conn.get("metadata")
    if isinstance(md, dict):
        for key in ("ResourceId", "resourceId", "resource_id"):
            v = md.get(key)
            if v:
                return normalise_scope(v)
    t = conn.get("target")
    return normalise_scope(t) if t else None


def _tool_reach(agent_name: str, agents: dict) -> dict:
    """Resources this agent's own tools reach, and how.

    An agent is credited with a connection when the snapshot says that agent's
    definition refers to it. Nothing is inferred from a connection merely
    existing in the same project: two agents in one project do not share each
    other's tools.
    """
    observed = agents.get("observed") or {}
    conns = observed.get("connections") or agents.get("connections") or []
    links = observed.get("agent_connections") or agents.get(
        "agent_connections") or []
    by_id = {}
    for c in conns:
        for key in ("id", "name"):
            if c.get(key):
                by_id[str(c[key]).strip().lower()] = c

    out = {}
    for link in links:
        if str(link.get("agent") or "") != agent_name:
            continue
        for key in ("connection_id", "connection"):
            c = by_id.get(str(link.get(key) or "").strip().lower())
            if c:
                break
        if not c or _is_a2a(c):
            continue
        res = _conn_resource(c)
        if not res:
            continue
        out[res] = (f"tool connection {c.get('name') or c.get('id')}, "
                    f"authType {c.get('auth_type') or c.get('authType') or 'unknown'}")
    return out


def _reach(principal, assignments, role_defs, agent_name=None,
           agents=None) -> dict:
    """Every resource this agent can act on, mapped to how it got there.

    Keyed by resource and not by role, so an API key route and a role route to
    the same resource are one entry. See this module's limits.
    """
    out = {}
    for a in assignments.get(str(principal), []):
        scope = normalise_scope(a["scope"])
        if not scope:
            continue
        out.setdefault(scope, f"role assignment {a['role']}")
    if agent_name and agents:
        for res, how in _tool_reach(agent_name, agents).items():
            out.setdefault(res, how)
    return out


def analyse_delegation(agents: dict, identities: dict) -> dict:
    """Esc for the delegated invocation mechanism, over the whole edge closure.

    A caller that may invoke a callee which may in turn invoke a third agent
    reaches the third agent's permissions too, so `eff` is the transitive
    closure rather than one hop. The path is reported, because a two hop
    finding is not readable without it.
    """
    observed = agents.get("observed") or {}
    assignments = _assignments_by_principal(
        observed.get("role_assignments") or agents.get("role_assignments"))
    role_defs = observed.get("role_definitions") or agents.get("role_definitions")
    by_name = {a["name"]: a for a in agents.get("agents", [])}

    # Every scope an agent occupies, read from the snapshot rather than
    # guessed from the shape of a resource id.
    agent_scopes = set()
    for a in agents.get("agents", []):
        for s in _agent_target_scopes(a):
            n = normalise_scope(s)
            if n:
                agent_scopes.add(n)

    edges, undecidable = invoke_edges(agents, identities)
    succ: dict[str, list] = {}
    for e in edges:
        succ.setdefault(e["caller"], []).append(e)

    results = []
    for name, agent in by_name.items():
        pid = _principal_of(agent, identities)
        if not pid:
            continue
        own = _reach(pid, assignments, role_defs, name, agents)

        # Breadth first over invocation edges, keeping the shortest path to
        # each agent so the finding can name how the reach was obtained.
        paths = {name: [name]}
        frontier, seen = [name], {name}
        while frontier:
            nxt = []
            for cur in frontier:
                for e in succ.get(cur, []):
                    q = e["callee"]
                    if q in seen:
                        continue
                    seen.add(q)
                    paths[q] = paths[cur] + [q]
                    nxt.append(q)
            frontier = nxt

        eff, contributors = dict(own), []
        for q in seen - {name}:
            qpid = _principal_of(by_name.get(q, {}), identities)
            if not qpid:
                continue
            qreach = _reach(qpid, assignments, role_defs, q, agents)
            new_here = {r: h for r, h in qreach.items() if r not in own}
            if new_here:
                contributors.append({
                    "agent": q, "path": paths[q], "hops": len(paths[q]) - 1,
                    "contributes": sorted(f"{r}  ({h})"
                                          for r, h in new_here.items())})
            for r, h in qreach.items():
                eff.setdefault(r, h)

        # Reaching another agent is a hop, not a prize. The AWS corpus showed
        # a three-tier orchestrator where each tier may invoke the next and
        # no tier holds anything else: counting agent scopes as gains makes
        # that two escalations when it is none. The agents reached are still
        # reported, because the path is what makes a two hop finding
        # readable. They do not decide Esc.
        gained_all = {r: h for r, h in eff.items() if r not in own}
        gained = {r: h for r, h in gained_all.items()
                  if r not in agent_scopes}
        gained_agents = {r: h for r, h in gained_all.items()
                         if r in agent_scopes}
        if gained:
            results.append({
                "caller": name,
                "mechanism": "delegated invocation",
                "gained": sorted(f"{r}  ({h})" for r, h in gained.items()),
                "agents_reached": sorted(gained_agents),
                "through": contributors,
                "own_resources": len(own),
                "effective_resources": len(eff),
            })

    return {
        "escalations": results,
        "edges": edges,
        "undecidable": undecidable,
        "mechanism": (
            "The caller authenticates as itself and a role assignment "
            "authorises it to invoke the callee, which performs the "
            "privileged work with its own identity. The caller never holds "
            "the callee's role assignments, so a rule that compares role sets "
            "after a passthrough connection does not fire on this. Esc is "
            "true because reach grows."),
        "limits": (
            "An authorised delegation and an escalation have the same shape "
            "here. The rule reports that reach grows and names the assignment "
            "that allows it; whether that was intended is a judgement the "
            "output supports rather than makes. Reach is keyed by resource "
            "and not by role, because an agent can reach a resource through a "
            "role assignment or through a tool connection holding a key, and "
            "the two must compare equal or the falsification case breaks. The "
            "cost is that holding a stronger role over something already "
            "reachable is not counted as a gain, which understates. A "
            "connection is credited to an agent only when the snapshot says "
            "that agent's definition refers to it. A scope that is itself an "
            "agent is a hop and not a gain: it is reported under "
            "agents_reached and does not decide Esc, because a chain of "
            "agents that ends in nothing is not an escalation."),
    }

#!/usr/bin/env python3
"""The delegated invocation rule, checked against the cells the lab ran.

Every cell of the A2A experiment is reproduced from a snapshot built in the
test, so the rule can be checked without an Azure subscription and a reviewer
can see which outcome each cell is supposed to produce. The cells and their
measured outcomes are in infra/foundry/FINDINGS-A2A-2026-10-26.md.

The snapshots here are shaped like the real lab rather than like a convenient
example, and the difference matters. The callee holds no role assignment at
all: it reaches the search index through a project connection carrying an API
key, because a Search connection does not authenticate as the agent. The
falsification cell gives the caller a Search Index Data Reader role over the
same search service. Those two routes have to compare equal, or the
falsification cell keeps reporting a gain and the rule is wrong exactly where
it most needs to be right. That is why reach is keyed by resource.

The three cells that matter are not the treatment. A rule that fires whenever
two agents can call each other passes the treatment and fails the control, the
negative control and the falsification.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from agentpathtriage.foundry_delegation import (  # noqa: E402
    analyse_delegation, auth_identity_class, invoke_edges,
    role_invokes_agents, scope_contains)

SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
RG = f"{SUB}/resourceGroups/rg-lab"
ACCOUNT = f"{RG}/providers/Microsoft.CognitiveServices/accounts/acct"
PROJ_A = f"{ACCOUNT}/projects/projA"
PROJ_B = f"{ACCOUNT}/projects/projB"
CALLER_SCOPE = f"{PROJ_A}/agents/caller"
CALLEE_SCOPE = f"{PROJ_B}/agents/callee"
SEARCH_ID = f"{RG}/providers/Microsoft.Search/searchServices/srch"
SEARCH_URL = "https://srch.search.windows.net"
A2A_TARGET = ("https://acct.services.ai.azure.com/api/projects/projB/agents"
              "/callee/endpoint/protocols/a2a")

CONSUMER = "Foundry Agent Consumer"
INDEX_READER = "Search Index Data Reader"


def snapshot(*, caller_may_invoke, auth_type, caller_has_index=False,
             invoke_scope=CALLEE_SCOPE, role_definitions=None,
             invoke_role=CONSUMER, callee_has_tool=True):
    """One cell of the experiment, as the analyser receives it.

    The callee's privilege is a tool connection and not a role, which is how
    the real lab is built.
    """
    ra = []
    if caller_may_invoke:
        ra.append({"principal_id": "pid-caller",
                   "role_definition_name": invoke_role,
                   "scope": invoke_scope})
    if caller_has_index:
        ra.append({"principal_id": "pid-caller",
                   "role_definition_name": INDEX_READER,
                   "scope": SEARCH_ID})

    conns = [{"name": "callee-a2a", "id": f"{PROJ_A}/connections/callee-a2a",
              "auth_type": auth_type, "target": A2A_TARGET,
              "category": "RemoteA2A", "project": "agentA"}]
    links = [{"agent": "caller", "connection": "callee-a2a",
              "connection_id": f"{PROJ_A}/connections/callee-a2a"}]
    if callee_has_tool:
        conns.append({"name": "search-b",
                      "id": f"{PROJ_B}/connections/search-b",
                      "auth_type": "ApiKey", "target": SEARCH_URL,
                      "category": "CognitiveSearch",
                      "resource_id": SEARCH_ID, "project": "agentB"})
        links.append({"agent": "callee", "connection": "search-b",
                      "connection_id": f"{PROJ_B}/connections/search-b"})

    return {
        "agents": [
            {"name": "caller", "project": "projA",
             "instance_principal_id": "pid-caller", "scope": CALLER_SCOPE},
            {"name": "callee", "project": "projB",
             "instance_principal_id": "pid-callee", "scope": CALLEE_SCOPE},
        ],
        "invocations": [{"caller": "caller", "callee": "callee"}],
        "observed": {
            "role_assignments": ra,
            "connections": conns,
            "agent_connections": links,
            "role_definitions": role_definitions or {},
        },
    }


def esc_for(result, name):
    return [e for e in result["escalations"] if e["caller"] == name]


# ----------------------------------------------------------- the cells ----

def test_treatment_reaches():
    """Caller holds Consumer at the callee's scope and the connection runs as
    the agent. Measured outcome: reached. The rule must report one escalation
    naming the search service, which the caller cannot reach on its own."""
    r = analyse_delegation(snapshot(caller_may_invoke=True,
                                    auth_type="AgenticIdentityToken"), {})
    e = esc_for(r, "caller")
    assert len(e) == 1, r
    assert len(e[0]["gained"]) == 1, e[0]["gained"]
    g = e[0]["gained"][0]
    # Scopes are normalised to lower case so they compare as paths.
    assert SEARCH_ID.lower() in g, g
    assert "apikey" in g.lower(), ("the finding must say the callee's route "
                                   f"is a key, not a role: {g}")
    assert e[0]["through"][0]["agent"] == "callee"
    assert e[0]["through"][0]["hops"] == 1
    assert not r["undecidable"], r["undecidable"]


def test_control_role_revoked_is_blocked():
    """The same deployment with the role assignment withdrawn. Measured
    outcome: blocked. No edge, no escalation, and nothing undecidable: the
    inputs settle it."""
    r = analyse_delegation(snapshot(caller_may_invoke=False,
                                    auth_type="AgenticIdentityToken"), {})
    assert r["escalations"] == []
    assert r["edges"] == []
    assert r["undecidable"] == [], r["undecidable"]


def test_negative_control_managed_identity_is_not_this_rule():
    """authType swapped to ProjectManagedIdentity. Measured outcome: blocked.
    A managed identity path belongs to the passthrough rule, so this rule
    stays silent rather than reporting one deployment twice."""
    r = analyse_delegation(snapshot(caller_may_invoke=True,
                                    auth_type="ProjectManagedIdentity"), {})
    assert r["escalations"] == []
    assert r["edges"] == []
    assert r["undecidable"] == []


def test_falsification_caller_already_reaches_the_resource():
    """Caller holds the index role on the search service while the callee gets
    there with a key. Measured outcome: reached, which is the point: reaching
    the data is not escalation when the caller could already reach it.

    This is the case that forces reach to be keyed by resource. As (role,
    scope) pairs, `Search Index Data Reader @ srch` and `ApiKey connection to
    srch` are different entries and the rule would still report a gain.
    """
    r = analyse_delegation(
        snapshot(caller_may_invoke=True, auth_type="AgenticIdentityToken",
                 caller_has_index=True), {})
    assert len(r["edges"]) == 1, r
    assert esc_for(r, "caller") == [], r["escalations"]


def test_a_callee_with_no_privilege_yields_no_escalation():
    """An invocation edge on its own is not a finding. If the callee reaches
    nothing the caller cannot, there is nothing to report, and this is the
    state the live lab was in on the first end to end run."""
    r = analyse_delegation(
        snapshot(caller_may_invoke=True, auth_type="AgenticIdentityToken",
                 callee_has_tool=False), {})
    assert len(r["edges"]) == 1
    assert r["escalations"] == []


def test_user_delegated_auth_is_not_a_cross_agent_finding():
    r = analyse_delegation(snapshot(caller_may_invoke=True,
                                    auth_type="AgentOnBehalfOfUser"), {})
    assert r["escalations"] == []
    assert r["undecidable"] == []


def test_unclassified_auth_type_is_undecidable_not_absent():
    """An authType nobody has documented or measured must not be reported as
    safe. The caller is authorised; only the executing identity is unknown."""
    r = analyse_delegation(snapshot(caller_may_invoke=True,
                                    auth_type="AgenticUser"), {})
    assert r["escalations"] == []
    assert len(r["undecidable"]) == 1, r["undecidable"]
    assert "not classified" in r["undecidable"][0]["why"]


# ------------------------------------------------------------- scoping ----

def test_grant_higher_up_the_scope_still_authorises():
    """Azure RBAC inherits downward, so a grant on the account covers an agent
    inside it. Missing this would understate the rule."""
    r = analyse_delegation(snapshot(caller_may_invoke=True,
                                    auth_type="AgenticIdentityToken",
                                    invoke_scope=ACCOUNT), {})
    assert len(esc_for(r, "caller")) == 1, r


def test_grant_on_a_sibling_scope_does_not_authorise():
    """The containment test is a path prefix, not a string prefix."""
    sibling = CALLEE_SCOPE.replace("/accounts/acct", "/accounts/acct2")
    r = analyse_delegation(snapshot(caller_may_invoke=True,
                                    auth_type="AgenticIdentityToken",
                                    invoke_scope=sibling), {})
    assert r["escalations"] == []
    assert r["edges"] == []


def test_resource_group_prefix_is_not_containment():
    assert scope_contains("/subscriptions/s/resourceGroups/rg-a",
                          "/subscriptions/s/resourceGroups/rg-a/providers/x")
    assert not scope_contains("/subscriptions/s/resourceGroups/rg-a",
                              "/subscriptions/s/resourceGroups/rg-ab/providers/x")
    assert scope_contains("/SUBSCRIPTIONS/S", "/subscriptions/s/resourceGroups/g")


# -------------------------------------------------------- tool reach ----

def test_a_tool_connection_is_credited_only_to_the_agent_that_uses_it():
    """Two agents in one project do not share each other's tools. Dropping the
    agent-to-connection link must remove the callee's reach, not leave it to
    be inferred from the connection existing."""
    s = snapshot(caller_may_invoke=True, auth_type="AgenticIdentityToken")
    s["observed"]["agent_connections"] = [
        x for x in s["observed"]["agent_connections"]
        if x["agent"] != "callee"]
    r = analyse_delegation(s, {})
    assert len(r["edges"]) == 1
    assert r["escalations"] == [], ("a connection nobody is recorded as using "
                                   "must not count as anyone's reach")


def test_the_a2a_connection_is_not_counted_as_reach():
    """The A2A connection is the invocation edge. Counting it as reach as well
    would report one deployment as two findings, and would make a caller with
    no privileged callee look like an escalation."""
    s = snapshot(caller_may_invoke=True, auth_type="AgenticIdentityToken",
                 callee_has_tool=False)
    s["observed"]["agent_connections"].append(
        {"agent": "callee", "connection": "callee-a2a",
         "connection_id": f"{PROJ_A}/connections/callee-a2a"})
    r = analyse_delegation(s, {})
    assert r["escalations"] == []


def test_a_tool_without_a_resource_id_falls_back_to_its_target():
    """Not every connection carries a resource id in its metadata. The target
    is then the only identifier, and reach is still counted."""
    s = snapshot(caller_may_invoke=True, auth_type="AgenticIdentityToken")
    for c in s["observed"]["connections"]:
        c.pop("resource_id", None)
    r = analyse_delegation(s, {})
    e = esc_for(r, "caller")
    assert len(e) == 1
    assert SEARCH_URL.lower() in e[0]["gained"][0], e[0]["gained"]


def test_two_hops_are_followed_and_the_path_is_named():
    """A caller that may invoke a middle agent which may invoke a third one
    reaches the third one's resources. One hop would miss it."""
    third_scope = f"{ACCOUNT}/projects/projC/agents/third"
    vault = f"{RG}/providers/Microsoft.KeyVault/vaults/kv"
    s = snapshot(caller_may_invoke=True, auth_type="AgenticIdentityToken",
                 callee_has_tool=False)
    s["agents"].append({"name": "third", "project": "projC",
                        "instance_principal_id": "pid-third",
                        "scope": third_scope})
    s["invocations"].append({"caller": "callee", "callee": "third"})
    s["observed"]["role_assignments"] += [
        {"principal_id": "pid-callee", "role_definition_name": CONSUMER,
         "scope": third_scope},
        {"principal_id": "pid-third",
         "role_definition_name": "Key Vault Secrets User", "scope": vault},
    ]
    s["observed"]["connections"].append(
        {"name": "third-a2a", "id": f"{PROJ_B}/connections/third-a2a",
         "auth_type": "AgenticIdentityToken", "category": "RemoteA2A",
         "target": A2A_TARGET.replace("projB/agents/callee",
                                      "projC/agents/third")})
    s["observed"]["agent_connections"].append(
        {"agent": "callee", "connection": "third-a2a",
         "connection_id": f"{PROJ_B}/connections/third-a2a"})
    r = analyse_delegation(s, {})
    e = esc_for(r, "caller")
    assert len(e) == 1, r
    assert any(vault.lower() in g for g in e[0]["gained"]), e[0]["gained"]
    hop2 = [t for t in e[0]["through"] if t["agent"] == "third"]
    assert hop2 and hop2[0]["path"] == ["caller", "callee", "third"], e[0]


# ---------------------------------------------------- role definitions ----

def test_role_definition_beats_the_name_list():
    """A custom role carrying the published action authorises the call even
    though its name is in no list."""
    defs = {"my-custom-caller": {"data_actions": [
        "Microsoft.CognitiveServices/accounts/AIServices/endpoints/"
        "interact/action"]}}
    ok, basis = role_invokes_agents("my-custom-caller", defs)
    assert ok is True and "action" in basis

    ok, _ = role_invokes_agents("Owner", {"owner": {"actions": ["*"]}})
    assert ok is True, "a wildcard action does cover the invoke action"

    ok, _ = role_invokes_agents("Reader", {"reader": {"actions": ["*/read"]}})
    assert ok is False


def test_documented_owner_and_contributor_are_not_invoke_capable():
    """The permissions reference marks Owner and Contributor as unable to
    interact with agents, so with no definition in hand neither may be assumed
    invoke-capable. Assuming otherwise would fire on most deployments."""
    assert role_invokes_agents("Owner", None)[0] is None
    assert role_invokes_agents("Contributor", None)[0] is None
    assert role_invokes_agents("Foundry Agent Consumer", None)[0] is True


def test_exclusion_overrides_a_wildcard_grant():
    """Cognitive Services User is written this way: a broad data action list
    with an agent action taken back out. Reading only the grants makes every
    deployment using such a role a false positive."""
    defs = {"broad-but-denied": {
        "data_actions": ["*"],
        "not_data_actions": [
            "Microsoft.CognitiveServices/accounts/AIServices/agents/"
            "endpoints/interact/action"]}}
    ok, basis = role_invokes_agents("broad-but-denied", defs)
    assert ok is False, basis
    assert "excludes" in basis


def test_both_action_spellings_are_accepted():
    """The permissions reference and the subscription disagree about an
    `agents` segment. Matching only the documented spelling would match no
    real role definition."""
    documented = {"r": {"data_actions": [
        "Microsoft.CognitiveServices/accounts/AIServices/endpoints/"
        "interact/action"]}}
    live = {"r": {"data_actions": [
        "Microsoft.CognitiveServices/accounts/AIServices/agents/endpoints/"
        "interact/action"]}}
    assert role_invokes_agents("r", documented)[0] is True
    assert role_invokes_agents("r", live)[0] is True


def test_user_impersonation_is_not_an_invoke_action():
    """`UserIdentityImpersonation` sits on the same path and means something
    else: calling an agent as a user. A rule about two agents must not fire on
    a permission that is about a user."""
    defs = {"impersonator": {"data_actions": [
        "Microsoft.CognitiveServices/accounts/AIServices/agents/endpoints/"
        "UserIdentityImpersonation/action"]}}
    assert role_invokes_agents("impersonator", defs)[0] is False


def test_unknown_custom_role_is_undecidable():
    r = analyse_delegation(snapshot(caller_may_invoke=True,
                                    auth_type="AgenticIdentityToken",
                                    invoke_role="some-custom-role"), {})
    assert r["escalations"] == []
    assert len(r["undecidable"]) == 1
    assert "not a documented built-in role" in r["undecidable"][0]["why"]


def test_against_the_role_definitions_captured_from_azure():
    """Run the matcher over the definitions this project pulled from the
    subscription, instead of over definitions written here.

    Cognitive Services User is the case that matters, and the answer is not the
    one the documentation implies. Its dataActions are
    `Microsoft.CognitiveServices/*` and its notDataActions exclude exactly
    three things, one of which is the agent user-impersonation action. The
    wildcard therefore still grants every other agent data action, including
    interacting with an agent endpoint, even though the permissions reference
    lists only four Foundry roles as able to do that and does not mention this
    role. Carving out one agent action and leaving the rest is evidence the
    exclusion was deliberate, which is why the matcher honours the wildcard.
    """
    p = (pathlib.Path(__file__).resolve().parent.parent
         / "infra" / "foundry" / "roles-evidence.json")
    if not p.exists():
        print("    (skipped: roles-evidence.json is not in the tree)")
        return
    import json
    rows = json.loads(p.read_text())["roles"]
    defs = {r["roleName"]: {"actions": r.get("actions") or [],
                            "data_actions": r.get("dataActions") or [],
                            "not_actions": r.get("notActions") or [],
                            "not_data_actions": r.get("notDataActions") or []}
            for r in rows}

    ok, basis = role_invokes_agents("Cognitive Services User", defs)
    assert ok is True, basis
    assert "microsoft.cognitiveservices/*" in basis, basis

    # Azure AI Developer is the contrast: its own description points at the
    # Foundry roles for project access, and it carries no agent action.
    assert role_invokes_agents("Azure AI Developer", defs)[0] is False

    for name in defs:
        ok, basis = role_invokes_agents(name, defs)
        assert ok in (True, False), f"{name} came back undecidable: {basis}"


def test_the_impersonation_exclusion_is_the_only_agent_carve_out():
    """Pins the fact the test above rests on, so a change to the captured
    evidence shows up here rather than silently changing a conclusion."""
    p = (pathlib.Path(__file__).resolve().parent.parent
         / "infra" / "foundry" / "roles-evidence.json")
    if not p.exists():
        print("    (skipped: roles-evidence.json is not in the tree)")
        return
    import json
    rows = json.loads(p.read_text())["roles"]
    csu = [r for r in rows if r["roleName"] == "Cognitive Services User"][0]
    assert csu["dataActions"] == ["Microsoft.CognitiveServices/*"]
    agent_excl = [x for x in csu["notDataActions"] if "/agents/" in x]
    assert agent_excl == [
        "Microsoft.CognitiveServices/accounts/AIServices/agents/endpoints/"
        "UserIdentityImpersonation/action"], agent_excl


# --------------------------------------------------------- plumbing ----

def test_callee_without_a_scope_is_undecidable():
    s = snapshot(caller_may_invoke=True, auth_type="AgenticIdentityToken")
    del s["agents"][1]["scope"]
    r = analyse_delegation(s, {})
    assert r["escalations"] == []
    assert len(r["undecidable"]) == 1
    assert "no recorded scope" in r["undecidable"][0]["why"]


def test_no_connection_recorded_is_undecidable():
    s = snapshot(caller_may_invoke=True, auth_type="AgenticIdentityToken")
    s["observed"]["connections"] = []
    r = analyse_delegation(s, {})
    assert r["escalations"] == []
    assert len(r["undecidable"]) == 1
    assert "no connection" in r["undecidable"][0]["why"]


def test_falls_back_to_the_configuration_identity_when_no_instance_identity():
    """An agent whose instance identity was not captured still resolves,
    through the user assigned identity in Terraform state."""
    s = snapshot(caller_may_invoke=True, auth_type="AgenticIdentityToken")
    del s["agents"][0]["instance_principal_id"]
    s["agents"][0]["identity"] = "id-caller"
    r = analyse_delegation(s, {"id-caller": "pid-caller"})
    assert len(esc_for(r, "caller")) == 1, r


def test_auth_identity_class_records_its_basis():
    kind, basis = auth_identity_class("AgenticIdentityToken")
    assert kind == "agent" and "lab" in basis
    assert auth_identity_class("ProjectManagedIdentity")[0] == "managed-identity"
    assert auth_identity_class(None)[0] == "unknown"


def test_edges_carry_the_facts_that_decided_them():
    edges, undecidable = invoke_edges(
        snapshot(caller_may_invoke=True, auth_type="AgenticIdentityToken"), {})
    assert len(edges) == 1 and not undecidable
    e = edges[0]
    assert e["authorised_by"][0]["role"] == CONSUMER
    assert e["authorised_by"][0]["scope"] == CALLEE_SCOPE
    assert e["carried_by"][0]["auth_type"] == "AgenticIdentityToken"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    bad = 0
    for f in fns:
        try:
            f()
            print(f"ok    {f.__name__}")
        except AssertionError as ex:
            bad += 1
            print(f"FAIL  {f.__name__}: {ex}")
    print(f"\n{len(fns) - bad}/{len(fns)} passed")
    sys.exit(1 if bad else 0)

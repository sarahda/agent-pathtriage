#!/usr/bin/env python3
"""Cross-agent escalation over A2A.

The claim:

    apt-caller cannot read the index. apt-callee can. apt-caller asks
    apt-callee over A2A and ends up holding what only apt-callee could
    reach. Remove apt-caller's permission to call apt-callee and the same
    request returns nothing.

Every parameter below comes from Microsoft's own pages, read before any of
this was run:

  agents/concepts/agent-identity
    Only two tools authenticate as the agent: MCP (AgenticIdentityToken,
    RemoteTool) and A2A (RemoteA2A). A Search tool does not, which is why
    the Search-axis run of 2026-10-25 could never have worked.

  agents/how-to/enable-agent-to-agent-endpoint
    Incoming A2A is a PATCH that sets agent_card and turns on the a2a
    protocol. The connection body is authType AgenticIdentityToken,
    category RemoteA2A, audience https://ai.azure.com, api-version
    2025-04-01-preview. The caller needs Foundry Agent Consumer
    (eed3b665-ab3a-47b6-8f48-c9382fb1dad6) on the target project or agent,
    assigned to the caller's instance_identity principal id.

Order, and what each step is for:

    python3 lab_a2a.py arm-callee     # give the callee something worth having
    python3 lab_a2a.py check-callee   # positive control: the callee can reach it
    python3 lab_a2a.py enable-callee  # expose the callee over A2A
    python3 lab_a2a.py connect        # the A2A connection on project A
    python3 lab_a2a.py grant          # caller may call callee
    python3 lab_a2a.py observe        # treatment
    python3 lab_a2a.py revoke
    python3 lab_a2a.py observe --label control
"""
import argparse
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CALLER, CALLEE = "apt-caller", "apt-callee"
INDEX = "apt-sensitive"
CANARY = "APT-CANARY-7F3A"
MODEL = "gpt-5.4-mini"
A2A_CONN = "callee-a2a"
SEARCH_CONN_B = "callee-search"
CONSUMER_ROLE = "eed3b665-ab3a-47b6-8f48-c9382fb1dad6"   # Foundry Agent Consumer
ARM_API_CONN = "2025-04-01-preview"


def sh(args):
    return subprocess.check_output(args, text=True, cwd=HERE)


def tf():
    """Lab outputs, read from terraform rather than written down anywhere.

    Every cell starts here, so a missing binary should say so once rather than
    surface as a traceback from whichever helper happened to run first.
    """
    try:
        raw = sh(["terraform", "output", "-json"])
    except FileNotFoundError:
        sys.exit("terraform is not on PATH in this shell. Every cell reads "
                 "the lab's identifiers from terraform output, so run them "
                 "in a terminal that has terraform and the Azure CLI.")
    except subprocess.CalledProcessError as e:
        sys.exit(f"terraform output failed: {e}. Run it by hand in "
                 "infra/foundry to see why.")
    return {k: v.get("value") for k, v in json.loads(raw).items()}


def account(t):
    return t["foundry_id"].rstrip("/").rsplit("/", 1)[-1]


def endpoint(t, project):
    return f"https://{account(t)}.services.ai.azure.com/api/projects/{project}"


def client(t, project):
    from azure.identity import DefaultAzureCredential
    from azure.ai.projects import AIProjectClient
    return AIProjectClient(endpoint=endpoint(t, project),
                           credential=DefaultAzureCredential())


def arm_token():
    from azure.identity import DefaultAzureCredential
    return DefaultAzureCredential().get_token(
        "https://management.azure.com/.default").token


def req(url, method="GET", headers=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw[:800]}


def callee_instance_id(t):
    return client(t, "agentB").agents.get(CALLEE).instance_identity


def caller_principal(t):
    d = client(t, "agentA").agents.get(CALLER).instance_identity
    return getattr(d, "principal_id", None) or (
        d.get("principal_id") if isinstance(d, dict) else None)


def callee_scope(t):
    return f"{t['projectB_id']}/agents/{CALLEE}"


def a2a_target(t):
    return (f"{endpoint(t, 'agentB')}/agents/{CALLEE}"
            f"/endpoint/protocols/a2a")


# --------------------------------------------------------- arm-callee ----
def cmd_arm_callee(a):
    """Give the callee a tool that reaches the index, and the caller none.

    The callee uses a key, not an identity, because a Search connection does
    not authenticate as the agent. That is fine for this experiment: what the
    caller gains is reach, and reach is what the predicate is about. The
    callee holds a credential the caller does not.
    """
    from azure.ai.projects.models import (
        PromptAgentDefinition, AzureAISearchTool, AzureAISearchToolResource,
        AISearchIndexResource, AzureAISearchQueryType)
    t = tf()
    key = json.loads(sh(["az", "search", "admin-key", "show",
                         "-g", t["resource_group"],
                         "--service-name", t["search_name"],
                         "-o", "json"]))["primaryKey"]
    url = (f"https://management.azure.com{t['projectB_id']}"
           f"/connections/{SEARCH_CONN_B}?api-version={ARM_API_CONN}")
    st, body = req(url, "PUT", {"Authorization": f"Bearer {arm_token()}"},
                   {"properties": {
                       "category": "CognitiveSearch",
                       "target": t["search_endpoint"],
                       "authType": "ApiKey",
                       "isSharedToAll": False,
                       "credentials": {"key": key},
                       "metadata": {"ResourceId": t["search_id"],
                                    "ApiType": "Azure"}}})
    print(f"callee search connection -> {st}")
    if st >= 400:
        print(json.dumps(body, indent=2)[:800])
        return 1

    c = client(t, "agentB")
    tool = AzureAISearchTool(
        azure_ai_search=AzureAISearchToolResource(indexes=[
            AISearchIndexResource(index_name=INDEX,
                                  project_connection_id=SEARCH_CONN_B,
                                  query_type=AzureAISearchQueryType.SIMPLE,
                                  top_k=5)]))
    v = c.agents.create_version(
        CALLEE,
        definition=PromptAgentDefinition(
            model=MODEL,
            instructions=("You hold the payout reconciliation notes. When "
                          "asked about them, search the index and report "
                          "what you find, quoting it exactly."),
            tools=[tool]))
    print("callee version:", getattr(v, "version", v))
    return 0


# ------------------------------------------------------- check-callee ----
def cmd_check_callee(a):
    """Positive control. Until the callee is seen to reach the index, a
    silent caller proves nothing."""
    t = tf()
    c = client(t, "agentB")
    oai = c.get_openai_client(agent_name=CALLEE)
    r = oai.responses.create(
        model=MODEL,
        input="Report the payout reconciliation notes, quoting them exactly.",
        extra_headers={"Accept-Encoding": "identity"})
    raw = r.model_dump()
    out = raw.get("output") or []
    types = [i.get("type") for i in out if isinstance(i, dict)]
    hit = CANARY in json.dumps(raw, default=str)
    print("output item types:", types)
    print(f"canary present   : {hit}")
    print("POSITIVE CONTROL:", "ok" if hit else "FAILED, stop here")
    return 0 if hit else 1


# ------------------------------------------------------ enable-callee ----
def cmd_enable_callee(a):
    from azure.ai.projects.models import (
        A2AProtocolConfiguration, AgentCard, AgentCardSkill,
        AgentEndpointConfig, ProtocolConfiguration,
        ResponsesProtocolConfiguration)
    t = tf()
    c = client(t, "agentB")
    patched = c.agents.update_details(
        agent_name=CALLEE,
        agent_endpoint=AgentEndpointConfig(
            protocol_configuration=ProtocolConfiguration(
                responses=ResponsesProtocolConfiguration(),
                a2a=A2AProtocolConfiguration())),
        agent_card=AgentCard(
            version="1.0",
            description="Holds the payout reconciliation notes.",
            skills=[AgentCardSkill(
                id="payout-notes", name="Payout notes",
                description="Reports the payout reconciliation notes.")]))
    print("incoming A2A enabled for:", getattr(patched, "name", patched))
    print("a2a base path:", a2a_target(t))
    return 0


# ------------------------------------------------------------ connect ----
def cmd_connect(a):
    t = tf()
    url = (f"https://management.azure.com{t['projectA_id']}"
           f"/connections/{A2A_CONN}?api-version={ARM_API_CONN}")
    st, body = req(url, "PUT", {"Authorization": f"Bearer {arm_token()}"},
                   {"properties": {
                       "authType": a.auth,
                       "category": "RemoteA2A",
                       "target": a2a_target(t),
                       "audience": "https://ai.azure.com",
                       "Credentials": {},
                       "metadata": {}}})
    print(f"A2A connection -> {st}")
    print(json.dumps(body, indent=2)[:900])
    if st < 400:
        _note_connect(a.auth, body)
    return 0 if st < 400 else 1


# ------------------------------------------------------- grant/revoke ----
# `az role assignment delete` exits non-zero when there is nothing to delete,
# and sh() captures stdout only, so the reason was not visible to the code.
# Both streams are captured here. Absent is what a revoke asks for, so it is
# not a failure, but a control cell still has to know which of the two
# happened.
NO_MATCH = "no matched assignments were found to delete"


def _az_role(cmd, verb):
    """Run an az role assignment command.

    Returns (ok, already_in_that_state). A delete that finds nothing is ok and
    already. Any other non-zero exit is not ok and the az output is printed,
    because "failed" on its own is not something a run can be judged from.
    """
    print(" ".join(cmd))
    try:
        r = subprocess.run(cmd, cwd=HERE, text=True, capture_output=True)
    except FileNotFoundError:
        # The bridge VM mounts the folders but not the Mac's binaries, so a
        # cell started from there dies here. Saying which binary is missing is
        # the difference between a one line fix and a confusing traceback.
        print("az is not on PATH in this shell. The role assignment cells "
              "need the Azure CLI, so run them in a terminal that has it.")
        return False, False
    text = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        if verb == "delete" and NO_MATCH in text.lower():
            print("nothing to delete: the assignment is not there. Treating "
                  "this as the requested state, not as a failure.")
            print("If it was expected to be there, something removed it "
                  "outside this script, and the run that depended on it is "
                  "not reproducible from this state.")
            return True, True
        print(f"az exited {r.returncode}")
        if text.strip():
            print(text.strip()[:700])
        return False, False
    if verb == "create":
        # create is idempotent and returns the existing assignment on
        # conflict, so createdOn is the only way to tell a new grant from one
        # that was already there.
        try:
            d = json.loads(r.stdout)
            d = d[0] if isinstance(d, list) and d else d
            print("assignment id:", d.get("id", "?"))
            print("createdOn:    ", d.get("createdOn", "?"),
                  "  <- today means this grant is new")
        except Exception:
            print((r.stdout or "")[:400])
    else:
        print((r.stdout or "").strip()[:400] or "deleted")
    return True, False


def _role(t, verb):
    pid = caller_principal(t)
    print(f"caller instance identity: {pid}")
    cmd = ["az", "role", "assignment", verb,
           "--assignee-object-id", pid,
           "--role", CONSUMER_ROLE, "--scope", callee_scope(t)]
    if verb == "create":
        cmd += ["--assignee-principal-type", "ServicePrincipal"]
    ok, already = _az_role(cmd, verb)
    if not ok:
        return 1
    if not already:
        print("\nWait for propagation before observing. Five minutes on this "
              "subscription for data-plane grants.")
    return 0


def _note_connect(auth, body):
    """Record what connect actually set.

    The SDK connection object does not expose authType, so an observe cannot
    read it back from the data plane. ARM can, but the ARM token expires
    independently of the data plane one, which is how a run came to be
    labelled for an auth type its connection never had. connect knows exactly
    what it set because the service echoed it in the 200, so it writes that
    here and observe reads it.
    """
    got = None
    if isinstance(body, dict):
        got = (body.get("properties") or {}).get("authType")
    os.makedirs(os.path.join(HERE, "runs"), exist_ok=True)
    with open(os.path.join(HERE, "runs", ".last_connect.json"), "w") as f:
        json.dump({"requested": auth, "confirmed_by_service": got,
                   "at": time.strftime("%Y-%m-%dT%H:%M:%S")}, f, indent=2)
    if got and got != auth:
        print(f"WARNING: asked for {auth}, service reports {got}")


def _read_connect_note():
    try:
        with open(os.path.join(HERE, "runs", ".last_connect.json")) as f:
            return json.load(f)
    except Exception:
        return {"confirmed_by_service": "unknown, no connect note"}


def cmd_grant(a):
    return _role(tf(), "create")


def cmd_revoke(a):
    return _role(tf(), "delete")


# -------------------------------------------------- falsification cell ----
INDEX_READER_ROLE = "Search Index Data Reader"


def _index_role(t, verb):
    """Put the index role on the caller itself.

    The treatment cell says the caller ends up holding index contents it does
    not have. That rests on auth(caller) excluding index read. This cell gives
    the caller's own instance identity the index role, so the same observed
    behaviour is no longer a gain. What should change is the verdict, not the
    trace: reach stays, escalation goes. Without this cell the treatment shows
    delegation working, not escalation.
    """
    pid = caller_principal(t)
    scope = t.get("search_id")
    if not scope:
        print("no search_id output: deploy_search is off")
        return 1
    print(f"caller instance identity: {pid}")
    cmd = ["az", "role", "assignment", verb,
           "--assignee-object-id", pid,
           "--role", INDEX_READER_ROLE, "--scope", scope]
    if verb == "create":
        cmd += ["--assignee-principal-type", "ServicePrincipal"]
    ok, already = _az_role(cmd, verb)
    if not ok:
        return 1
    if not already:
        print("\nWait for propagation before observing. Five minutes on this "
              "subscription for data-plane grants.")
    return 0


def cmd_falsify_grant(a):
    return _index_role(tf(), "create")


def cmd_falsify_revoke(a):
    return _index_role(tf(), "delete")


# ------------------------------------------------------------ observe ----
# ------------------------------------------------- PMI positive control ----
# The negative control set authType to ProjectManagedIdentity with the
# Consumer role still on the caller's instance identity, and was blocked.
# That has two readings: the role stopped applying because the acting
# principal changed, or ProjectManagedIdentity does not work for A2A at all.
# Microsoft Learn's A2A authentication page lists project managed identity as
# a supported A2A method and says it "requires role assignments on the
# underlying service", and system_identity.tf records that it resolves to the
# project's system-assigned identity. Granting the Consumer role to that
# principal and reaching with PMI leaves only the first reading.
def _pmi_role(t, verb, scope_kind="agent"):
    """Consumer on the principal ProjectManagedIdentity resolves to.

    scope_kind picks which of the two scopes the vendor page allows:

      agent    the callee's agent scope, which authorises calls to that one
               agent endpoint
      project  the callee's project scope, which authorises calls to every
               agent endpoint in the project

    Both are documented, and the two cells that came back blocked used the
    agent scope, so the project scope is a different reading of the same
    instruction rather than a guess.
    https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/enable-agent-to-agent-endpoint
    """
    pid = t.get("projectA_sa_principal_id")
    if not pid:
        print("no projectA_sa_principal_id output. The account was applied "
              "with UserAssigned only, so there is no system-assigned "
              "principal for ProjectManagedIdentity to resolve to, and this "
              "cell cannot run. See system_identity.tf.")
        return 2
    if scope_kind == "project":
        scope = t.get("projectB_id")
        if not scope:
            print("no projectB_id output, so the project scope cannot be "
                  "formed.")
            return 2
    elif scope_kind == "agent":
        scope = callee_scope(t)
    else:
        print(f"unknown scope kind {scope_kind!r}")
        return 2
    print(f"project A system-assigned identity: {pid}")
    print(f"caller instance identity (for contrast): {caller_principal(t)}")
    print(f"grant scope ({scope_kind}): {scope}")
    cmd = ["az", "role", "assignment", verb,
           "--assignee-object-id", pid,
           "--role", CONSUMER_ROLE, "--scope", scope]
    if verb == "create":
        cmd += ["--assignee-principal-type", "ServicePrincipal"]
    # Same helper as the other two cells: an absent assignment on delete is
    # the requested state, and an az failure for any other reason says why.
    ok, already = _az_role(cmd, verb)
    if not ok:
        return 1
    if not already:
        print("\nWait for propagation before observing. Five minutes on this "
              "subscription for data-plane grants.")
    return 0


def cmd_pmi_grant(a):
    return _pmi_role(tf(), "create")


def cmd_pmi_grant_project(a):
    return _pmi_role(tf(), "create", "project")


def cmd_pmi_revoke_project(a):
    return _pmi_role(tf(), "delete", "project")


def cmd_pmi_revoke(a):
    return _pmi_role(tf(), "delete")
def _build_tool(A2ATool, A2AProtocolVersion, conn_id, want_card_credentials):
    """Build the A2A tool, and report what was actually set, not what was asked.

    Microsoft Learn documents send_credentials_for_agent_card as a property of
    the A2A tool definition, defaulting to false, which is why the agent card
    fetch goes out anonymously unless it is set. The installed SDK may predate
    the property. Asking for it and silently not getting it would mislabel the
    run, the same way an unrecorded authType mislabelled one on 2026-10-31, so
    the value that ends up on the object is what gets recorded.
    """
    kw = dict(a2a_version=A2AProtocolVersion.V1_0, project_connection_id=conn_id)
    if want_card_credentials:
        try:
            tool = A2ATool(send_credentials_for_agent_card=True, **kw)
        except TypeError:
            tool = A2ATool(**kw)
            try:
                setattr(tool, "send_credentials_for_agent_card", True)
            except Exception:
                pass
    else:
        tool = A2ATool(**kw)
    got = getattr(tool, "send_credentials_for_agent_card", "absent from the SDK")
    if want_card_credentials and got is not True:
        print(f"WARNING: asked to send credentials on the agent card request, "
              f"the tool object reports {got!r}. This run is not the "
              f"send_credentials cell.")
    print("send_credentials_for_agent_card as built:", got)
    return tool, got


def cmd_observe(a):
    from azure.ai.projects.models import (
        A2AProtocolVersion, A2ATool, PromptAgentDefinition)
    t = tf()
    c = client(t, "agentA")
    conn = c.connections.get(A2A_CONN)
    print("a2a connection id:", conn.id)
    cstate = _conn_state(conn)
    cstate["auth_type_from_last_connect"] = _read_connect_note()
    print("connection as executed:",
          {k: v for k, v in cstate.items() if k != "raw"})

    want = getattr(a, "expect_auth", None)
    live = cstate.get("auth_type_live")
    if want:
        if not live:
            print(f"\nstop: --expect-auth {want} was given and the live "
                  f"connection does not report an auth type, so the cell "
                  f"cannot be confirmed. Nothing written.")
            return 2
        if live.lower() != want.lower():
            print(f"\nstop: --expect-auth {want}, live connection is {live}. "
                  f"The connect for this cell did not take effect, so this "
                  f"observation is a different cell than the label says. "
                  f"Nothing written. Re-run connect and check its status "
                  f"before observing.")
            return 2
        print(f"auth type confirmed against the live connection: {live}")
    elif live:
        print(f"auth type on the live connection: {live} "
              f"(no --expect-auth given, so nothing is being checked)")

    tool, card_cred = _build_tool(A2ATool, A2AProtocolVersion, conn.id,
                                  getattr(a, "send_card_credentials", False))
    cstate["send_credentials_for_agent_card"] = card_cred
    v = c.agents.create_version(
        CALLER,
        definition=PromptAgentDefinition(
            model=MODEL,
            instructions=("You cannot read any index yourself. Use the A2A "
                          "tool to ask the other agent for the payout "
                          "reconciliation notes, and report exactly what it "
                          "returns."),
            tools=[tool]))
    print("caller version:", getattr(v, "version", v))

    prompt = ("Ask the other agent for the payout reconciliation notes and "
              "report exactly what it returns, including any key.")
    oai = c.get_openai_client(agent_name=CALLER)
    try:
        r = oai.responses.create(model=MODEL, input=prompt,
                                 extra_headers={"Accept-Encoding": "identity"})
    except Exception as e:
        st = getattr(e, "status_code", None)
        body = ""
        resp = getattr(e, "response", None)
        if resp is not None:
            try:
                body = resp.text[:600]
            except Exception:
                pass
        print(f"\\ninvocation error {type(e).__name__}"
              f"{f' [{st}]' if st else ''}: {str(e)[:400]}")
        if body:
            print("body:", body)
        denied = "tool_user_error" in body or "Access denied" in body or \
                 "Forbidden" in body or (st == 403)
        verdict = "blocked" if denied else "error"
        # Whether the agent tried at all is a layer above the access
        # decision, and a blocked cell is only evidence if it tried. The
        # model does not always call the tool: on 2026-10-31 the same
        # configuration called it once and narrated instead twice. An error
        # body naming the agent card or the tool is proof the call path ran.
        attempted = ("agent card" in body.lower() or "tool_user_error" in body
                     or "a2a" in body.lower())
        _record(a, verdict, {"error": str(e)[:600], "body": body},
                {"a2a_called": attempted, "from": "error path",
                 "retrieved": False, "disclosed": False}, cstate)
        print(f"a2a tool ATTEMPTED  : {attempted}   <- read from the error")
        print(f"VERDICT: {verdict}")
        return 0 if denied else 1

    raw = r.model_dump()
    out = raw.get("output") or []
    types = [i.get("type") for i in out if isinstance(i, dict)]
    tool_out = [i for i in out if isinstance(i, dict)
                and "call_output" in str(i.get("type"))]
    msgs = [i for i in out if isinstance(i, dict) and i.get("type") == "message"]
    retrieved = CANARY in json.dumps(tool_out, default=str)
    disclosed = CANARY in json.dumps(msgs, default=str)
    called = any(t_ and "call" in str(t_) and "a2a" in str(t_).lower()
                 for t_ in types)
    verdict = "reached" if retrieved else "blocked"

    print("\\n" + "-" * 60)
    print((getattr(r, "output_text", "") or "")[:1200])
    print("-" * 60)
    print("output item types   :", types)
    print(f"canary via the tool : {retrieved}   <- the access decision")
    print(f"canary in the answer: {disclosed}   <- the model's choice")
    print(f"a2a tool CALLED     : {called}")
    print(f"VERDICT: {verdict}")
    if not retrieved and not called:
        print("\\nThe caller did not call the tool at all. That is not a "
              "refusal. Read the raw record before recording this.")
    _record(a, verdict, raw, {"retrieved": retrieved, "disclosed": disclosed,
                              "a2a_called": called, "types": types}, cstate)
    return 0


def _conn_state(conn):
    """What the connection says right now, not what the label claims.

    On 2026-10-31 a connect command failed on an expired ARM token, the
    observe that followed ran anyway on the data plane token, and the run file
    carried a label naming an auth type the connection never had. Every run
    now records the live connection so a mislabelled one is visible in the
    artifact rather than only in the terminal scrollback.
    """
    d = {}
    for attr in ("id", "name", "type", "category", "auth_type", "authType"):
        v = getattr(conn, attr, None)
        if v is not None:
            d[attr] = str(v)[:300]
    props = getattr(conn, "properties", None)
    if props is not None:
        for attr in ("auth_type", "authType", "category", "audience",
                     "target"):
            v = getattr(props, attr, None)
            if v is not None:
                d["properties." + attr] = str(v)[:300]
    for meth in ("as_dict", "to_dict"):
        f = getattr(conn, meth, None)
        if callable(f):
            try:
                raw = f()
                d["raw"] = {k: str(v)[:300] for k, v in raw.items()}
                # The note above said the SDK does not expose the auth type,
                # which is why the connect sidecar exists. That was wrong: it
                # is under credentials.type on the serialised connection. This
                # reads the live object, so it is a better guard than a note
                # written by a previous command, and it is what --expect-auth
                # is checked against. The sidecar stays as a second opinion.
                cred = raw.get("credentials")
                if isinstance(cred, str):
                    try:
                        cred = json.loads(cred.replace("'", '"'))
                    except Exception:
                        cred = None
                if isinstance(cred, dict) and cred.get("type"):
                    d["auth_type_live"] = str(cred["type"])
                break
            except Exception:
                pass
    return d


def _record(a, verdict, raw, flags, conn_state=None):
    """Write one observation, with real GUIDs replaced before it hits disk.

    conn_state carries the connection's full resource id, which carries the
    subscription id. Seven run files were committed with it before this was
    noticed. The redaction happens here, at the point of writing, because one
    applied to the files afterwards comes back on the next run. Each distinct
    GUID keeps its own placeholder, so the caller, the callee and the project
    stay distinguishable, which the cells depend on. See redact.py.
    """
    os.makedirs(os.path.join(HERE, "runs"), exist_ok=True)
    tag = f"a2a{('-' + a.label) if a.label else ''}"
    out = os.path.join(HERE, "runs",
                       f"{tag}-{time.strftime('%Y%m%dT%H%M%S')}.json")
    payload = {"axis": "a2a_caller_may_invoke_callee", "verdict": verdict,
               "label": a.label, "caller": CALLER, "callee": CALLEE,
               "index": INDEX, "connection_as_executed": conn_state,
               "flags": flags, "raw": raw}
    # Round trip through json first, so default=str has already turned SDK
    # objects into strings and the redactor sees every GUID as text.
    payload = json.loads(json.dumps(payload, default=str))
    try:
        sys.path.insert(0, HERE)
        from redact import Redactor
        r = Redactor()
        payload = r.obj(payload)
        r.save()
    except Exception as e:
        # A run that cannot be redacted is still a run, but it must not be
        # written somewhere it might be committed by accident.
        out = out + ".UNREDACTED"
        print(f"redaction unavailable ({type(e).__name__}: {e}). Writing to "
              f"{os.path.basename(out)} so it is not committed by mistake.")
    with open(out, "w") as f:
        json.dump(payload, f, indent=2, default=str)
    print(f"wrote {out}")


# ------------------------------------------------------------- diag ----
# Categories to enable if the resource supports them. The list is filtered
# against what the resource actually reports, because enabling a category a
# resource does not have fails the whole setting.
# Everything the resource reports as supported, rather than a list written
# here. A negative result ("the denial is in none of them") only holds if
# none was left off, and the set differs by account and changes over time.


def _workspace_name(t):
    """Derived from the account, so two labs do not share a workspace and
    nothing is written down here."""
    return f"law-{account(t)}"


def cmd_diag_on(a):
    """Send the account's resource logs to a Log Analytics workspace.

    Creates the workspace if it is not there, asks the resource which log
    categories it supports, and enables the ones this lab wants that the
    resource has.
    """
    t = tf()
    rg, acct_id = t["resource_group"], t["foundry_id"]
    ws_name = a.workspace or _workspace_name(t)

    ok, ws = _az_json(["az", "monitor", "log-analytics", "workspace", "show",
                       "-g", rg, "-n", ws_name, "-o", "json"])
    if not ok or not ws:
        print(f"creating workspace {ws_name}")
        ok, ws = _az_json(["az", "monitor", "log-analytics", "workspace",
                           "create", "-g", rg, "-n", ws_name,
                           "--retention-time", "30", "-o", "json"])
        if not ok or not ws:
            print("stop: could not create the workspace. Without it there is "
                  "nowhere for the logs to go and nothing is enabled.")
            return 2
    else:
        print(f"workspace {ws_name} already exists")
    print(f"workspace customerId: {ws.get('customerId')}")

    ok, cats = _az_json(["az", "monitor", "diagnostic-settings", "categories",
                         "list", "--resource", acct_id, "-o", "json"])
    if not ok:
        print("stop: could not list the supported log categories. Enabling a "
              "category the resource does not have fails the whole setting, "
              "so nothing is enabled.")
        return 2
    supported = {c.get("name") for c in (cats or {}).get("value", [])
                 if c.get("categoryType") == "Logs"}
    enable = sorted(supported)
    print(f"log categories this resource supports, all of which are being "
          f"enabled: {', '.join(enable) or 'none reported'}")
    if not enable:
        print("stop: the resource reports no log categories, so there is "
              "nothing to enable and nothing to conclude from an empty "
              "workspace.")
        return 2

    logs = json.dumps([{"category": c, "enabled": True} for c in enable])
    ok, out = _az_json(["az", "monitor", "diagnostic-settings", "create",
                        "--name", "apt-lab-diag", "--resource", acct_id,
                        "--workspace", ws["id"], "--logs", logs, "-o", "json"])
    if not ok:
        print("stop: the diagnostic setting was not created.")
        return 2
    print(f"enabled: {', '.join(enable)}")
    print("\nLogs take a few minutes to start arriving, and the first record "
          "for a category can take longer. Run a cell, then read them with:")
    print("  python3 lab_a2a.py diag-query")
    return 0


def cmd_diag_query(a):
    """Print what the account actually logged, fields and all.

    The categories' contents are undocumented, so this prints whole records
    instead of chosen columns. A field that turns out to carry the status code
    or the caller identity is what makes a blocked verdict a logged decision
    rather than an inference, and it cannot be projected before it is known to
    exist.
    """
    t = tf()
    ws_name = a.workspace or _workspace_name(t)
    ok, ws = _az_json(["az", "monitor", "log-analytics", "workspace", "show",
                       "-g", t["resource_group"], "-n", ws_name, "-o", "json"])
    if not ok or not ws:
        print(f"no workspace {ws_name}. Run diag-on first.")
        return 2
    wsid = ws.get("customerId")

    counts = (f'AzureDiagnostics | where TimeGenerated > ago({a.hours}h) '
              f'| summarize n=count() by Category | order by n desc')
    ok, res = _az_json(["az", "monitor", "log-analytics", "query",
                        "-w", wsid, "--analytics-query", counts, "-o", "json"])
    if not ok:
        print("the query failed. If az says the command is not found, add the "
              "extension once with:  az extension add --name log-analytics")
        return 2
    if not res:
        print(f"nothing logged in the last {a.hours}h yet. Records can take "
              f"several minutes to arrive, and a category with no matching "
              f"activity stays empty, which is itself an answer.")
        return 0
    print(f"records in the last {a.hours}h, by category:")
    for row in res:
        print(f"  {row.get('Category')}: {row.get('n')}")

    rows_q = (f'AzureDiagnostics | where TimeGenerated > ago({a.hours}h) '
              f'| order by TimeGenerated desc | take {a.take}')
    ok, rows = _az_json(["az", "monitor", "log-analytics", "query",
                         "-w", wsid, "--analytics-query", rows_q, "-o", "json"])
    if not ok or not rows:
        return 0
    print(f"\nthe {len(rows)} most recent records, non-empty fields only:")
    for i, row in enumerate(rows, 1):
        print(f"\n--- record {i} ---")
        for k, v in sorted(row.items()):
            if v in (None, "", [], {}):
                continue
            s = str(v)
            print(f"  {k}: {s[:300]}")
    out = os.path.join(HERE, "runs",
                       f"diag-{time.strftime('%Y%m%dT%H%M%S')}.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    payload = json.loads(json.dumps({"by_category": res, "records": rows},
                                    default=str))
    try:
        sys.path.insert(0, HERE)
        from redact import Redactor
        r = Redactor()
        payload = r.obj(payload)
        r.save()
    except Exception as e:
        out = out + ".UNREDACTED"
        print(f"\nredaction unavailable ({type(e).__name__}: {e}); writing to "
              f"{os.path.basename(out)} so it is not committed.")
    with open(out, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\nwrote {out}")
    return 0


# ---------------------------------------------------------- snapshot ----
def _az_json(cmd):
    """Run an az command that returns JSON.

    Returns (ok, parsed). A failure prints what az said, because an empty list
    and a failed call mean completely different things to a rule that reports
    "no escalation" when it sees no assignments.
    """
    try:
        r = subprocess.run(cmd, cwd=HERE, text=True, capture_output=True)
    except FileNotFoundError:
        print("az is not on PATH in this shell. The snapshot reads the live "
              "role assignments, so run it in a terminal that has the "
              "Azure CLI.")
        return False, None
    if r.returncode != 0:
        print(" ".join(cmd))
        print(f"az exited {r.returncode}")
        print(((r.stdout or "") + (r.stderr or "")).strip()[:600])
        return False, None
    try:
        return True, json.loads(r.stdout or "null")
    except Exception as e:
        print(f"az returned something that is not json: {e}")
        return False, None


def _instance_principal(t, project, name):
    """The principal an agent runs as, read from the agent itself."""
    d = client(t, project).agents.get(name).instance_identity
    pid = getattr(d, "principal_id", None)
    if pid is None and isinstance(d, dict):
        pid = d.get("principal_id")
    return pid


def cmd_snapshot(a):
    """Write the agent layer, so the analyser can evaluate the predicate on it.

    What this collects and why each piece is needed:

      instance identities   the principal the live grants were made to. The
                            identity in Terraform is a different principal, so
                            an analyser reading only the configuration tests
                            the wrong one.
      role assignments      the Consumer grant that authorises the call and the
                            index role that makes the callee privileged.
                            Neither is in Terraform.
      role definitions      the actions each role carries, so the rule decides
                            from the definition rather than from the role's
                            name.
      the A2A connection    its target and the identity it executes as, which
                            decides whether this is delegated invocation or
                            identity passthrough.
    """
    t = tf()
    out_path = a.out or os.path.join(HERE, "agents_observed.json")

    agents, principals = [], {}
    # (data-plane project, agent name, the terraform output holding the
    # project's resource id). Named rather than derived, so a renamed output
    # fails here with a KeyError instead of silently producing a scope that
    # nothing contains.
    for project, name, id_output in (("agentA", CALLER, "projectA_id"),
                                     ("agentB", CALLEE, "projectB_id")):
        pid = _instance_principal(t, project, name)
        if not pid:
            print(f"stop: {name} reports no instance identity principal. "
                  f"Nothing written: a snapshot missing a principal would "
                  f"make the rule return no escalation for the wrong reason.")
            return 2
        principals[name] = pid
        scope = f"{t[id_output]}/agents/{name}"
        agents.append({"name": name, "project": project,
                       "instance_principal_id": pid, "scope": scope})
        print(f"{name}: principal {pid}")
        print(f"{' ' * len(name)}  scope {scope}")

    # The principals a managed-identity authType resolves to. A connection set
    # to ProjectManagedIdentity executes as the project's system-assigned
    # identity, so that is where its authorisation sits and a snapshot that
    # omits it cannot represent such a deployment. Collected as principals,
    # not as agents, because they are neither.
    identity_principals = []
    for project, output in (("agentA", "projectA_sa_principal_id"),
                            ("agentB", "projectB_sa_principal_id")):
        pid = t.get(output)
        if not pid:
            continue
        identity_principals.append({
            "principal_id": pid,
            "kind": "project system-assigned identity",
            "project": project,
            "resolves_for_auth_types": ["ProjectManagedIdentity"],
        })
        print(f"{project} system-assigned identity: {pid}")
    acct = t.get("foundry_sa_principal_id")
    if acct:
        identity_principals.append({
            "principal_id": acct,
            "kind": "account system-assigned identity",
            "project": None,
            "resolves_for_auth_types": ["AccountManagedIdentity"],
        })
        print(f"account system-assigned identity: {acct}")

    # --assignee-object-id, not --assignee. The second form resolves the
    # assignee through Graph and returns an empty list with exit status 0 when
    # it cannot resolve it, which is indistinguishable from a principal that
    # holds nothing. The grant and revoke commands above already use the
    # object id form for the same reason.
    assignments, failed, disagreed = [], [], []
    scopes = {a["name"]: a["scope"] for a in agents}
    for ip in identity_principals:
        principals[f"{ip['kind']} ({ip['project'] or 'account'})"] = \
            ip["principal_id"]
    for name, pid in principals.items():
        ok, rows = _az_json(["az", "role", "assignment", "list", "--all",
                             "--assignee-object-id", pid, "-o", "json"])
        if not ok:
            failed.append(name)
            continue
        rows = rows or []

        # Cross-check. An empty subscription-wide answer is the one that can be
        # wrong without saying so, so it is the one that gets checked, against
        # a query at the scope where this lab's grants are actually made.
        for other, scope in scopes.items():
            ok2, rows2 = _az_json(["az", "role", "assignment", "list",
                                   "--assignee-object-id", pid,
                                   "--scope", scope, "--include-inherited",
                                   "-o", "json"])
            if not ok2:
                continue
            extra = [r for r in (rows2 or [])
                     if r.get("id") not in {x.get("id") for x in rows}]
            if extra:
                disagreed.append(
                    f"{name} at {other}'s scope: the subscription-wide query "
                    f"returned {len(rows)} assignment(s) and the scoped query "
                    f"found {len(extra)} more")
                rows = rows + extra

        for row in rows:
            assignments.append({
                "principal_id": row.get("principalId") or pid,
                "role_definition_name": row.get("roleDefinitionName"),
                "role_definition_id": row.get("roleDefinitionId"),
                "scope": row.get("scope"),
                "for_agent": name,
            })
        print(f"{name}: {len(rows)} role assignment(s)")

    if failed:
        print(f"\nstop: could not list role assignments for "
              f"{', '.join(failed)}. Nothing written, because a snapshot with "
              f"an empty assignment list looks exactly like a deployment with "
              f"no grants.")
        return 2

    if disagreed:
        print("\nthe two queries disagreed, and the scoped results were kept:")
        for d in disagreed:
            print("  " + d)

    if not assignments:
        print("\nNo role assignment on any principal. That is a real state "
              "of this lab, not an error: it is what the control and the PMI "
              "positive control cells leave behind. The snapshot records it, "
              "and the rule should report no invocation edge. To get the "
              "treatment state back, run `python3 lab_a2a.py cell treatment`, "
              "which grants and waits, then take the snapshot again.")

    definitions = {}
    for nm in sorted({x["role_definition_name"] for x in assignments
                      if x.get("role_definition_name")}):
        ok, rows = _az_json(["az", "role", "definition", "list",
                             "--name", nm, "-o", "json"])
        if not ok or not rows:
            print(f"role definition for {nm!r} not captured; the rule will "
                  f"fall back to the documented role names for it")
            continue
        acts, dacts, nacts = [], [], []
        for perm in (rows[0].get("permissions") or []):
            acts += perm.get("actions") or []
            dacts += perm.get("dataActions") or []
            nacts += perm.get("notActions") or []
        definitions[nm] = {"actions": acts, "data_actions": dacts,
                           "not_actions": nacts}
    print(f"role definitions captured: {len(definitions)}")

    # Every connection on every project, not only the A2A one. A tool
    # connection is how an agent reaches a resource when it holds no role, and
    # the callee in this lab is exactly that case.
    connections = []
    for project in ("agentA", "agentB"):
        try:
            listed = list(client(t, project).connections.list())
        except Exception as e:
            print(f"could not list connections on {project} "
                  f"({type(e).__name__}: {e})")
            continue
        for conn in listed:
            cstate = _conn_state(conn)
            raw = cstate.get("raw") or {}
            md = raw.get("metadata")
            if isinstance(md, str):
                try:
                    md = json.loads(md.replace("'", '"'))
                except Exception:
                    md = {}
            resource_id = None
            if isinstance(md, dict):
                resource_id = (md.get("ResourceId") or md.get("resourceId")
                               or md.get("resource_id"))
            connections.append({
                "name": cstate.get("name"),
                "id": cstate.get("id"),
                "auth_type": cstate.get("auth_type_live"),
                "target": raw.get("target") or cstate.get("properties.target"),
                "category": raw.get("category") or cstate.get("category")
                or cstate.get("properties.category"),
                "type": raw.get("type") or cstate.get("type"),
                "resource_id": resource_id,
                "project": project,
            })
            kind = (connections[-1]["category"] or connections[-1]["type"]
                    or "unclassified")
            print(f"connection {cstate.get('name')} on {project}: "
                  f"kind {kind}, authType "
                  f"{cstate.get('auth_type_live') or 'not reported'}"
                  + (f", resource {resource_id}" if resource_id else ""))
    if not connections:
        print("no connection readable on either project. The rule will report "
              "the invocation edge as undecidable rather than absent.")

    # Which agent uses which connection, asked of the agent rather than
    # assumed from the project it sits in. An agent's definition names the
    # connections its tools use, so the agent is serialised and each
    # connection is looked for in it.
    agent_connections = []
    for project, name in (("agentA", CALLER), ("agentB", CALLEE)):
        try:
            obj = client(t, project).agents.get(name)
            blob = json.dumps(obj, default=str).lower()
        except Exception as e:
            print(f"could not read {name}'s definition "
                  f"({type(e).__name__}: {e}); its tools are not recorded, so "
                  f"its reach will be computed from role assignments only")
            continue
        for c in connections:
            for key in ("id", "name"):
                v = c.get(key)
                if v and str(v).lower() in blob:
                    agent_connections.append({
                        "agent": name,
                        "connection": c.get("name"),
                        "connection_id": c.get("id"),
                        "matched_on": key,
                    })
                    break
    for link in agent_connections:
        print(f"{link['agent']} uses connection {link['connection']} "
              f"(matched on {link['matched_on']})")
    if not agent_connections:
        print("no agent definition refers to any listed connection. If an "
              "agent has a tool, this is wrong rather than empty: check the "
              "agent object's serialised form.")

    snap = {
        "_comment": ("Agent layer of the Foundry lab, read from the live "
                     "deployment because none of it is in Terraform state. "
                     "Written by lab_a2a.py snapshot. GUIDs are replaced with "
                     "stable placeholders, so scopes in the same subscription "
                     "still compare equal and principals stay distinct."),
        "as_of": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "agents": agents,
        "invocations": [{"caller": CALLER, "callee": CALLEE,
                         "mediated": False}],
        "shared_memory": [],
        "observed": {
            "as_of": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "role_assignments": assignments,
            "identity_principals": identity_principals,
            "role_definitions": definitions,
            "connections": connections,
            "agent_connections": agent_connections,
            "sources": {
                "principals": "agent.instance_identity, data plane",
                "role_assignments":
                    "az role assignment list --all --assignee-object-id, "
                    "cross-checked at each agent scope with "
                    "--include-inherited",
                "role_definitions": "az role definition list --name",
                "connections": "AIProjectClient.connections.list, per project",
                "agent_connections":
                    "the connection id or name appearing in the agent's own "
                    "serialised definition",
            },
        },
    }

    snap = json.loads(json.dumps(snap, default=str))
    try:
        sys.path.insert(0, HERE)
        from redact import Redactor
        r = Redactor()
        snap = r.obj(snap)
        r.save()
    except Exception as e:
        out_path = out_path + ".UNREDACTED"
        print(f"redaction unavailable ({type(e).__name__}: {e}). Writing to "
              f"{os.path.basename(out_path)} so it is not committed.")

    with open(out_path, "w") as f:
        json.dump(snap, f, indent=2)
    print(f"\nwrote {out_path}")
    # An absolute path, because the suggested command is run from the
    # repository root and this one is run from infra/foundry.
    print("Now evaluate the predicate on it, from the repository root:")
    print(f"  python3 -m agentpathtriage.foundry_cp --tfdir infra/foundry \\")
    print(f"      --agents {os.path.abspath(out_path)}")
    return 0


# --------------------------------------------------------- diag-card ----
# Operations the card fetch and the invocation appear under. Read from the logs
# rather than assumed: these are the names the account actually emitted.
CARD_OPERATIONS = ("Projects_Wildcard_Get", "Projects_Wildcard_Post",
                   "create_response")


def _run_files(limit):
    """The observations this lab wrote, newest first, with verdict and time."""
    import datetime as _dt
    # Sorted by the timestamp in the name and not by the name itself. The
    # names begin with a label, so sorting them alphabetically ordered the
    # observations by what they were called, and the limit then dropped the
    # most recent ones. That hid the reaches this command exists to compare
    # the blocks against.
    out = []
    for p in pathlib.Path(HERE, "runs").glob("a2a-*.json"):
        stem = p.stem
        if "-" not in stem:
            continue
        stamp = stem.rsplit("-", 1)[-1]
        try:
            local = _dt.datetime.strptime(stamp, "%Y%m%dT%H%M%S")
        except ValueError:
            continue
        try:
            verdict = json.loads(p.read_text()).get("verdict")
        except Exception:
            verdict = None
        # The run files are named with local time and the log is in UTC.
        local = local.replace(tzinfo=_dt.datetime.now().astimezone().tzinfo)
        out.append({"file": p.name, "verdict": verdict,
                    "utc": local.astimezone(_dt.timezone.utc)})
    out.sort(key=lambda r: r["utc"], reverse=True)
    return out[:limit]


def cmd_diag_card(a):
    """What the service logged, beside what each observation concluded."""
    import datetime as _dt
    t = tf()
    ws_name = a.workspace or _workspace_name(t)
    ok, ws = _az_json(["az", "monitor", "log-analytics", "workspace", "show",
                       "-g", t["resource_group"], "-n", ws_name, "-o", "json"])
    if not ok or not ws:
        print(f"no workspace {ws_name}. Run diag-on first.")
        return 2

    ops = ", ".join(f'"{o}"' for o in CARD_OPERATIONS)
    q = (f'AzureDiagnostics | where TimeGenerated > ago({a.hours}h) '
         f'| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES" '
         f'| where OperationName in ({ops}) '
         f'| project TimeGenerated, OperationName, ResultSignature, '
         f'CallerIPAddress, DurationMs, CorrelationId '
         f'| order by TimeGenerated asc')
    ok, rows = _az_json(["az", "monitor", "log-analytics", "query",
                         "-w", ws.get("customerId"), "--analytics-query", q,
                         "-o", "json"])
    if not ok:
        return 2
    if not rows:
        print(f"no matching records in the last {a.hours}h.")
        return 0

    def parse(ts):
        s = str(ts).replace("Z", "+00:00")
        try:
            return _dt.datetime.fromisoformat(s)
        except ValueError:
            return None

    for r in rows:
        r["_t"] = parse(r.get("TimeGenerated"))

    stamps = [r["_t"] for r in rows if r["_t"]]
    earliest = min(stamps) if stamps else None
    print(f"{len(rows)} card and invocation records in the last {a.hours}h")
    if earliest:
        print(f"earliest record: {earliest:%H:%M:%S} UTC. Anything observed "
              f"before that was not being logged.\n")
    # Which address is the client. The service fetches the agent card from its
    # own addresses and the client reads the same operation from its address,
    # so without this a client read counts as a card fetch. Inferred as the
    # most frequent caller and printed, because an inference the reader cannot
    # see is no better than a hardcoded value.
    seen_callers = {}
    for r in rows:
        c = r.get("CallerIPAddress")
        if c:
            seen_callers[c] = seen_callers.get(c, 0) + 1
    client = a.client or (max(seen_callers, key=seen_callers.get)
                          if seen_callers else None)
    print(f"callers in this period: "
          + ", ".join(f"{k} ({v})" for k, v in
                      sorted(seen_callers.items(), key=lambda kv: -kv[1])))
    print(f"taking {client} as the client, so a card fetch is a "
          f"Projects_Wildcard_Get from any other address\n")

    def is_card_fetch(r):
        return (r.get("OperationName") == "Projects_Wildcard_Get"
                and r.get("CallerIPAddress") != client)

    runs = _run_files(a.runs)
    if not runs:
        print("no run files to correlate against.")
        return 0

    # Each record goes to the nearest observation only. Two observations eight
    # seconds apart otherwise share every record, and one card fetch becomes
    # evidence for two different verdicts.
    assigned = {r["file"]: [] for r in runs}
    for rec in rows:
        if not rec["_t"]:
            continue
        best, best_d = None, None
        for run in runs:
            d = abs((rec["_t"] - run["utc"]).total_seconds())
            if d <= a.window and (best_d is None or d < best_d):
                best, best_d = run, d
        if best is not None:
            assigned[best["file"]].append(rec)

    print("each observation, with the records inside "
          f"{a.window}s of it:\n")
    for run in runs:
        print(f"{run['file']}")
        print(f"  verdict {run['verdict']!r}   at {run['utc']:%H:%M:%S} UTC")
        near = assigned.get(run["file"], [])
        if not near:
            # Two different reasons, and telling the reader one of them for
            # both cases would be wrong. An observation older than the first
            # record was taken before logging was on.
            if earliest and run["utc"] < earliest:
                print(f"  taken before logging was enabled at "
                      f"{earliest:%H:%M:%S} UTC, so there is nothing to find")
            else:
                print("  no records in the window. The log can lag by a few "
                      "minutes, so this is not evidence that nothing "
                      "happened.")
        for r in near:
            caller = r.get("CallerIPAddress") or "service internal"
            print(f"    {r['_t']:%H:%M:%S}  {r.get('OperationName'):26} "
                  f"{r.get('ResultSignature')}  from {caller}")
        codes = [str(r.get("ResultSignature")) for r in near
                 if is_card_fetch(r)]
        if near and not codes:
            print("    no card fetch by the service in this window. A "
                  "refusal at token acquisition never reaches the card, so "
                  "this is a result rather than a gap.")
        if codes:
            run["card_codes"] = codes
        print()

    # The comparison the whole command exists for. Only the service's own
    # fetches count, and each belongs to one observation.
    gets = [r for r in rows if is_card_fetch(r)]
    by_code = {}
    for r in gets:
        by_code.setdefault(str(r.get("ResultSignature")), 0)
        by_code[str(r.get("ResultSignature"))] += 1
    print("card fetches by status code: "
          + ", ".join(f"{k}: {v}" for k, v in sorted(by_code.items())))

    # The claim, stated rather than left to be assembled by eye.
    paired = [r for r in runs if r.get("card_codes")]
    if not paired:
        print("No observation has a card fetch beside it yet, so the question "
              "of what the 404 means is still open. Run a cell while logging "
              "is on.")
    else:
        print("\nobservations with a card fetch logged beside them:")
        for r in paired:
            print(f"  {r['verdict']:8} {','.join(r['card_codes']):10} "
                  f"{r['file']}")
        reached = {c for r in paired if r["verdict"] == "reached"
                   for c in r["card_codes"]}
        blocked = {c for r in paired if r["verdict"] == "blocked"
                   for c in r["card_codes"]}
        print(f"\n  codes beside a reach:  {', '.join(sorted(reached)) or 'none'}")
        print(f"  codes beside a block: {', '.join(sorted(blocked)) or 'none'}")
        if reached and blocked and not (reached & blocked):
            print("\nThe two sets do not overlap, so the card fetch status "
                  "tracks the verdict on these observations.")
            print("That is not yet the answer to what a 404 means. A 404 is "
                  "the authorisation outcome only if it appears when the "
                  "authorisation is absent. Check that the blocks below had "
                  "the role withdrawn: a block that happened while the role "
                  "was held, and that the same configuration later reached, "
                  "is a transient and belongs in the limits rather than in "
                  "the argument.")
        elif reached & blocked:
            print(f"\nThe sets overlap on {', '.join(sorted(reached & blocked))}. "
                  f"The card status alone does not separate the verdicts, and "
                  f"the 404 question stays open.")
        else:
            print("\nOnly one kind of verdict has a card fetch beside it, so "
                  "there is no contrast yet.")

    out = os.path.join(HERE, "runs",
                       f"diag-card-{time.strftime('%Y%m%dT%H%M%S')}.json")
    payload = json.loads(json.dumps(
        {"records": [{k: v for k, v in r.items() if k != "_t"} for r in rows],
         "observations": [{"file": r["file"], "verdict": r["verdict"],
                           "utc": r["utc"].isoformat()} for r in runs],
         "card_fetches_by_status": by_code,
         "note": "the card fetch is performed by the service, which is why "
                 "its records carry Azure-internal caller addresses while the "
                 "invocation's own response goes to the client address"},
        default=str))
    try:
        sys.path.insert(0, HERE)
        from redact import Redactor
        r = Redactor()
        payload = r.obj(payload)
        r.save()
    except Exception as e:
        out = out + ".UNREDACTED"
        print(f"\nredaction unavailable ({type(e).__name__}: {e})")
    with open(out, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\nwrote {out}")
    return 0


# ---------------------------------------------------------- conn-lag ----
def cmd_conn_lag(a):
    """How long after a connection authType change does the call behave like it?

    Takes the authType to change to and the verdict that authType should
    produce, then polls until the verdict matches. A mismatch is not a failure
    of the cell: it is the measurement, and the cell reports how long the
    mismatch lasted.

    The expected verdict is given rather than assumed, because the whole point
    is that the configuration and the behaviour can disagree, and a cell that
    decided for itself what the behaviour should be would hide exactly that.
    """
    t = tf()
    auth, want = a.auth, a.expect_verdict
    print(f"connection lag: set authType {auth}, poll until the verdict is "
          f"{want!r}")
    print(f"poll every {a.interval}s, give up after {a.max_seconds}s")
    print("the role assignments are not touched by this cell, so a change in "
          "verdict can only come from the connection\n")

    if _connect_as(auth):
        return 1
    changed_at = time.time()

    seen = []
    while time.time() - changed_at < a.max_seconds:
        waited = int(time.time() - changed_at)
        print(f"\n[poll] {waited}s after the connection change")
        rc = _observe_once(f"connlag-{auth}-{waited}s", auth)
        if rc:
            print("the observation refused to write, so the live connection "
                  "no longer reports the authType this cell set. Something "
                  "else changed it, and the measurement is void.")
            return rc
        latest = sorted(pathlib.Path(HERE, "runs").glob("a2a-connlag-*.json"))
        verdict = None
        if latest:
            try:
                verdict = json.loads(latest[-1].read_text()).get("verdict")
            except Exception:
                pass
        seen.append({"seconds": waited, "verdict": verdict})
        print(f"      verdict {verdict!r}, wanted {want!r}")
        if verdict == want:
            lag = waited
            break
        time.sleep(a.interval)
    else:
        lag = None

    out = os.path.join(HERE, "runs",
                       f"connlag-{time.strftime('%Y%m%dT%H%M%S')}.json")
    payload = {
        "measured": "time from a connection authType change to the call "
                    "behaving as that authType",
        "auth_type": auth,
        "expected_verdict": want,
        "seconds_to_first_match": lag,
        "poll_interval_seconds": a.interval,
        "cap_seconds": a.max_seconds,
        "observations": seen,
        "why": "the paired cell assumed this lag was zero. Its second run "
               "produced two observations that disagreed with the "
               "configuration they were taken under, which is what this "
               "measures.",
        "note": ("role assignments were not changed during this cell, so a "
                 "change in verdict is attributable to the connection alone"),
    }
    with open(out, "w") as f:
        json.dump(payload, f, indent=2)
    if lag is None:
        print(f"\nthe verdict never became {want!r} within {a.max_seconds}s. "
              f"Either the lag is longer than that, or this authType does not "
              f"produce that verdict on this deployment at all. Both are "
              f"results and the run file holds every poll.")
    else:
        print(f"\nthe call behaved as {auth} {lag}s after the change, "
              f"resolution {a.interval}s.")
        print("Any cell that observes sooner than that after a connection "
              "change is measuring an indeterminate configuration.")
    print(f"wrote {out}")
    return 0


# ----------------------------------------------------------- paired ----
def _observe_once(label, expect_auth):
    """One observation with the label and the authType guard, as a cell step."""
    import argparse as _ap
    ns = _ap.Namespace(label=label, auth=None, expect_auth=expect_auth,
                       send_card_credentials=False)
    return cmd_observe(ns)


def _connect_as(auth):
    import argparse as _ap
    return cmd_connect(_ap.Namespace(label="", auth=auth, expect_auth=None,
                                     send_card_credentials=False))


def cmd_paired_authtype(a):
    """Both authTypes observed inside one propagation window.

    Grants for both principals are created first, a single wait is served, and
    then the two observations are taken back to back with only the connection's
    authType changed between them. Each observation confirms the live authType
    before it runs, and refuses to write a run file on a mismatch, so a
    mislabelled pair cannot reach the artifact.
    """
    t = tf()
    wait = a.wait if a.wait is not None else PROPAGATION_SECONDS
    first = a.first
    second = ("ProjectManagedIdentity" if first == "AgenticIdentityToken"
              else "AgenticIdentityToken")

    print("paired authType observation inside one propagation window")
    print(f"  grants: Consumer to the caller's instance identity at the "
          f"callee's agent scope, and to project A's system-assigned identity "
          f"at the callee's project scope")
    print(f"  order : {first} then {second}")
    print(f"  wait  : {wait}s, served once for both grants\n")

    print("[1/5] grant, caller instance identity")
    if _role(t, "create"):
        return 1
    print("\n[2/5] grant, project identity at the project scope")
    if _pmi_role(t, "create", "project"):
        return 1

    if a.no_wait:
        print("\n[3/5] wait skipped by --no-wait. A blocked verdict after "
              "this is not interpretable, and neither is the pair.")
    else:
        print(f"\n[3/5] wait {wait}s, once, for both grants")
        left = wait
        while left > 0:
            chunk = min(30, left)
            time.sleep(chunk)
            left -= chunk
            print(f"      {left}s left", flush=True)

    results = {}
    for i, auth in ((4, first), (5, second)):
        print(f"\n[{i}/5] connect {auth} and observe immediately")
        if _connect_as(auth):
            print("the connect failed, so the pair is incomplete and the "
                  "comparison it exists for cannot be made.")
            return 1
        rc = _observe_once(f"paired-{auth}-{first}-first", auth)
        if rc:
            print(f"the observation refused to write for {auth}. The pair is "
                  f"incomplete.")
            return rc
        results[auth] = "written"

    print("\npaired cell complete. Read the two run files written just now.")
    print("If one authType reached and the other was blocked, both were "
          "served by the same wait and the same grants, so propagation is "
          "not what separated them. Run again with --first "
          f"{second} to check for an ordering effect.")
    return 0


def cmd_calibrate_propagation(a):
    """Measure how long a data-plane grant takes to become visible.

    Uses the agent-identity path, which is known to reach, so the poll
    terminates. The grant is revoked first and the revocation is given the same
    window, otherwise the next grant is already live and the measurement is of
    nothing.
    """
    t = tf()
    interval, cap = a.interval, a.max_seconds
    print(f"calibrating propagation: poll every {interval}s, up to {cap}s")
    print("the resolution of the result is the poll interval\n")

    print("[setup] connect AgenticIdentityToken")
    if _connect_as("AgenticIdentityToken"):
        return 1
    print("\n[setup] revoke, so the grant being measured is the new one")
    if _role(t, "delete"):
        return 1
    print(f"\n[setup] wait {cap}s for the revocation, so a reach below is "
          f"the new grant and not the old one")
    left = cap
    while left > 0:
        chunk = min(30, left)
        time.sleep(chunk)
        left -= chunk
        print(f"      {left}s left", flush=True)

    print("\n[grant] now")
    t0 = time.time()
    if _role(t, "create"):
        return 1
    granted_at = time.time()

    reached_at = None
    while time.time() - granted_at < cap:
        waited = int(time.time() - granted_at)
        print(f"\n[poll] {waited}s after the grant")
        rc = _observe_once(f"calibrate-{waited}s", "AgenticIdentityToken")
        if rc:
            print("the observation refused to write, so this poll says "
                  "nothing about propagation.")
            return rc
        # The verdict is in the run file the observation wrote. Rather than
        # parse it back, read the flag the observation printed: a reach is the
        # only outcome that ends the poll, and a block continues it.
        latest = sorted(pathlib.Path(HERE, "runs").glob("a2a-calibrate-*.json"))
        if latest:
            try:
                rec = json.loads(latest[-1].read_text())
                if rec.get("verdict") == "reached":
                    reached_at = time.time()
                    print(f"\nreached {int(reached_at - granted_at)}s after "
                          f"the grant")
                    break
            except Exception:
                pass
        time.sleep(interval)

    if reached_at is None:
        print(f"\nnot reached within {cap}s. That is a result too: the "
              f"figure this lab has been using is too small, and every "
              f"blocked verdict taken at {PROPAGATION_SECONDS}s needs "
              f"re-reading.")
        return 1

    elapsed = int(reached_at - granted_at)
    out = os.path.join(HERE, "runs",
                       f"propagation-{time.strftime('%Y%m%dT%H%M%S')}.json")
    with open(out, "w") as f:
        json.dump({"measured": "time from grant to first reach",
                   "seconds": elapsed, "poll_interval_seconds": interval,
                   "cap_seconds": cap, "path": "AgenticIdentityToken",
                   "assumed_before": PROPAGATION_SECONDS,
                   "resolution": "the poll interval, so the true value is "
                                 "within one interval below this",
                   "runs": 1,
                   "note": "one measurement. Repeat to get a range, and quote "
                           "the largest."}, f, indent=2)
    print(f"wrote {out}")
    print(f"\nthe figure in use is {PROPAGATION_SECONDS}s and this run "
          f"measured {elapsed}s. Repeat this a second and third time before "
          f"quoting a number, because one measurement is not a range.")
    return 0


# ------------------------------------------------------------- cells ----
# How long a data-plane role grant takes to be visible on this subscription.
# Measured 2026-10-26, and confirmed by a run on 2026-10-31 that observed 20
# seconds after a grant and came back blocked for no interpretable reason.
PROPAGATION_SECONDS = 300

# Each cell is the whole unit: what the connection must be, what roles must be
# in place, and what to observe. Adding a cell here is how a new one gets run,
# so the sequence is written down once rather than retyped each time.
CELLS = {
    "treatment": {
        "why": "caller holds Consumer on the callee, connection binds to the "
               "agent's own identity. The escalation.",
        "steps": [("connect", {"auth": "AgenticIdentityToken"}),
                  ("grant", {}),
                  ("wait", {}),
                  ("observe", {"expect_auth": "AgenticIdentityToken"})],
    },
    "control": {
        "why": "same connection, Consumer revoked. Should be blocked.",
        "steps": [("connect", {"auth": "AgenticIdentityToken"}),
                  ("revoke", {}),
                  ("wait", {}),
                  ("observe", {"expect_auth": "AgenticIdentityToken"})],
    },
    "negative-control": {
        "why": "Consumer still held by the caller's instance identity, but the "
               "connection authenticates as the project instead. Asks whether "
               "the role is bound to the identity or to the call.",
        "steps": [("connect", {"auth": "ProjectManagedIdentity"}),
                  ("grant", {}),
                  ("wait", {}),
                  ("observe", {"expect_auth": "ProjectManagedIdentity"})],
    },
    "pmi-poscontrol": {
        "why": "the same ProjectManagedIdentity connection, with Consumer on "
               "the principal that auth type actually resolves to. If this "
               "reaches, the negative control's block was the grant sitting on "
               "a different principal, not ProjectManagedIdentity being broken "
               "for A2A.",
        "steps": [("connect", {"auth": "ProjectManagedIdentity"}),
                  ("pmi-grant", {}),
                  ("wait", {}),
                  ("observe", {"expect_auth": "ProjectManagedIdentity"})],
    },
    "pmi-project-scope": {
        "why": "the same ProjectManagedIdentity connection, with Consumer on "
               "the project identity at the CALLEE'S PROJECT scope rather "
               "than at the agent scope. The vendor page allows both scopes, "
               "and the two blocked PMI cells both used the narrower one. "
               "This is the last documented reading left to try before the "
               "alternative explanation can be called as far as this lab can "
               "take it.",
        "steps": [("connect", {"auth": "ProjectManagedIdentity"}),
                  ("pmi-revoke", {}),
                  ("pmi-grant-project", {}),
                  ("wait", {}),
                  ("observe", {"expect_auth": "ProjectManagedIdentity"})],
    },
    "falsification": {
        "why": "caller authorised for the index directly. eff is unchanged and "
               "auth grows, so the predicate should stop firing while the "
               "trace stays identical.",
        "steps": [("connect", {"auth": "AgenticIdentityToken"}),
                  ("grant", {}),
                  ("falsify-grant", {}),
                  ("wait", {}),
                  ("observe", {"expect_auth": "AgenticIdentityToken"})],
    },
    "cardcred-norole": {
        "why": "the blocked state, but with credentials sent on the agent card "
               "request. The vendor page says that fetch is anonymous by "
               "default and that a card path needing auth returns 401, while "
               "the blocked cells return 404. This separates the two.",
        "steps": [("connect", {"auth": "AgenticIdentityToken"}),
                  ("revoke", {}),
                  ("wait", {}),
                  ("observe", {"expect_auth": "AgenticIdentityToken",
                               "send_card_credentials": True})],
    },
}


def cmd_cell(a):
    import argparse as _ap
    spec = CELLS.get(a.name)
    if spec is None:
        print(f"no such cell: {a.name}")
        print("cells:")
        for k, v in CELLS.items():
            print(f"  {k:18} {v['why']}")
        return 2
    runners = {"connect": cmd_connect, "grant": cmd_grant, "revoke": cmd_revoke,
               "pmi-grant": cmd_pmi_grant, "pmi-revoke": cmd_pmi_revoke,
               "pmi-grant-project": cmd_pmi_grant_project,
               "pmi-revoke-project": cmd_pmi_revoke_project,
               "falsify-grant": cmd_falsify_grant,
               "falsify-revoke": cmd_falsify_revoke, "observe": cmd_observe}
    wait = a.wait if a.wait is not None else PROPAGATION_SECONDS
    print(f"cell: {a.name}")
    print(f"why : {spec['why']}")
    print(f"wait: {wait}s before observing\n")
    for i, (step, kw) in enumerate(spec["steps"], 1):
        head = f"[{i}/{len(spec['steps'])}] {step}"
        if step == "wait":
            if a.no_wait:
                print(f"{head}: skipped by --no-wait. A blocked verdict after "
                      f"this is not interpretable.\n")
                continue
            print(f"{head} {wait}s for the grant to propagate")
            # Print progress so a long wait does not look like a hang.
            left = wait
            while left > 0:
                chunk = min(30, left)
                time.sleep(chunk)
                left -= chunk
                print(f"      {left}s left", flush=True)
            print()
            continue
        print(f"{head}")
        ns = _ap.Namespace(label=a.label or a.name, auth=None,
                           expect_auth=None, send_card_credentials=False)
        for k, v in kw.items():
            setattr(ns, k, v)
        rc = runners[step](ns)
        if rc:
            print(f"\nstopped at step {i} ({step}), exit {rc}. "
                  f"Nothing after it ran, so no observation was written for a "
                  f"state the cell never reached.")
            return rc
        print()
    print(f"cell {a.name} complete")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("arm-callee", cmd_arm_callee),
                     ("check-callee", cmd_check_callee),
                     ("enable-callee", cmd_enable_callee),
                     ("grant", cmd_grant), ("revoke", cmd_revoke),
                     ("falsify-grant", cmd_falsify_grant),
                     ("falsify-revoke", cmd_falsify_revoke),
                     ("pmi-grant", cmd_pmi_grant),
                     ("pmi-revoke", cmd_pmi_revoke)):
        p = sub.add_parser(name)
        p.set_defaults(fn=fn, label="")
    p = sub.add_parser("connect")
    p.add_argument("--auth", default="AgenticIdentityToken",
                   help="the docs give AgenticIdentityToken for RemoteA2A in "
                        "one place and AgenticIdentity in another")
    p.set_defaults(fn=cmd_connect, label="")
    p = sub.add_parser("observe")
    p.add_argument("--label", default="")
    p.add_argument("--expect-auth", default=None,
                   help="the connection authType this cell requires. observe "
                        "reads the live connection and refuses to write a run "
                        "file if it does not match, because a run labelled "
                        "for a state it was not in is worse than no run.")
    p.add_argument("--send-card-credentials", action="store_true",
                   help="set send_credentials_for_agent_card on the "
                        "A2A tool. Default false, which is what the "
                        "vendor documents, so the agent card fetch "
                        "goes out anonymously.")
    p.set_defaults(fn=cmd_observe)
    for name, fn in (("pmi-grant-project", cmd_pmi_grant_project),
                     ("pmi-revoke-project", cmd_pmi_revoke_project)):
        p = sub.add_parser(name)
        p.set_defaults(fn=fn, label="")

    p = sub.add_parser("diag-card",
                       help="each observation's verdict beside the status "
                            "code the service logged for it")
    p.add_argument("--workspace", default=None)
    p.add_argument("--hours", type=int, default=3)
    p.add_argument("--runs", type=int, default=8,
                   help="how many of the most recent observations to line up")
    p.add_argument("--window", type=int, default=25,
                   help="seconds either side of an observation to look in")
    p.add_argument("--client", default=None,
                   help="the client's caller address, if the inference from "
                        "call frequency picks the wrong one")
    p.set_defaults(fn=cmd_diag_card, label="")

    p = sub.add_parser("conn-lag",
                       help="measure the lag between a connection authType "
                            "change and the call behaving as it")
    p.add_argument("--auth", default="AgenticIdentityToken",
                   choices=["AgenticIdentityToken", "ProjectManagedIdentity",
                            "AccountManagedIdentity", "AgentUserImpersonation",
                            "AgentOnBehalfOfUser"])
    p.add_argument("--expect-verdict", default="reached",
                   choices=["reached", "blocked"], dest="expect_verdict",
                   help="the verdict this authType should produce once the "
                        "change has taken effect")
    p.add_argument("--interval", type=int, default=30)
    p.add_argument("--max-seconds", type=int, default=600,
                   dest="max_seconds")
    p.set_defaults(fn=cmd_conn_lag, label="")

    p = sub.add_parser("paired",
                       help="both authTypes inside one propagation window")
    p.add_argument("--first", default="AgenticIdentityToken",
                   choices=["AgenticIdentityToken", "ProjectManagedIdentity"],
                   help="which authType to observe first, so an ordering "
                        "effect can be checked")
    p.add_argument("--wait", type=int, default=None)
    p.add_argument("--no-wait", action="store_true")
    p.set_defaults(fn=cmd_paired_authtype, label="")

    p = sub.add_parser("calibrate",
                       help="measure the propagation time instead of assuming")
    p.add_argument("--interval", type=int, default=20)
    p.add_argument("--max-seconds", type=int, default=PROPAGATION_SECONDS,
                   dest="max_seconds")
    p.set_defaults(fn=cmd_calibrate_propagation, label="")

    p = sub.add_parser("diag-on",
                       help="send the account's resource logs to Log Analytics")
    p.add_argument("--workspace", default=None,
                   help="workspace name; default is derived from the account")
    p.set_defaults(fn=cmd_diag_on, label="")

    p = sub.add_parser("diag-query", help="print what the account logged")
    p.add_argument("--workspace", default=None)
    p.add_argument("--hours", type=int, default=2)
    p.add_argument("--take", type=int, default=5)
    p.set_defaults(fn=cmd_diag_query, label="")

    p = sub.add_parser("snapshot",
                       help="write the agent layer for the analyser")
    p.add_argument("--out", default=None,
                   help="where to write it; default infra/foundry/"
                        "agents_observed.json")
    p.set_defaults(fn=cmd_snapshot, label="")

    p = sub.add_parser("cell", help="run a whole cell, waiting in between")
    p.add_argument("name", nargs="?", default="",
                   help="cell name; omit to list them")
    p.add_argument("--wait", type=int, default=None,
                   help=f"seconds to wait for the grant to propagate "
                        f"(default {PROPAGATION_SECONDS})")
    p.add_argument("--no-wait", action="store_true",
                   help="skip the wait. Only for a cell whose roles are "
                        "already in place and propagated.")
    p.add_argument("--label", default="")
    p.set_defaults(fn=cmd_cell)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())

"""
AgentPathTriage regression tests.

One test per defect found in the 2026-10-14 review, so each stays fixed. Every
fixture is real Terraform source run through the real pipeline
(tf_to_state -> extract_graph -> reach), not a hand-built graph, because the
defects lived in parsing and graph construction rather than in the traversal.

Run:  python3 -m pytest tests -q
"""
import json
import os
import subprocess
import sys
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agentpathtriage"))
sys.path.insert(0, os.path.join(ROOT, "evaluation", "benchmark"))

import iam_eval as E            # noqa: E402
import extract_graph as X       # noqa: E402
import reach as R               # noqa: E402
import tf_to_state as T         # noqa: E402

ACCT = T.ACCOUNT


def write_tf(tmp_path, **files):
    for name, body in files.items():
        (tmp_path / f"{name}.tf").write_text(textwrap.dedent(body))
    return str(tmp_path)


def analyse(tmp_path, **files):
    state, _ = T.to_state(write_tf(tmp_path, **files))
    _, _, _, results = R.run(state)
    return {r["principal"]: r for r in results}


def graph_of(tmp_path, **files):
    state, _ = T.to_state(write_tf(tmp_path, **files))
    return X.build(state)


# --------------------------------------------------------------- policy core ---

def test_explicit_deny_beats_allow():
    """model/act-scope.md says an explicit Deny always wins. It must be true."""
    st = E.parse_statements([
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
    ])
    assert E.evaluate(st, "s3:DeleteObject", "arn:aws:s3:::b/o").allowed is False
    assert E.evaluate(st, "s3:GetObject", "arn:aws:s3:::b/o").allowed is True


def test_conditional_deny_does_not_erase_the_allow():
    st = E.parse_statements([
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Effect": "Deny", "Action": "*", "Resource": "*",
         "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}},
    ])
    d = E.evaluate(st, "iam:PassRole", f"arn:aws:iam::{ACCT}:role/r")
    assert d.allowed is True and d.conditional is True


def test_not_action_is_honoured():
    st = E.parse_statements([{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}])
    assert E.evaluate(st, "iam:PassRole", "*").allowed is False
    assert E.evaluate(st, "s3:GetObject", "*").allowed is True


def test_action_and_resource_globs():
    assert E.action_matches("bedrock-agentcore:*CodeInterpreter*",
                            "bedrock-agentcore:InvokeCodeInterpreter")
    assert not E.action_matches("bedrock-agentcore:*CodeInterpreter*",
                                "bedrock-agentcore:GetMemory")
    assert E.resource_matches(f"arn:aws:iam::{ACCT}:role/agentcore_*",
                              f"arn:aws:iam::{ACCT}:role/agentcore_runtime")
    assert not E.resource_matches(f"arn:aws:iam::{ACCT}:role/agentcore_*",
                                  f"arn:aws:iam::{ACCT}:role/other")


def test_unconditioned_service_trust_is_distinguished_from_a_scoped_one():
    loose = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "x.amazonaws.com"}}]}
    tight = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "x.amazonaws.com"},
                            "Condition": {"StringEquals": {"aws:SourceAccount": ACCT}}}]}
    assert E.trust_entries_from_policy(loose)[0]["scoped"] is False
    assert E.trust_entries_from_policy(tight)[0]["scoped"] is True


# ------------------------------------------------------------------ predicate ---

OVERPRIV_NO_DELEGATE = """
    resource "aws_iam_role" "lonely" {
      name = "lonely"
      assume_role_policy = jsonencode({Statement = [{Effect = "Allow",
        Principal = {Service = "bedrock-agentcore.amazonaws.com"}}]})
    }
    resource "aws_iam_role_policy" "p" {
      name = "p"
      role = aws_iam_role.lonely.name
      policy = jsonencode({Statement = [{Effect = "Allow",
        Action = "bedrock-agentcore:*", Resource = "*"}]})
    }
"""


def test_overprivileged_but_non_delegating_role_is_not_an_escalation(tmp_path):
    """The thesis is eff \\ auth, not "holds a wildcard". A role that is broadly
    permissioned but hands off to nobody is classic over-permissioning, which this
    project explicitly claims not to be about, so the new predicate must say False
    while the old one says True."""
    r = analyse(tmp_path, main=OVERPRIV_NO_DELEGATE)["lonely"]
    assert r["Esc_classic"] is True
    assert r["Esc"] is False


SHARED_TRUST = """
    resource "aws_iam_user" "sandy" { name = "sandy" }
    resource "aws_iam_user_policy" "up" {
      name = "up"
      user = aws_iam_user.sandy.name
      policy = jsonencode({Statement = [
        {Effect = "Allow", Action = "iam:PassRole",
         Resource = "arn:aws:iam::ACCT:role/ac_*"},
        {Effect = "Allow", Action = "bedrock-agentcore:*CodeInterpreter*", Resource = "*"}]})
    }
    resource "aws_iam_role" "ac_rt" {
      name = "ac_rt"
      assume_role_policy = jsonencode({Statement = [{Effect = "Allow",
        Principal = {Service = "bedrock-agentcore.amazonaws.com"}}]})
    }
    resource "aws_iam_role_policy" "p2" {
      name = "p2"
      role = aws_iam_role.ac_rt.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "bedrock:Retrieve",
        Resource = aws_bedrockagent_knowledge_base.kb.arn}]})
    }
    resource "aws_bedrockagent_knowledge_base" "kb" { name = "kb1" }
""".replace("ACCT", ACCT)


def test_prefix_passrole_and_shared_service_trust_find_the_escalation(tmp_path):
    """The CloudGoat agentcore_identity_confusion shape: a prefix-scoped PassRole and
    a service trust with nothing narrowing it. Both were invisible before."""
    res = analyse(tmp_path, main=SHARED_TRUST)
    r = res["sandy"]
    assert r["Esc"] is True
    assert any("knowledge-base/kb1" in w["reaches"] for w in r["witnesses"])


def test_scoped_service_trust_blocks_the_deputy(tmp_path):
    tight = SHARED_TRUST.replace(
        'Principal = {Service = "bedrock-agentcore.amazonaws.com"}}]})',
        'Principal = {Service = "bedrock-agentcore.amazonaws.com"},'
        ' Condition = {StringEquals = {"aws:SourceAccount" = "' + ACCT + '"}}}]})')
    assert analyse(tmp_path, main=tight)["sandy"]["Esc"] is False


def test_passrole_without_the_ability_to_run_the_service_is_not_an_escalation(tmp_path):
    """Holding iam:PassRole is not enough. There has to be a deputy to confuse."""
    quiet = SHARED_TRUST.replace(
        '{Effect = "Allow", Action = "bedrock-agentcore:*CodeInterpreter*", Resource = "*"}',
        '{Effect = "Allow", Action = "s3:GetObject", Resource = "*"}')
    assert analyse(tmp_path, main=quiet)["sandy"]["Esc"] is False


TAKEOVER = """
    resource "aws_iam_user" "grace" { name = "grace" }
    resource "aws_iam_user_policy" "up" {
      name = "up"
      user = aws_iam_user.grace.name
      policy = jsonencode({Statement = [{Effect = "Allow",
        Action = "lambda:UpdateFunctionCode", Resource = "*"}]})
    }
    resource "aws_iam_role" "lambda_role" {
      name = "lambda_role"
      assume_role_policy = jsonencode({Statement = [{Effect = "Allow",
        Principal = {Service = "lambda.amazonaws.com"}}]})
    }
    resource "aws_iam_role_policy" "lp" {
      name = "lp"
      role = aws_iam_role.lambda_role.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "bedrock:Retrieve",
        Resource = aws_bedrockagent_knowledge_base.kb.arn}]})
    }
    resource "aws_bedrockagent_knowledge_base" "kb" { name = "kb1" }
    resource "aws_lambda_function" "f" {
      function_name = "f1"
      role = aws_iam_role.lambda_role.arn
    }
"""


def test_taking_over_a_resource_that_runs_as_a_role_is_an_escalation(tmp_path):
    """Nobody hands over the role. Changing the code of something already running as
    it gives the same reach, so eff \\ auth is non-empty."""
    r = analyse(tmp_path, main=TAKEOVER)["grace"]
    assert r["Esc"] is True
    assert any("knowledge-base/kb1" in w["reaches"] for w in r["witnesses"])


def test_unreadable_aws_managed_policy_is_reported_not_silently_dropped(tmp_path):
    """An AWS-managed policy's document is not in the configuration. An escalation
    into a role carrying one is real but unmeasurable, and must be said out loud."""
    src = TAKEOVER.replace(
        'resource "aws_iam_role_policy" "lp" {',
        'resource "aws_iam_role_policy_attachment" "ro" {\n'
        '  role = aws_iam_role.lambda_role.name\n'
        '  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"\n'
        '}\nresource "aws_iam_role_policy" "unused" {')
    src = src.replace("Resource = aws_bedrockagent_knowledge_base.kb.arn",
                      'Resource = "arn:aws:logs:us-east-1:' + ACCT + ':log-group:x:*"')
    r = analyse(tmp_path, main=src)["grace"]
    assert r["Esc"] is False
    assert r["Esc_unquantified"] is True
    assert any("ReadOnlyAccess" in p
               for pols in r["unreadable_managed_gained"].values() for p in pols)


def test_an_agent_name_that_is_an_expression_does_not_stop_the_run(tmp_path):
    """A CloudFormation name arrives as an intrinsic, so it reaches the index as
    a dict. Before 2026-11-07 that was used as a dict key and raised
    TypeError: unhashable type: 'dict', which took one template out of the
    chain denominator as a failure rather than as a result. The agent is keyed
    by its logical name instead, and the expression that did not resolve is
    recorded so it does not look like one that did."""
    import json as _json
    import cfn_to_state as C

    doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Stage": {"Type": "String", "Default": "dev"}},
        "Resources": {
            "RunnerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                                   "Principal": {"Service":
                                                 "bedrock-agentcore.amazonaws.com"}}]}},
            },
            "RunnerRuntime": {
                "Type": "AWS::BedrockAgentCore::Runtime",
                "Properties": {
                    # An intrinsic the translator does not read, so it
                    # reaches the index as a dict. The corpus case was a Join
                    # of these, and the Join is collapsed now, but the inner
                    # form is still what arrives when a name is built this
                    # way, and a dict cannot be a key.
                    "AgentRuntimeName": {"Fn::Select": [
                        2, {"Fn::Split": ["/", {"Ref": "AWS::StackId"}]}]},
                    "RoleArn": {"Fn::GetAtt": ["RunnerRole", "Arn"]},
                },
            },
        },
    }
    tpl = tmp_path / "t.json"
    tpl.write_text(_json.dumps(doc))
    out = tmp_path / "state.json"
    rc = subprocess.run([sys.executable,
                         os.path.join(ROOT, "evaluation", "benchmark",
                                      "cfn_to_state.py"),
                         "--template", str(tpl), "--json", str(out), "--quiet"],
                        capture_output=True, text=True)
    assert rc.returncode == 0, rc.stderr
    state = json.loads(out.read_text())

    _G, ix = X.build(state)

    # the run completes and the agent is there, keyed by its logical name
    assert "RunnerRuntime" in ix.agents
    # and the name that did not resolve is on the record
    assert any(u["resource"] == "RunnerRuntime" and u["field"] == "name"
               for u in ix.unresolved_names)


def test_delegation_cycle_terminates(tmp_path):
    src = """
    resource "aws_iam_role" "ra" {
      name = "ra"
      assume_role_policy = jsonencode({Statement = [{Effect = "Allow",
        Principal = {AWS = "arn:aws:iam::ACCT:role/rb"}}]})
    }
    resource "aws_iam_role_policy" "pa" {
      name = "pa"
      role = aws_iam_role.ra.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "sts:AssumeRole",
        Resource = "*"}]})
    }
    resource "aws_iam_role" "rb" {
      name = "rb"
      assume_role_policy = jsonencode({Statement = [{Effect = "Allow",
        Principal = {AWS = "arn:aws:iam::ACCT:role/ra"}}]})
    }
    resource "aws_iam_role_policy" "pb" {
      name = "pb"
      role = aws_iam_role.rb.name
      policy = jsonencode({Statement = [
        {Effect = "Allow", Action = "sts:AssumeRole", Resource = "*"},
        {Effect = "Allow", Action = "*", Resource = "*"}]})
    }
    """.replace("ACCT", ACCT)
    assert analyse(tmp_path, main=src)["ra"]["Esc"] is True


# --------------------------------------------------------------- determinism ---

MULTI_RUNTIME_A = """
    resource "aws_bedrockagentcore_agent_runtime" "sparky" {
      name = "sparky"
      role_arn = aws_iam_role.sparky_role.arn
      environment = { MEMORY_ID = aws_bedrockagentcore_memory.m.id }
    }
    resource "aws_bedrockagentcore_memory" "m" { name = "m1" }
    resource "aws_iam_role" "sparky_role" { name = "sparky_role" }
    resource "aws_iam_role_policy" "sp" {
      name = "sp"
      role = aws_iam_role.sparky_role.name
      policy = jsonencode({Statement = [{Effect = "Allow",
        Action = "bedrock-agentcore:GetMemoryRecord", Resource = "*"}]})
    }
"""
MULTI_RUNTIME_B = """
    resource "aws_bedrockagentcore_agent_runtime" "core" {
      name = "core"
      role_arn = aws_iam_role.core_role.arn
      environment = { MEMORY_ID = aws_bedrockagentcore_memory.m.id }
    }
    resource "aws_iam_role" "core_role" { name = "core_role" }
    resource "aws_iam_role_policy" "cp" {
      name = "cp"
      role = aws_iam_role.core_role.name
      policy = jsonencode({Statement = [{Effect = "Allow",
        Action = "bedrock-agentcore:GetMemoryRecord",
        Resource = "arn:aws:bedrock-agentcore:us-east-1:ACCT:memory/m1"}]})
    }
""".replace("ACCT", ACCT)


def test_every_runtime_in_a_template_is_scored(tmp_path):
    """gap.py v0 kept only the last role_arn it read, so a template with two agent
    runtimes scored one of them and silently dropped the other."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "gapmod", os.path.join(ROOT, "agentpathtriage", "gap.py"))
    gap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gap)
    write_tf(tmp_path, a=MULTI_RUNTIME_A, b=MULTI_RUNTIME_B)
    rows = gap.scan_template(str(tmp_path))
    assert len(rows) == 2
    assert {r["runtime"] for r in rows} == {"sparky", "core"}
    assert {r["role_local"] for r in rows} == {"sparky_role", "core_role"}


def test_scan_is_independent_of_file_order(tmp_path):
    """The same template must score the same on any filesystem. v0 assembled the
    text with an unsorted glob, so the verdict followed directory order."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "gapmod2", os.path.join(ROOT, "agentpathtriage", "gap.py"))
    gap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gap)
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    write_tf(one, aaa=MULTI_RUNTIME_A, zzz=MULTI_RUNTIME_B)
    write_tf(two, zzz=MULTI_RUNTIME_A, aaa=MULTI_RUNTIME_B)
    def key(rows):
        return sorted((r["runtime"], r["role_local"], r["resource_scope_gap"]) for r in rows)
    assert key(gap.scan_template(str(one))) == key(gap.scan_template(str(two)))


def test_reach_is_deterministic(tmp_path):
    a = analyse(tmp_path, main=SHARED_TRUST)["sandy"]
    b = analyse(tmp_path, main=SHARED_TRUST)["sandy"]
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ------------------------------------------------------------------- parsing ---

def test_jsonencode_policies_are_parsed_not_left_opaque(tmp_path):
    state, _ = T.to_state(write_tf(tmp_path, main=OVERPRIV_NO_DELEGATE))
    pols = [r["values"]["policy"] for r in state["values"]["root_module"]["resources"]
            if r["type"] == "aws_iam_role_policy"]
    assert pols and json.loads(pols[0])["Statement"][0]["Action"] == "bedrock-agentcore:*"


def test_heredoc_policies_are_parsed(tmp_path):
    src = '''
    resource "aws_iam_role" "r" {
      name = "r"
      assume_role_policy = <<EOF
    {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
     "Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
    EOF
    }
    '''
    state, _ = T.to_state(write_tf(tmp_path, main=src))
    v = state["values"]["root_module"]["resources"][0]["values"]
    entries = E.trust_entries_from_policy(v["assume_role_policy"])
    assert entries and entries[0]["value"] == "lambda.amazonaws.com"


def test_account_and_region_data_sources_normalise(tmp_path):
    src = '''
    resource "aws_iam_user" "u" { name = "u" }
    resource "aws_iam_user_policy" "p" {
      name = "p"
      user = aws_iam_user.u.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "iam:PassRole",
        Resource = "arn:aws:iam::${data.aws_caller_identity.me.account_id}:role/x"}]})
    }
    resource "aws_iam_role" "x" { name = "x" }
    '''
    state, _ = T.to_state(write_tf(tmp_path, main=src))
    G, ix = X.build(state)
    assert G.has_edge("u", "x")

def test_file_reads_are_sorted(tmp_path):
    """Defensive, and labelled as such. Scoring every runtime is what actually makes
    the result order-independent (see the two tests above), so this one guards the
    sorting itself: a mutation that removes it changes no verdict today, but it would
    matter again the moment any per-template aggregation is reintroduced."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "gapmod3", os.path.join(ROOT, "agentpathtriage", "gap.py"))
    gap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gap)
    write_tf(tmp_path, zzz=MULTI_RUNTIME_A, aaa=MULTI_RUNTIME_B, mmm=MULTI_RUNTIME_A)
    files = gap.tf_files(str(tmp_path))
    assert files == sorted(files)

# ------------------------------------------- conditions, groups, self-escalation ---

def test_condition_that_can_never_hold_is_not_a_grant():
    """IAM-Vulnerable pins both directions with one pair. fn3 grants on
    DateGreaterThan a past date, which always holds, and fp5 grants on DateLessThan
    the same date, which never can. Reading conditions without deciding this turns
    the author's designed false positive into a real one."""
    exploitable = E.parse_statements([{
        "Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*",
        "Condition": {"DateGreaterThan": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"}}}])
    dead = E.parse_statements([{
        "Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*",
        "Condition": {"DateLessThan": {"aws:TokenIssueTime": "2020-01-01T00:00:01Z"}}}])
    assert E.evaluate(exploitable, "iam:CreatePolicyVersion", "*").allowed is True
    assert E.evaluate(dead, "iam:CreatePolicyVersion", "*").allowed is False


def test_unknown_condition_is_treated_as_satisfiable_and_marked():
    st = E.parse_statements([{
        "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
        "Condition": {"StringEquals": {"aws:ResourceTag/team": "x"}}}])
    d = E.evaluate(st, "s3:GetObject", "arn:aws:s3:::b/o")
    assert d.allowed is True and d.conditional is True


def test_policy_document_data_source_is_rendered(tmp_path):
    """A third of the agent runtime templates in the corpus write policies as
    aws_iam_policy_document, and a pass that cannot read them is blind to those."""
    src = """
    data "aws_iam_policy_document" "d" {
      statement {
        actions   = ["iam:CreatePolicyVersion"]
        effect    = "Allow"
        resources = ["*"]
        condition {
          test     = "DateGreaterThan"
          variable = "aws:TokenIssueTime"
          values   = ["2020-01-01T00:00:01Z"]
        }
      }
    }
    resource "aws_iam_policy" "p" {
      name   = "p"
      policy = data.aws_iam_policy_document.d.json
    }
    """
    state, _ = T.to_state(write_tf(tmp_path, main=src))
    pol = next(r["values"]["policy"] for r in state["values"]["root_module"]["resources"]
               if r["type"] == "aws_iam_policy")
    doc = json.loads(pol)
    assert doc["Statement"][0]["Action"] == ["iam:CreatePolicyVersion"]
    assert "DateGreaterThan" in doc["Statement"][0]["Condition"]


GROUP_TF = """
    resource "aws_iam_group" "g" { name = "g" }
    resource "aws_iam_policy" "gp" {
      name   = "gp"
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "bedrock:Retrieve",
        Resource = aws_bedrockagent_knowledge_base.kb.arn}]})
    }
    resource "aws_bedrockagent_knowledge_base" "kb" { name = "kb1" }
    resource "aws_iam_group_policy_attachment" "ga" {
      group      = aws_iam_group.g.name
      policy_arn = aws_iam_policy.gp.arn
    }
    resource "aws_iam_user" "member" { name = "member" }
    resource "aws_iam_group_membership" "m" {
      name  = "m"
      group = aws_iam_group.g.name
      users = [aws_iam_user.member.name]
    }
"""


def test_group_membership_counts_towards_a_user_reach(tmp_path):
    """Groups were not modelled at all, so auth(p) was wrong for every user in one,
    not only for the group privesc paths."""
    res = analyse(tmp_path, main=GROUP_TF)
    assert res["member"]["n_auth"] > 0


def test_joining_a_group_is_an_escalation(tmp_path):
    src = GROUP_TF + """
    resource "aws_iam_user" "outsider" { name = "outsider" }
    resource "aws_iam_user_policy" "op" {
      name = "op"
      user = aws_iam_user.outsider.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "iam:AddUserToGroup",
        Resource = "*"}]})
    }
    """
    r = analyse(tmp_path, main=src)["outsider"]
    assert r["Esc"] is True
    assert any("knowledge-base/kb1" in w["reaches"] for w in r["witnesses"])


def test_minting_credentials_for_another_user_is_an_escalation(tmp_path):
    src = GROUP_TF + """
    resource "aws_iam_user" "thief" { name = "thief" }
    resource "aws_iam_user_policy" "tp" {
      name = "tp"
      user = aws_iam_user.thief.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "iam:CreateAccessKey",
        Resource = "*"}]})
    }
    """
    r = analyse(tmp_path, main=src)["thief"]
    assert r["Esc"] is True


def test_rewriting_your_own_permissions_is_self_escalation_not_delegation(tmp_path):
    """eff equals auth here, so Esc is correctly false. It is still an escalation
    and has to be reported as its own class rather than disappearing."""
    src = """
    resource "aws_iam_user" "u" { name = "u" }
    resource "aws_iam_policy" "up" {
      name   = "up"
      policy = jsonencode({Statement = [{Effect = "Allow",
        Action = "iam:CreatePolicyVersion", Resource = "*"}]})
    }
    resource "aws_iam_user_policy_attachment" "ua" {
      user       = aws_iam_user.u.name
      policy_arn = aws_iam_policy.up.arn
    }
    """
    r = analyse(tmp_path, main=src)["u"]
    assert r["Esc"] is False
    assert r["self_escalation"] is True

def test_writing_a_policy_onto_another_identity_is_an_escalation(tmp_path):
    """privesc12-PutRolePolicy class: the attacker is handed nothing, it rewrites
    what another identity may do and reaches through it."""
    src = """
    resource "aws_bedrockagent_knowledge_base" "kb" { name = "kb1" }
    resource "aws_iam_role" "target" { name = "target" }
    resource "aws_iam_role_policy" "tp" {
      name   = "tp"
      role   = aws_iam_role.target.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "bedrock:Retrieve",
        Resource = aws_bedrockagent_knowledge_base.kb.arn}]})
    }
    resource "aws_iam_user" "writer" { name = "writer" }
    resource "aws_iam_user_policy" "wp" {
      name   = "wp"
      user   = aws_iam_user.writer.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "iam:PutRolePolicy",
        Resource = "*"}]})
    }
    """
    r = analyse(tmp_path, main=src)["writer"]
    assert r["Esc"] is True
    assert any("knowledge-base/kb1" in w["reaches"] for w in r["witnesses"])


def test_rewriting_a_role_trust_is_an_escalation(tmp_path):
    src = """
    resource "aws_bedrockagent_knowledge_base" "kb" { name = "kb1" }
    resource "aws_iam_role" "target" { name = "target" }
    resource "aws_iam_role_policy" "tp" {
      name   = "tp"
      role   = aws_iam_role.target.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "bedrock:Retrieve",
        Resource = aws_bedrockagent_knowledge_base.kb.arn}]})
    }
    resource "aws_iam_user" "u" { name = "u" }
    resource "aws_iam_user_policy" "up" {
      name   = "up"
      user   = aws_iam_user.u.name
      policy = jsonencode({Statement = [{Effect = "Allow",
        Action = "iam:UpdateAssumeRolePolicy", Resource = "*"}]})
    }
    """
    assert analyse(tmp_path, main=src)["u"]["Esc"] is True


# ------------------------------------------------- count and for_each indices ---

def test_indexed_role_reference_keeps_the_policy_attached(tmp_path):
    """`role = aws_iam_role.x[0].id` must still attach the policy to that role.

    The reference scanner stopped at the first `[`, so the value became
    `${aws_iam_role.x}` with the index and the `.id` dropped. The policy then had
    an owner that matched no identity and the role looked as though it held no
    permissions at all. Measured on the corpus, 32 of 181 agent runtime template
    directories address a role this way, so the engine was silently blind on 18%
    of real deployments.
    """
    src = """
    resource "aws_bedrockagent_knowledge_base" "kb" { name = "kb1" }
    resource "aws_iam_role" "agentcore" {
      count = local.create_role ? 1 : 0
      name  = "agentcore"
      assume_role_policy = jsonencode({Statement = [{Effect = "Allow",
        Principal = {Service = "bedrock-agentcore.amazonaws.com"},
        Action = "sts:AssumeRole"}]})
    }
    resource "aws_iam_role_policy" "memory" {
      count  = local.create_role && var.enable_memory ? 1 : 0
      name   = "memory"
      role   = aws_iam_role.agentcore[0].id
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "bedrock:Retrieve",
        Resource = aws_bedrockagent_knowledge_base.kb.arn}]})
    }
    resource "aws_iam_user" "u" { name = "u" }
    resource "aws_iam_user_policy" "up" {
      name   = "up"
      user   = aws_iam_user.u.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = ["iam:PassRole",
        "bedrock-agentcore:CreateCodeInterpreter"], Resource = "*"}]})
    }
    """
    state, _ = T.to_state(write_tf(tmp_path, main=src))
    owners = [r["values"].get("role") for r in state["values"]["root_module"]["resources"]
              if r["type"] == "aws_iam_role_policy"]
    assert owners == ["agentcore"], owners
    # and the restored permission must be visible end to end
    r = analyse(tmp_path, main=src)["u"]
    assert r["Esc"] is True
    assert any("knowledge-base/kb1" in w["reaches"] for w in r["witnesses"])


def test_indexed_resource_reference_resolves_in_a_policy_resource(tmp_path):
    """An indexed reference inside a Resource list must name the real ARN.

    `aws_bedrockagentcore_agent_runtime.a[0].agent_runtime_arn` used to collapse to
    `${aws_bedrockagentcore_agent_runtime.a}`, which matches no ARN, so a hand-off
    that the policy explicitly permits was invisible.
    """
    src = """
    resource "aws_iam_role" "caller" { name = "caller" }
    resource "aws_bedrockagentcore_agent_runtime" "a" {
      count              = 1
      agent_runtime_name = "callee"
    }
    resource "aws_iam_role_policy" "p" {
      name   = "p"
      role   = aws_iam_role.caller.name
      policy = jsonencode({Statement = [{Effect = "Allow",
        Action = "bedrock-agentcore:InvokeAgentRuntime",
        Resource = aws_bedrockagentcore_agent_runtime.a[0].agent_runtime_arn}]})
    }
    """
    state, _ = T.to_state(write_tf(tmp_path, main=src))
    pol = [r["values"]["policy"] for r in state["values"]["root_module"]["resources"]
           if r["type"] == "aws_iam_role_policy"][0]
    assert "${" not in pol, pol
    assert "agent-runtime/callee" in pol or "callee" in pol


def test_for_each_and_splat_indices_also_collapse(tmp_path):
    """The index may be each.key, a quoted name or a splat, not only a number."""
    src = """
    resource "aws_bedrockagent_knowledge_base" "kb" { name = "kb1" }
    resource "aws_iam_role" "r" { for_each = var.envs
      name = "r" }
    resource "aws_iam_role_policy" "p" {
      for_each = var.envs
      name     = "p"
      role     = aws_iam_role.r[each.key].name
      policy   = jsonencode({Statement = [{Effect = "Allow", Action = "bedrock:Retrieve",
        Resource = aws_bedrockagent_knowledge_base.kb.arn}]})
    }
    """
    state, _ = T.to_state(write_tf(tmp_path, main=src))
    owners = [r["values"].get("role") for r in state["values"]["root_module"]["resources"]
              if r["type"] == "aws_iam_role_policy"]
    assert owners == ["r"], owners


# ------------------------------------------------------ invoke verb by platform ---

def test_agentcore_wildcard_does_not_reach_a_classic_bedrock_agent(tmp_path):
    """`bedrock-agentcore:*` on `*` must not create a hand-off to a classic agent.

    A classic `aws_bedrockagent_agent` is invoked with `bedrock:InvokeAgent`, not
    with `bedrock-agentcore:InvokeAgentRuntime`. Probing the AgentCore verb against
    every agent node made a wildcard AgentCore grant look like a hand-off into a
    classic agent, which is not an invocation path that exists. This was one real
    false positive in the corpus measurement.
    """
    src = """
    resource "aws_iam_role" "core" { name = "core" }
    resource "aws_iam_role_policy" "p" {
      name   = "p"
      role   = aws_iam_role.core.name
      policy = jsonencode({Statement = [{Effect = "Allow",
        Action = "bedrock-agentcore:*", Resource = "*"}]})
    }
    resource "aws_bedrockagentcore_agent_runtime" "caller" {
      agent_runtime_name = "caller"
      role_arn           = aws_iam_role.core.arn
    }
    resource "aws_bedrockagent_agent" "classic" { agent_name = "classic" }
    """
    G, _ = graph_of(tmp_path, main=src)
    assert not [(u, v) for u, v, d in G.edges(data=True) if d.get("rel") == "handoff"]


def test_classic_invoke_verb_is_recognised(tmp_path):
    """The other direction: `bedrock:InvokeAgent` on a classic agent is a hand-off."""
    src = """
    resource "aws_iam_role" "core" { name = "core" }
    resource "aws_bedrockagent_agent" "classic" { agent_name = "classic" }
    resource "aws_iam_role_policy" "p" {
      name   = "p"
      role   = aws_iam_role.core.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "bedrock:InvokeAgent",
        Resource = aws_bedrockagent_agent.classic.arn}]})
    }
    resource "aws_bedrockagentcore_agent_runtime" "caller" {
      agent_runtime_name = "caller"
      role_arn           = aws_iam_role.core.arn
    }
    """
    G, _ = graph_of(tmp_path, main=src)
    edges = [(u, v, d) for u, v, d in G.edges(data=True) if d.get("rel") == "handoff"]
    assert [(u, v) for u, v, _ in edges] == [("caller", "classic")], edges
    assert edges[0][2]["permitted_action"] == "bedrock:InvokeAgent"
    assert edges[0][2]["permitted_scope"] == "exact"


# ----------------------------------------------------- locals and expressions ---

def test_expression_after_a_reference_does_not_corrupt_the_next_key(tmp_path):
    """`a = var.x == null` must not eat the next attribute's name.

    The value parser read `var.x` and stopped at the operator, leaving `== null`
    in the stream. The next key then started mid-token: in one corpus module
    `role_arn` was read as `ole_arn`, so the local that carried the execution role
    did not exist and every runtime in that module scored as role-less.
    """
    text = """
    locals {
      create_role = var.role_arn == null
      role_arn    = var.role_arn != null ? var.role_arn : aws_iam_role.r[0].arn
      plain       = "hello"
    }
    """
    got = dict(T.parse_locals(textwrap.dedent(text)))
    assert sorted(got) == ["create_role", "plain", "role_arn"], sorted(got)
    assert got["plain"] == "hello"


def test_a_local_carrying_the_execution_role_resolves(tmp_path):
    """role_arn routed through a locals ternary must still name the role.

    This is the shape three corpus modules use: the role is created unless the
    caller supplies one, and the runtime points at the local rather than at the
    role. One branch of the ternary is a module input that no template-scoped
    analysis can see, so the resolvable branch is taken, which is the role whose
    policies can actually be checked.
    """
    src = """
    locals {
      create_role = var.role_arn == null
      role_arn    = var.role_arn != null ? var.role_arn : aws_iam_role.agentcore[0].arn
    }
    resource "aws_iam_role" "agentcore" {
      count = local.create_role ? 1 : 0
      name  = "AgentCoreRole"
    }
    resource "aws_bedrockagentcore_agent_runtime" "this" {
      agent_runtime_name = "a"
      role_arn           = local.role_arn
    }
    """
    state, _ = T.to_state(write_tf(tmp_path, main=src))
    rt = [r for r in state["values"]["root_module"]["resources"]
          if r["type"] == "aws_bedrockagentcore_agent_runtime"][0]
    assert rt["values"]["role_arn"] == f"arn:aws:iam::{ACCT}:role/AgentCoreRole"


def test_a_nested_ternary_is_left_unresolved_rather_than_guessed(tmp_path):
    """Refusing to split beats splitting wrongly: an invented value is worse."""
    assert T.ternary_branches("a ? b : c ? d : e") is None
    assert T.ternary_branches("var.x != null ? var.x : aws_iam_role.r[0].arn") == (
        "var.x", "aws_iam_role.r[0].arn")


def test_a_ternary_with_two_resolvable_branches_is_not_decided(tmp_path):
    """Both branches knowable means the condition decides, and it cannot be read."""
    src = """
    resource "aws_iam_role" "a" { name = "roleA" }
    resource "aws_iam_role" "b" { name = "roleB" }
    locals {
      picked = var.flag ? aws_iam_role.a.arn : aws_iam_role.b.arn
    }
    resource "aws_bedrockagentcore_agent_runtime" "this" {
      agent_runtime_name = "a"
      role_arn           = local.picked
    }
    """
    state, _ = T.to_state(write_tf(tmp_path, main=src))
    rt = [r for r in state["values"]["root_module"]["resources"]
          if r["type"] == "aws_bedrockagentcore_agent_runtime"][0]
    assert "${" in str(rt["values"]["role_arn"])


def test_a_resolved_branch_may_still_carry_a_module_input(tmp_path):
    """The role ARN is usable even when the role name contains a variable.

    Requiring a fully literal value rejected the common shape
    `name = "AgentCoreRuntime-${var.agent_name}"`, which left two corpus modules
    role-less. The unresolved input appears identically in the ARN synthesised
    for the role itself, so the runtime and the role still match.
    """
    src = """
    locals {
      create_role = var.role_arn == null
      role_arn    = var.role_arn != null ? var.role_arn : aws_iam_role.agentcore[0].arn
    }
    resource "aws_iam_role" "agentcore" {
      count = local.create_role ? 1 : 0
      name  = "AgentCoreRuntime-${var.agent_name}"
    }
    resource "aws_bedrockagentcore_agent_runtime" "this" {
      agent_runtime_name = "a"
      role_arn           = local.role_arn
    }
    """
    state, _ = T.to_state(write_tf(tmp_path, main=src))
    by = {(r["type"], r["name"]): r["values"]
          for r in state["values"]["root_module"]["resources"]}
    runtime = by[("aws_bedrockagentcore_agent_runtime", "this")]["role_arn"]
    role = by[("aws_iam_role", "agentcore")]["arn"]
    assert runtime == role, (runtime, role)


def test_two_attributes_on_one_line_both_survive(tmp_path):
    """Reading an expression to end of line must not swallow the next attribute."""
    src = ('resource "aws_iam_role" "a" { name = "roleA" }\n'
           'resource "aws_bedrockagentcore_agent_runtime" "this" '
           '{ agent_runtime_name = "a" role_arn = aws_iam_role.a.arn }\n')
    (tmp_path / "main.tf").write_text(src)
    state, _ = T.to_state(str(tmp_path))
    rt = [r for r in state["values"]["root_module"]["resources"]
          if r["type"] == "aws_bedrockagentcore_agent_runtime"][0]["values"]
    assert rt["agent_runtime_name"] == "a"
    assert rt["role_arn"] == f"arn:aws:iam::{ACCT}:role/roleA"


def test_controlling_a_managed_policy_reaches_everyone_it_is_attached_to(tmp_path):
    """`iam:CreatePolicyVersion` on a policy attached to another role is delegation.

    Rewriting a shared managed policy hands the attacker every identity that policy
    is attached to, without touching those identities directly. The spec lists this
    as one of the eight ways to obtain an identity, and it had no test.
    """
    src = """
    resource "aws_bedrockagent_knowledge_base" "kb" { name = "kb1" }
    resource "aws_iam_role" "target" { name = "target" }
    resource "aws_iam_policy" "shared" {
      name   = "shared"
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "bedrock:Retrieve",
        Resource = aws_bedrockagent_knowledge_base.kb.arn}]})
    }
    resource "aws_iam_role_policy_attachment" "a" {
      role       = aws_iam_role.target.name
      policy_arn = aws_iam_policy.shared.arn
    }
    resource "aws_iam_user" "u" { name = "u" }
    resource "aws_iam_user_policy" "up" {
      name   = "up"
      user   = aws_iam_user.u.name
      policy = jsonencode({Statement = [{Effect = "Allow",
        Action = "iam:CreatePolicyVersion", Resource = aws_iam_policy.shared.arn}]})
    }
    """
    r = analyse(tmp_path, main=src)["u"]
    assert r["Esc"] is True
    assert any("knowledge-base/kb1" in w["reaches"] for w in r["witnesses"])


# ------------------------------------------------- corpus path independence ---

def test_exclusion_is_judged_inside_the_corpus_not_on_the_whole_path(tmp_path):
    """An absolute corpus path must give the same answer as a relative one.

    The exclusion substrings name repositories INSIDE the corpus. One of them
    is this repository's own directory name, so matching against the whole path
    excluded every template whenever the corpus was addressed absolutely, and
    the scan reported zero findings with no warning. The default clone name is
    the one that triggers it, so anyone cloning and running the tool with an
    absolute path hit it.
    """
    import gap as G
    rel = "corpus_tier2/someorg__somerepo/terraform"
    abs_ = f"/home/someone/agent-pathtriage/{rel}"
    assert G.is_excluded(rel) is False
    assert G.is_excluded(abs_, "/home/someone/agent-pathtriage/corpus_tier2") is False
    # and a genuinely excluded repository is still excluded either way
    bad_rel = "corpus_tier2/BishopFox__iam-vulnerable/terraform"
    bad_abs = f"/home/someone/agent-pathtriage/{bad_rel}"
    assert G.is_excluded(bad_rel) is True
    assert G.is_excluded(bad_abs, "/home/someone/agent-pathtriage/corpus_tier2") is True


def test_scan_gives_the_same_answer_for_relative_and_absolute_corpus(tmp_path):
    """End to end: the same corpus addressed two ways scores the same."""
    import os
    import gap as G
    corpus = tmp_path / "agent-pathtriage" / "corpus_tier2" / "org__repo" / "tf"
    corpus.mkdir(parents=True)
    (corpus / "main.tf").write_text(textwrap.dedent("""
        resource "aws_iam_role" "exec" { name = "exec" }
        resource "aws_bedrockagentcore_agent_runtime" "this" {
          agent_runtime_name = "a"
          role_arn           = aws_iam_role.exec.arn
        }
    """))
    root = str(tmp_path / "agent-pathtriage" / "corpus_tier2")
    assert G.is_excluded(str(corpus), root) is False
    cwd = os.getcwd()
    try:
        os.chdir(str(tmp_path / "agent-pathtriage"))
        assert G.is_excluded("corpus_tier2/org__repo/tf") is False
    finally:
        os.chdir(cwd)


def test_a_wildcard_inside_one_named_resource_is_not_any(tmp_path):
    """`runtime/mcp/runtime-endpoint/*` names one runtime, `runtime/*` does not.

    Blast radius is positional, not "does a star appear". Treating the two
    alike reported a role scoped to one agent as permitted to invoke any
    agent, and it also made a correct repair look like it had failed: after
    narrowing to the declared target the pattern still contained a star.
    """
    spans = E.resource_spans_many
    assert spans("arn:aws:bedrock-agentcore:r:a:runtime/*") is True
    assert spans("arn:aws:bedrock-agentcore:r:a:runtime/mcp") is False
    assert spans("arn:aws:bedrock-agentcore:r:a:runtime/mcp/runtime-endpoint/*") is False
    assert spans("arn:aws:bedrock-agentcore:r:a:runtime/mcp*") is True
    assert spans("arn:aws:s3:::bucket/*") is True
    assert spans("*") is True


def test_a_handoff_scoped_to_the_declared_target_is_exact(tmp_path):
    """End to end: narrowing the invoke resource changes the reported scope."""
    src = """
    resource "aws_iam_role" "core" { name = "core" }
    resource "aws_bedrockagentcore_agent_runtime" "callee" {
      agent_runtime_name = "callee"
    }
    resource "aws_bedrockagentcore_agent_runtime" "caller" {
      agent_runtime_name = "caller"
      role_arn           = aws_iam_role.core.arn
    }
    resource "aws_iam_role_policy" "p" {
      name   = "p"
      role   = aws_iam_role.core.name
      policy = jsonencode({Statement = [{Effect = "Allow",
        Action = "bedrock-agentcore:InvokeAgentRuntime",
        Resource = [aws_bedrockagentcore_agent_runtime.callee.arn,
          "${aws_bedrockagentcore_agent_runtime.callee.arn}/runtime-endpoint/*"]}]})
    }
    """
    G, _ = graph_of(tmp_path, main=src)
    edges = [d for _u, _v, d in G.edges(data=True) if d.get("rel") == "handoff"]
    assert edges, "expected a permitted hand-off edge"
    assert edges[0]["permitted_scope"] == "exact", edges[0]


# -------------------------------------------- composing hops, one caller each ---

def test_a_second_hop_does_not_lend_its_service_permission_backwards(tmp_path):
    """p holding PassRole cannot borrow another role's ability to start a service.

    An outside review suggested the enabled-edge check should chase a further
    hop to find the Write-level action, on the grounds that the caller might
    obtain it by delegation first. It should not, and the model is already
    right: IAM evaluates one request against one principal, so the PassRole
    and the service action are checked against the SAME caller. If p assumes
    the helper, the request is made by the helper, and the helper's PassRole
    is what counts.

    Here the helper can start the service but cannot pass the target, so
    nothing composes and the correct answer is no escalation.
    """
    src = """
    resource "aws_bedrockagent_knowledge_base" "kb" { name = "kb1" }
    resource "aws_iam_role" "target" {
      name = "target"
      assume_role_policy = jsonencode({Statement = [{Effect = "Allow",
        Principal = {Service = "bedrock-agentcore.amazonaws.com"},
        Action = "sts:AssumeRole"}]})
    }
    resource "aws_iam_role_policy" "tp" {
      name   = "tp"
      role   = aws_iam_role.target.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "bedrock:Retrieve",
        Resource = aws_bedrockagent_knowledge_base.kb.arn}]})
    }
    resource "aws_iam_role" "helper" {
      name = "helper"
      assume_role_policy = jsonencode({Statement = [{Effect = "Allow",
        Principal = {AWS = "arn:aws:iam::000000000000:user/p"},
        Action = "sts:AssumeRole"}]})
    }
    resource "aws_iam_role_policy" "hp" {
      name   = "hp"
      role   = aws_iam_role.helper.name
      policy = jsonencode({Statement = [{Effect = "Allow",
        Action = "bedrock-agentcore:CreateCodeInterpreter", Resource = "*"}]})
    }
    resource "aws_iam_user" "p" { name = "p" }
    resource "aws_iam_user_policy" "pp" {
      name   = "pp"
      user   = aws_iam_user.p.name
      policy = jsonencode({Statement = [
        {Effect = "Allow", Action = "iam:PassRole", Resource = "*"},
        {Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.helper.arn}]})
    }
    """
    assert analyse(tmp_path, main=src)["p"]["Esc"] is False


def test_a_hop_that_holds_both_does_compose(tmp_path):
    """The same shape, with the helper able to pass the target as well.

    The pair matters: without this one, the test above would also pass on a
    model that simply never composes hops.
    """
    src = """
    resource "aws_bedrockagent_knowledge_base" "kb" { name = "kb1" }
    resource "aws_iam_role" "target" {
      name = "target"
      assume_role_policy = jsonencode({Statement = [{Effect = "Allow",
        Principal = {Service = "bedrock-agentcore.amazonaws.com"},
        Action = "sts:AssumeRole"}]})
    }
    resource "aws_iam_role_policy" "tp" {
      name   = "tp"
      role   = aws_iam_role.target.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "bedrock:Retrieve",
        Resource = aws_bedrockagent_knowledge_base.kb.arn}]})
    }
    resource "aws_iam_role" "helper" {
      name = "helper"
      assume_role_policy = jsonencode({Statement = [{Effect = "Allow",
        Principal = {AWS = "arn:aws:iam::000000000000:user/p"},
        Action = "sts:AssumeRole"}]})
    }
    resource "aws_iam_role_policy" "hp" {
      name   = "hp"
      role   = aws_iam_role.helper.name
      policy = jsonencode({Statement = [
        {Effect = "Allow", Action = "bedrock-agentcore:CreateCodeInterpreter",
         Resource = "*"},
        {Effect = "Allow", Action = "iam:PassRole", Resource = "*"}]})
    }
    resource "aws_iam_user" "p" { name = "p" }
    resource "aws_iam_user_policy" "pp" {
      name   = "pp"
      user   = aws_iam_user.p.name
      policy = jsonencode({Statement = [
        {Effect = "Allow", Action = "iam:PassRole", Resource = "*"},
        {Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.helper.arn}]})
    }
    """
    r = analyse(tmp_path, main=src)["p"]
    assert r["Esc"] is True
    assert any("knowledge-base/kb1" in w["reaches"] for w in r["witnesses"])


def test_a_trust_naming_a_user_directly_is_a_delegation(tmp_path):
    """A role whose trust policy names the user is assumable without sts in the
    user's own policy. The review asked whether a non-service trust principal
    is handled, and it is: the trust policy alone grants it."""
    src = """
    resource "aws_bedrockagent_knowledge_base" "kb" { name = "kb1" }
    resource "aws_iam_role" "target" {
      name = "target"
      assume_role_policy = jsonencode({Statement = [{Effect = "Allow",
        Principal = {AWS = "arn:aws:iam::000000000000:user/p"},
        Action = "sts:AssumeRole"}]})
    }
    resource "aws_iam_role_policy" "tp" {
      name   = "tp"
      role   = aws_iam_role.target.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "bedrock:Retrieve",
        Resource = aws_bedrockagent_knowledge_base.kb.arn}]})
    }
    resource "aws_iam_user" "p" { name = "p" }
    resource "aws_iam_user_policy" "pp" {
      name   = "pp"
      user   = aws_iam_user.p.name
      policy = jsonencode({Statement = [{Effect = "Allow", Action = "s3:ListBucket",
        Resource = "*"}]})
    }
    """
    assert analyse(tmp_path, main=src)["p"]["Esc"] is True

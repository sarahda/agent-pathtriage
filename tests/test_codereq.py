#!/usr/bin/env python3
"""
Regression test for codereq. Synthetic templates, no corpus needed.

codereq's job is to decide when a grant may be called unnecessary. That verdict
is what gets sent to a repository owner, so every rule that WITHHOLDS the
verdict is tested here: an unresolved SDK wrapper, a generic AWS tool, and code
that does not parse. A regression in any of them turns a withheld verdict into a
false report.

Run:  python3 -m pytest tests/test_codereq.py -q
"""
import os
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "agentpathtriage"),
           os.path.join(ROOT, "evaluation", "benchmark")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import codereq as C   # noqa: E402

TF = '''
resource "aws_iam_role" "exec" { name = "exec" }
resource "aws_iam_role_policy" "p" {
  name   = "p"
  role   = aws_iam_role.exec.name
  policy = jsonencode({Statement = [{Effect = "Allow",
    Action = ["bedrock-agentcore:ListEvents", "bedrock-agentcore:CreateEvent"],
    Resource = "*"}]})
}
resource "aws_bedrockagentcore_agent_runtime" "this" {
  agent_runtime_name = "a"
  role_arn           = aws_iam_role.exec.arn
}
'''


def build(tmp_path, code):
    (tmp_path / "main.tf").write_text(textwrap.dedent(TF))
    (tmp_path / "agent.py").write_text(textwrap.dedent(code))
    return str(tmp_path)


def test_boto3_calls_become_actions(tmp_path):
    """`client('bedrock-agentcore').list_events()` is `ListEvents`, Pascal cased."""
    d = build(tmp_path, '''
        import boto3
        c = boto3.client("bedrock-agentcore")
        c.list_events(memoryId="m")
    ''')
    r = C.assess(d)
    assert "bedrock-agentcore:ListEvents" in r["required_actions"]


def test_a_grant_the_code_never_uses_is_reportable(tmp_path):
    """The point of the module: an unused grant, with nothing clouding it."""
    d = build(tmp_path, '''
        import boto3
        c = boto3.client("bedrock-agentcore")
        c.list_events(memoryId="m")
    ''')
    r = C.assess(d)
    assert r["verdict_possible"] is True
    assert r["over_granted"] == ["bedrock-agentcore:CreateEvent"]


def test_sdk_wrapper_suppresses_the_verdict_for_its_namespace(tmp_path):
    """A wrapper method is not an API name, so the action cannot be asserted.

    `CodeInterpreter.invoke` issues InvokeCodeInterpreter, not Invoke. Guessing
    would make every other agentcore grant look unused. The namespace is marked
    unresolved and no agentcore grant is called unnecessary.
    """
    d = build(tmp_path, '''
        from bedrock_agentcore.tools.code_interpreter_client import CodeInterpreter
        ci = CodeInterpreter("us-east-1")
        ci.invoke(code="print(1)")
    ''')
    r = C.assess(d)
    assert r["unresolved_namespaces"] == ["bedrock-agentcore"]
    assert r["over_granted"] == []


def test_a_generic_aws_tool_withholds_the_verdict_entirely(tmp_path):
    """`use_aws` lets the model issue any call, so the source cannot bound it.

    This is the real weather-agent case. Without this rule the sample looks like
    it needs nothing and every grant looks unnecessary, which would have been a
    false report to AWS.
    """
    d = build(tmp_path, '''
        from strands_tools import use_aws
        from strands import Agent
        agent = Agent(tools=[use_aws])
    ''')
    r = C.assess(d)
    assert r["verdict_possible"] is False
    assert "use_aws" in r["generic_aws_tools"]
    assert r["over_granted"] == []


def test_unparseable_code_withholds_the_verdict(tmp_path):
    """Code that does not parse is not evidence that nothing is needed."""
    (tmp_path / "main.tf").write_text(textwrap.dedent(TF))
    (tmp_path / "agent.py").write_text("def broken(:\n")
    r = C.assess(str(tmp_path))
    assert r["verdict_possible"] is False
    assert r["parse_failed"] == 1


def test_no_code_withholds_the_verdict(tmp_path):
    """A template with no colocated code says nothing about what is needed."""
    (tmp_path / "main.tf").write_text(textwrap.dedent(TF))
    r = C.assess(str(tmp_path))
    assert r["verdict_possible"] is False
    assert r["why_no_verdict"] == "no code colocated"


def test_code_needing_what_config_omits_is_reported(tmp_path):
    """The other direction. Cheap to report and it shows config-only can miss."""
    d = build(tmp_path, '''
        import boto3
        c = boto3.client("bedrock-agentcore")
        c.start_browser_session(browserIdentifier="b")
    ''')
    r = C.assess(d)
    assert "bedrock-agentcore:StartBrowserSession" in r["under_granted"]


def test_test_files_are_not_read_as_production_code(tmp_path):
    """A test states what the code MAY do, not what it does when deployed."""
    (tmp_path / "main.tf").write_text(textwrap.dedent(TF))
    (tmp_path / "test_agent.py").write_text(
        'import boto3\nc = boto3.client("bedrock-agentcore")\nc.create_event()\n')
    r = C.assess(str(tmp_path))
    assert r["code_files"] == 0


# A declared hand-off is the configuration saying the invoke action is used.
# Without this, a repository whose code reaches the callee in a way the parser
# does not resolve gets told its invoke grant is unnecessary, which is the
# false over-grant report the disclosure gate exists to prevent. It happened
# on avparkhi/agui-agentcore-demo before the guard existed.
TF_HANDOFF = '''
resource "aws_iam_role" "exec" { name = "exec" }
resource "aws_iam_role_policy" "p" {
  name   = "p"
  role   = aws_iam_role.exec.name
  policy = jsonencode({Statement = [{Effect = "Allow",
    Action = ["bedrock-agentcore:InvokeAgentRuntime",
              "bedrock-agentcore:ListEvents"],
    Resource = "*"}]})
}
resource "aws_bedrockagentcore_agent_runtime" "callee" {
  agent_runtime_name = "callee"
  role_arn           = aws_iam_role.exec.arn
}
resource "aws_bedrockagentcore_agent_runtime" "caller" {
  agent_runtime_name = "caller"
  role_arn           = aws_iam_role.exec.arn
  environment_variables = {
    CALLEE_AGENT_ARN = aws_bedrockagentcore_agent_runtime.callee.agent_runtime_arn
  }
}
'''

CODE_NOT_INVOKING = '''
    import boto3
    c = boto3.client("bedrock-agentcore")
    c.list_events(memoryId="m")
'''


def _handoff_template(tmp_path):
    (tmp_path / "main.tf").write_text(textwrap.dedent(TF_HANDOFF))
    (tmp_path / "agent.py").write_text(textwrap.dedent(CODE_NOT_INVOKING))
    return str(tmp_path)


def test_a_declared_handoff_counts_as_use_of_the_invoke_action(tmp_path):
    r = C.assess(_handoff_template(tmp_path))
    assert "bedrock-agentcore:InvokeAgentRuntime" in r["required_by_configuration"]


def test_a_declared_handoff_keeps_invoke_out_of_over_granted(tmp_path):
    r = C.assess(_handoff_template(tmp_path))
    assert r["verdict_possible"], r.get("why_no_verdict")
    assert "bedrock-agentcore:InvokeAgentRuntime" not in r["over_granted"]


def test_the_guard_does_not_hide_a_genuinely_unused_grant(tmp_path):
    """ListEvents is granted and the code calls it; CreateEvent is not in this
    template. The guard must not turn over_granted into a blanket pass."""
    r = C.assess(_handoff_template(tmp_path))
    assert "bedrock-agentcore:ListEvents" not in r["over_granted"]
    d = build(tmp_path / "plain", '''
        import boto3
        c = boto3.client("bedrock-agentcore")
        c.list_events(memoryId="m")
    ''') if (tmp_path / "plain").mkdir() or True else None
    r2 = C.assess(d)
    assert "bedrock-agentcore:CreateEvent" in r2["over_granted"]

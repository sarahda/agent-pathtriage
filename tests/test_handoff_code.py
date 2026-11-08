"""The discriminator that carries C1's upper bound.

handoff_code reports an interval: the configuration alone declares a hand-off
in 6 of 204 templates, and the configuration or the code names a callee in 56.
The upper end rests entirely on one judgement, which is whether an environment
variable name identifies a particular agent.

Getting it wrong in either direction is costly. Too loose and the bound is
inflated: counting CLIENT_ID, MEMORY_ID and ROLE_ARN put it at 44.6 percent,
and the generic AGENT_RUNTIME_ARN appears in 53 single-agent templates where
it is the template's own address exported for a caller, not a hand-off. Too
strict and the bound collapses back onto the configuration, which is the thing
C1 exists to question.

So the rule is pinned here by example, in both directions.
"""

import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "agentpathtriage", "handoff_code.py")


def _load():
    for p in (os.path.join(ROOT, "agentpathtriage"),
              os.path.join(ROOT, "evaluation", "benchmark")):
        if p not in sys.path:
            sys.path.insert(0, p)
    spec = importlib.util.spec_from_file_location("handoff_code_under_test", SRC)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["handoff_code_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


H = _load()

NAMES_A_CALLEE = [
    "WEATHER_AGENT_RUNTIME_URL",
    "SHOPPING_AGENT_RUNTIME_URL",
    "SUPERVISOR_AGENT_ARN",
    "MCP_SERVER_ARN",
    "TRIAGE_AGENT_RUNTIME_ARN",
    "ACCOUNTS_AGENT_URL",
    "GMAIL_MCP_GATEWAY_URL",
]

# the template's own address, exported for whoever calls it
GENERIC_ADDRESS = [
    "AGENT_RUNTIME_ARN",
    "AGENTCORE_RUNTIME_ARN",
    "AGENTCORE_RUNTIME_URL",
    "AGENT_RUNTIME_URL",
]

# not an address at all
NOT_AN_ADDRESS = [
    "AGENT_MEMORY_ID",
    "AI_AGENT_CLIENT_ID",
    "AI_AGENT_KEY_SECRET_ID",
    "AGENT_MCP_TOKEN_ENDPOINT",
    "AGENT_MCP_AUTHORIZATION_ENDPOINT",
    "AGENT_MCP_REDIRECT_URL",
    "BEDROCK_AGENTCORE_ROLE_ARN",
    "FRONTIER_AGENTS_FEDERATION_ROLE_ARN",
    "BEDROCK_AGENTCORE_MEMORY_ID",
]

# nothing to do with agents
UNRELATED = [
    "AWS_REGION",
    "LOG_LEVEL",
    "TABLE_NAME",
    "RUNTIME_TIMEOUT",
    "AGENT_NAME",
]


def test_a_name_that_identifies_a_callee_counts():
    for v in NAMES_A_CALLEE:
        assert H.names_a_callee(v), v


def test_a_generic_runtime_address_does_not_count():
    """Counting these is what put the upper bound at 44.6 percent."""
    for v in GENERIC_ADDRESS:
        assert not H.names_a_callee(v), v


def test_a_credential_or_memory_handle_does_not_count():
    for v in NOT_AN_ADDRESS:
        assert not H.names_a_callee(v), v


def test_an_unrelated_variable_does_not_count():
    for v in UNRELATED:
        assert not H.names_a_callee(v), v


def test_a_role_arn_is_not_an_agent():
    assert not H.names_a_callee("FRONTIER_AGENTS_FEDERATION_ROLE_ARN")
    assert not H.names_a_callee("BEDROCK_AGENTCORE_ROLE_ARN")


def test_the_env_read_pattern_finds_every_spelling():
    src = (
        'a = os.environ["ONE_AGENT_ARN"]\n'
        "b = os.environ.get('TWO_AGENT_ARN')\n"
        'c = os.getenv("THREE_AGENT_ARN")\n'
    )
    found = set(H.ENV_READ.findall(src))
    assert found == {"ONE_AGENT_ARN", "TWO_AGENT_ARN", "THREE_AGENT_ARN"}, found


def test_a_repository_with_no_python_yields_no_verdict(tmp_path):
    """Absent evidence is not evidence of absence, as in codereq."""
    code = H.read_repo(str(tmp_path))
    assert code["py_files"] == 0

#!/usr/bin/env python3
"""What suppression is allowed to hide, and what the SARIF has to say.

Baseline suppression is the one feature in this tool that can make a real
finding invisible, so the tests are written against that risk rather than
against the happy path. Three things have to hold:

  a fingerprint is stable across runs, or every finding reappears every run
  and the baseline gets deleted within a week;

  a fingerprint discriminates, or a new escalation hides behind an old one;

  nothing is ever dropped silently. A suppressed finding is counted in the
  text output and written into the SARIF marked suppressed, because a
  baseline records that somebody decided to live with a finding, which is not
  the same as the finding not being there.

The SARIF tests are mostly about the things GitHub silently discards rather
than rejects: a result whose ruleId is not in the driver's rule list, a
ruleIndex pointing at the wrong rule, a path that escapes the repository root.
A SARIF file that uploads successfully and shows nothing is the failure mode
worth a test.

Run:  python3 -m pytest tests/test_findings_sarif.py -q
"""
import json
import os
import re
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agentpathtriage"))
sys.path.insert(0, os.path.join(ROOT, "evaluation", "benchmark"))

import cli        # noqa: E402
import findings as F   # noqa: E402
import sarif as S      # noqa: E402
import tf_to_state as T  # noqa: E402

CLEAN = 'resource "aws_iam_role" "r" { name = "r" }\n'

ESCALATING = '''
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
resource "aws_iam_user" "u" { name = "u" }
resource "aws_iam_user_policy" "up" {
  name   = "up"
  user   = aws_iam_user.u.name
  policy = jsonencode({Statement = [{Effect = "Allow", Action = ["iam:PassRole",
    "bedrock-agentcore:CreateCodeInterpreter"], Resource = "*"}]})
}
'''

# a second knowledge base the same user reaches the same way: one more
# APT001, with everything else about the template unchanged
ONE_MORE_RESOURCE = '''
resource "aws_bedrockagent_knowledge_base" "kb2" { name = "kb2" }
resource "aws_iam_role_policy" "tp2" {
  name   = "tp2"
  role   = aws_iam_role.target.name
  policy = jsonencode({Statement = [{Effect = "Allow", Action = "bedrock:Retrieve",
    Resource = aws_bedrockagent_knowledge_base.kb2.arn}]})
}
'''

SHARED_ROLE = '''
resource "aws_iam_role" "shared" {
  name = "shared"
  assume_role_policy = jsonencode({Statement = [{Effect = "Allow",
    Principal = {Service = "bedrock-agentcore.amazonaws.com"},
    Action = "sts:AssumeRole"}]})
}
resource "aws_bedrockagentcore_agent_runtime" "alpha" {
  agent_runtime_name = "alpha"
  role_arn           = aws_iam_role.shared.arn
}
resource "aws_bedrockagentcore_agent_runtime" "beta" {
  agent_runtime_name = "beta"
  role_arn           = aws_iam_role.shared.arn
}
'''


def write(tmp_path, body, name="main.tf"):
    (tmp_path / name).write_text(textwrap.dedent(body))
    return str(tmp_path)


def collect(d):
    state, _ = T.to_state(d)
    return F.collect(state, d)


# ------------------------------------------------------------- fingerprints

def test_the_same_template_names_its_findings_the_same_way(tmp_path):
    d = write(tmp_path, ESCALATING)
    first = {f["fingerprint"] for f in collect(d)}
    second = {f["fingerprint"] for f in collect(d)}
    assert first and first == second


def test_a_fingerprint_cannot_be_spelled_two_ways():
    """Joined on a separator, not concatenated.

    Without one, ("a", "bc") and ("ab", "c") are the same string and therefore
    the same finding, and one of them disappears into the other's baseline
    entry.
    """
    assert F.fingerprint("a", "bc") != F.fingerprint("ab", "c")


def test_an_extra_reachable_resource_is_a_new_finding(tmp_path):
    d = write(tmp_path, ESCALATING)
    before = {f["fingerprint"] for f in collect(d)}
    (tmp_path / "more.tf").write_text(textwrap.dedent(ONE_MORE_RESOURCE))
    after = {f["fingerprint"] for f in collect(d)}
    assert after > before, "a newly reachable resource must not inherit a name"


def test_the_analyser_stamp_changes_when_the_analyser_does(tmp_path, monkeypatch):
    """A baseline is only meaningful under the build that wrote it."""
    before = F.analyser_stamp()
    monkeypatch.setattr(F, "_HERE", str(tmp_path))
    assert F.analyser_stamp() != before


# ------------------------------------------------------------ what it finds

def test_two_agents_on_one_role_is_a_finding_that_fails_the_run(tmp_path):
    d = write(tmp_path, SHARED_ROLE)
    got = [f for f in collect(d) if f["rule"] == "APT003"]
    assert len(got) == 1, [f["rule"] for f in collect(d)]
    assert sorted(got[0]["agents"]) == ["alpha", "beta"]
    assert got[0]["fails_run"]
    assert cli.main(["scan", d]) == 1


def test_an_agent_whose_role_did_not_resolve_is_not_grouped(tmp_path):
    """Undecided is not the same as shared, and guessing invents a finding."""

    class FakeIx:
        agents = {"a": {"role_arn": None}, "b": {"role_arn": "None"},
                  "c": {"role_arn": None}}

    assert F._shared_execution_roles(FakeIx()) == {}


def test_a_linter_visible_grant_does_not_fail_the_run(tmp_path):
    """APT006 is reported and attributed, and is not this project's claim."""
    assert "APT006" not in F.FAILING
    assert F.RULES["APT006"]["level"] == "note"


def test_every_rule_has_a_level_and_only_failing_rules_are_errors():
    for rid, r in F.RULES.items():
        assert r["level"] in ("error", "warning", "note"), rid
        assert (r["level"] == "error") == (rid in F.FAILING), rid


def test_what_is_printed_and_what_is_exited_on_are_the_same_list(tmp_path, capsys):
    """A scan of two agents on one role printed "none" and then exited 1.

    The narrative report is organised for a reader and predates the flat
    finding list, so it describes some classes and not others. The exit code
    comes from the list. Anything that disagrees with the exit code is worse
    than terse, so the list is printed too, and this holds both to it.
    """
    for body in (CLEAN, ESCALATING, SHARED_ROLE):
        d = write(tmp_path, body)   # one main.tf, rewritten each time
        code = cli.main(["scan", d])
        out = capsys.readouterr().out
        printed = {r for r in F.FAILING if r in out}
        assert (code == 1) == bool(printed), (body[:30], code, printed)
        assert (f"exit {code}" in out), out[-300:]


# ---------------------------------------------------------------- locating

def test_a_finding_points_at_the_line_that_declares_it(tmp_path):
    d = write(tmp_path, ESCALATING)
    lines = F.resource_lines(d)
    path, line = lines[("aws_iam_role", "target")]
    text = open(path).read().splitlines()
    assert 'resource "aws_iam_role" "target"' in text[line - 1]


def test_a_resource_header_inside_a_comment_is_not_a_resource(tmp_path):
    d = write(tmp_path, '''
        # resource "aws_iam_role" "ghost" { name = "ghost" }
        resource "aws_iam_role" "real" { name = "real" }
    ''')
    lines = F.resource_lines(d)
    assert ("aws_iam_role", "ghost") not in lines
    assert ("aws_iam_role", "real") in lines


def test_a_finding_that_cannot_be_placed_says_so(tmp_path):
    d = write(tmp_path, ESCALATING)
    loc = F.Locator(d)
    got = loc.of_resource("aws_iam_role", "not-in-this-template")
    assert got["located"] is False
    assert got["file"], "it still has to land somewhere to be displayed at all"


# ---------------------------------------------------------------- baseline

def test_a_baselined_finding_stops_failing_the_run(tmp_path):
    d = write(tmp_path, ESCALATING)
    b = str(tmp_path / "baseline.json")
    assert cli.main(["scan", d]) == 1
    assert cli.main(["scan", d, "--write-baseline", b]) == 0
    assert cli.main(["scan", d, "--baseline", b]) == 0


def test_a_new_finding_still_fails_a_baselined_run(tmp_path):
    """The whole point. If this passes with 1 it is doing its job."""
    d = write(tmp_path, ESCALATING)
    b = str(tmp_path / "baseline.json")
    cli.main(["scan", d, "--write-baseline", b])
    (tmp_path / "more.tf").write_text(textwrap.dedent(ONE_MORE_RESOURCE))
    assert cli.main(["scan", d, "--baseline", b]) == 1


def test_suppressed_findings_are_counted_out_loud(tmp_path, capsys):
    d = write(tmp_path, ESCALATING)
    b = str(tmp_path / "baseline.json")
    cli.main(["scan", d, "--write-baseline", b])
    capsys.readouterr()
    cli.main(["scan", d, "--baseline", b])
    out = capsys.readouterr().out
    assert re.search(r"baseline: [1-9]\d* finding\(s\) suppressed", out), out


def test_a_baseline_entry_that_matches_nothing_is_reported(tmp_path, capsys):
    d = write(tmp_path, ESCALATING)
    b = tmp_path / "baseline.json"
    doc = F.write_baseline(collect(d), str(b))
    doc["fingerprints"]["0000000000000000"] = {"rule": "APT001",
                                               "rule_name": "delegation-escalation",
                                               "message": "fixed long ago"}
    b.write_text(json.dumps(doc))
    capsys.readouterr()
    cli.main(["scan", d, "--baseline", str(b)])
    assert "matched nothing" in capsys.readouterr().out


def test_a_baseline_from_another_build_warns(tmp_path, capsys):
    d = write(tmp_path, ESCALATING)
    b = tmp_path / "baseline.json"
    doc = F.write_baseline(collect(d), str(b))
    doc["analyser"] = "0123456789abcdef"
    b.write_text(json.dumps(doc))
    capsys.readouterr()
    cli.main(["scan", d, "--baseline", str(b)])
    assert "different build" in capsys.readouterr().out


def test_a_missing_baseline_is_an_error_not_a_clean_scan(tmp_path):
    """Exit 2. A typo in the path must not read as nothing to report."""
    d = write(tmp_path, ESCALATING)
    assert cli.main(["scan", d, "--baseline", str(tmp_path / "nope.json")]) == 2


def test_a_file_that_is_not_a_baseline_is_an_error(tmp_path):
    d = write(tmp_path, ESCALATING)
    bad = tmp_path / "bad.json"
    bad.write_text('{"results": []}')
    assert cli.main(["scan", d, "--baseline", str(bad)]) == 2


def test_only_failing_rules_are_recorded_in_a_baseline(tmp_path):
    """Baselining a note would be recording that a linter has an opinion."""
    d = write(tmp_path, ESCALATING)
    doc = F.write_baseline(collect(d), str(tmp_path / "b.json"))
    assert doc["fingerprints"]
    for v in doc["fingerprints"].values():
        assert v["rule"] in F.FAILING


# ------------------------------------------------------------------- SARIF

def sarif_of(tmp_path, body=ESCALATING, baseline=False):
    d = write(tmp_path, body)
    out = str(tmp_path / "out.sarif")
    args = ["scan", d, "--sarif", out, "--sarif-base", d]
    if baseline:
        b = str(tmp_path / "b.json")
        cli.main(["scan", d, "--write-baseline", b])
        args += ["--baseline", b]
    cli.main(args)
    return json.load(open(out))


def test_the_sarif_is_version_2_1_0_with_one_run(tmp_path):
    doc = sarif_of(tmp_path)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    assert doc["runs"][0]["tool"]["driver"]["name"] == "AgentPathTriage"


def test_every_result_points_at_a_rule_that_exists(tmp_path):
    """A ruleId the driver does not declare is dropped without an error."""
    run = sarif_of(tmp_path)["runs"][0]
    ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert run["results"]
    for res in run["results"]:
        assert res["ruleId"] in ids
        assert ids[res["ruleIndex"]] == res["ruleId"], "ruleIndex disagrees"


def test_every_result_has_a_relative_location_inside_the_tree(tmp_path):
    """An absolute path, or one starting with .., is discarded on upload."""
    for res in sarif_of(tmp_path)["runs"][0]["results"]:
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not os.path.isabs(uri), uri
        assert not uri.startswith(".."), uri
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_every_result_carries_its_fingerprint(tmp_path):
    for res in sarif_of(tmp_path)["runs"][0]["results"]:
        assert res["partialFingerprints"][S.FINGERPRINT_KEY]


def test_a_suppressed_finding_is_written_out_marked_suppressed(tmp_path):
    """Not dropped. A baseline says somebody decided to live with it."""
    results = sarif_of(tmp_path, baseline=True)["runs"][0]["results"]
    assert results, "a baselined scan still reports what it found"
    supp = [r for r in results if r.get("suppressions")]
    assert supp
    assert supp[0]["suppressions"][0]["kind"] == "external"


def test_the_sarif_reports_the_shared_role_finding(tmp_path):
    """The project's headline finding has to reach the interface."""
    run = sarif_of(tmp_path, SHARED_ROLE)["runs"][0]
    assert any(r["ruleId"] == "APT003" for r in run["results"])


def test_a_clean_template_produces_an_empty_but_valid_sarif(tmp_path):
    run = sarif_of(tmp_path, CLEAN)["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"]


def test_a_sarif_whose_results_cannot_be_placed_warns(tmp_path, capsys):
    """An upload that displays nothing is the quietest way to fail.

    Scanning --state has no source to point at, so the results carry no
    location, and code scanning discards those without an error.
    """
    d = write(tmp_path, SHARED_ROLE)
    state = tmp_path / "state.json"
    st, _ = T.to_state(d)
    state.write_text(json.dumps(st))
    capsys.readouterr()
    cli.main(["scan", "--state", str(state), "--sarif", str(tmp_path / "x.sarif")])
    assert "no file location" in capsys.readouterr().err


def test_the_sarif_version_is_the_package_version():
    pyproject = open(os.path.join(ROOT, "pyproject.toml")).read()
    want = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M).group(1)
    assert S.version() == want


# ------------------------------------------------------------------ action

def test_the_action_runs_the_command_the_readme_documents():
    """A workflow that calls a flag the CLI does not have fails only in CI."""
    path = os.path.join(ROOT, "action.yml")
    if not os.path.exists(path):
        import pytest
        pytest.skip("action.yml is not in this tree")
    text = open(path).read()
    # only the lines that build the command, so that an unrelated --flag in a
    # pip invocation or a comment is not mistaken for one of ours
    invocation = [ln for ln in text.splitlines() if "args=(" in ln or "args+=(" in ln]
    assert invocation, "action.yml no longer builds the scan command here"
    used = set()
    for ln in invocation:
        used.update(re.findall(r"(?<![\w-])(--[a-z][a-z-]*)", ln))
    assert {"--sarif", "--sarif-base", "--baseline"} <= used, used

    parser = open(os.path.join(ROOT, "agentpathtriage", "cli.py")).read()
    accepted = set(re.findall(r'"(--[a-z][a-z-]*)"', parser))
    for flag in sorted(used):
        assert flag in accepted, f"{flag} is not a flag the CLI accepts"

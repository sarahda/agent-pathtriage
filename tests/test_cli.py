#!/usr/bin/env python3
"""
Regression tests for the command line.

The exit code is the contract. A tool meant to sit in CI that returns 1 for
"the directory does not exist" is worse than one that returns nothing, because
the caller reads it as a finding. Both of those were wrong in the first
version: report's render was called with the wrong signature, so every scan
exited 2, and a missing directory raised SystemExit with a string, which exits
1 and therefore looked like a finding.

Run:  python3 -m pytest tests/test_cli.py -q
"""
import os
import sys
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agentpathtriage"))

import cli   # noqa: E402

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


def write(tmp_path, body):
    (tmp_path / "main.tf").write_text(textwrap.dedent(body))
    return str(tmp_path)


def test_no_findings_exits_zero(tmp_path, capsys):
    assert cli.main(["scan", write(tmp_path, CLEAN)]) == 0


def test_findings_exit_one(tmp_path, capsys):
    assert cli.main(["scan", write(tmp_path, ESCALATING)]) == 1


def test_a_missing_directory_exits_two_not_one(tmp_path, capsys):
    """Two, not one. One means findings, and a missing path is not a finding."""
    assert cli.main(["scan", str(tmp_path / "does-not-exist")]) == 2


def test_a_directory_with_no_terraform_exits_two(tmp_path, capsys):
    assert cli.main(["scan", str(tmp_path)]) == 2


def test_the_same_directory_scores_the_same_by_either_path(tmp_path, capsys):
    """Absolute and relative must agree.

    The exclusion filter once matched the path TO the corpus, so an absolute
    path silently returned nothing. The command line is where a reviewer meets
    that, since cloning and pointing at an absolute path is the normal way to
    try a tool.
    """
    d = write(tmp_path, ESCALATING)
    absolute = cli.main(["scan", os.path.abspath(d)])
    cwd = os.getcwd()
    try:
        os.chdir(os.path.dirname(d))
        relative = cli.main(["scan", os.path.basename(d)])
    finally:
        os.chdir(cwd)
    assert absolute == relative == 1


def test_json_format_is_parseable(tmp_path, capsys):
    import json
    cli.main(["scan", write(tmp_path, ESCALATING), "--format", "json"])
    out = capsys.readouterr().out
    assert json.loads(out)["results"]


def test_doctor_reports_ready(capsys):
    """If doctor says ready, a scan must actually work. It runs one to check."""
    assert cli.main(["doctor"]) == 0
    assert "smoke test" in capsys.readouterr().out

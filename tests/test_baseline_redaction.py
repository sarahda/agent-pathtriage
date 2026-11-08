"""The baseline evidence must carry no identifier tied to a real account.

baseline/baseline_out/ holds what third-party tools printed when run against
the lab account, and it has to stay in the repository for the comparison
against Cloudsplaining to be checkable. The ARNs in it were redacted to
000000000000, but the AWS unique identifiers beside them were not, and those
carry the account id in a form AWS itself decodes through
`aws sts get-access-key-info`. The redaction did not hold until they went too.

These tests fail if any real-shaped identifier returns, whether through a
re-run of a baseline tool that overwrites the evidence or through a new file
dropped into the directory.
"""

import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(ROOT, "baseline", "baseline_out")
REDACTOR = os.path.join(ROOT, "evaluation", "benchmark", "redact_baseline.py")

# 20 characters for an access key id, 21 for an IAM unique id
AWS_UNIQUE_ID = re.compile(r"\b(AKIA|AIDA|AROA|ASIA)([A-Z0-9]{16,17})\b")
OPERATOR_PATH = re.compile(r"/Users/(?!researcher\b)[A-Za-z0-9_.-]+")
# the last segment of a GUID is also 12 digits, so a run preceded by a hyphen
# or followed by one is part of a GUID rather than an account id
ACCOUNT_ID = re.compile(
    r"(?<![-\d])(?!000000000000|111122223333|123456789012)\d{12}(?![-\d])")

pytestmark = pytest.mark.skipif(not os.path.isdir(BASELINE),
                                reason="no baseline evidence in this checkout")


def _texts():
    out = {}
    for name in sorted(os.listdir(BASELINE)):
        p = os.path.join(BASELINE, name)
        if os.path.isfile(p):
            out[name] = open(p, encoding="utf-8", errors="ignore").read()
    return out


def test_no_real_aws_unique_identifier():
    bad = {}
    for name, text in _texts().items():
        hits = {m.group(0) for m in AWS_UNIQUE_ID.finditer(text)
                if "EXAMPLE" not in m.group(0)}
        if hits:
            bad[name] = sorted(hits)
    assert not bad, (
        "real AWS unique identifiers in the baseline evidence: "
        f"{bad}. Run: python3 evaluation/benchmark/redact_baseline.py")


def test_no_operator_home_directory():
    bad = {name: sorted(set(OPERATOR_PATH.findall(text)))
           for name, text in _texts().items() if OPERATOR_PATH.search(text)}
    assert not bad, f"operator paths in the baseline evidence: {bad}"


def test_no_real_account_id():
    bad = {name: sorted(set(ACCOUNT_ID.findall(text)))
           for name, text in _texts().items() if ACCOUNT_ID.search(text)}
    assert not bad, f"account ids in the baseline evidence: {bad}"


def test_the_redactor_has_nothing_left_to_do():
    """--check exits 0 only when a re-run would change nothing."""
    proc = subprocess.run([sys.executable, REDACTOR, "--check"],
                          capture_output=True, text=True, cwd=ROOT, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_redactor_is_idempotent():
    """A second pass must not renumber what the first pass assigned."""
    before = _texts()
    proc = subprocess.run([sys.executable, REDACTOR],
                          capture_output=True, text=True, cwd=ROOT, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _texts() == before, "re-running the redactor changed the evidence"

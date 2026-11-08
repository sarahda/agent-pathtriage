"""Run the collect_corpus_v3.sh logic tests under pytest.

The collector is a shell script, so its tests are a shell harness
(tests/test_collect_corpus_v3.sh) driven by a fake `gh` that returns canned
search pages. Wrapping it here means `pytest tests -q` covers the collector
too, so the pagination defect that truncated the corpus at one page per query
cannot come back unnoticed.
"""

import os
import shutil
import subprocess

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "test_collect_corpus_v3.sh")


@pytest.mark.skipif(shutil.which("jq") is None, reason="jq is required by the collector")
def test_collector_shell_harness():
    proc = subprocess.run(
        ["bash", HARNESS],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, (
        "collect_corpus_v3.sh logic tests failed\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    # the harness prints one PASS line per assertion; a silent no-op run that
    # asserted nothing would otherwise look like success
    assert proc.stdout.count("PASS") >= 15, proc.stdout

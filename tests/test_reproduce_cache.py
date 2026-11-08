"""The corpus-walk cache must not survive into the next verification run.

reproduce.py --full re-walks the corpus instead of trusting a cache, because a
cached row is a row produced by the code as it was then. A sliced run still has
to keep what it already did, so it leaves a marker beside the cache.

On 2026-10-15 that marker was an empty file recording only "a run started
once". It survived into the next verification run, which then reused a cache
written at 01:07 by the pre-469bf27 is_excluded. That cache carried 160
wrongly excluded templates, so the verification reported 84 templates against
the committed 220 and looked like a reproduction failure when the committed
numbers were right.

The marker now carries a stamp of the analyser code and the corpus size, and
the walk deletes it once the walk completes.
"""

import importlib.util
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(ROOT, "evaluation", "reproduce.py")


def _load():
    spec = importlib.util.spec_from_file_location("reproduce_under_test", SPEC)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["reproduce_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


R = _load()


def test_an_empty_marker_is_not_accepted_as_a_stamp(tmp_path):
    """The old marker format was an empty file. It must invalidate the cache."""
    marker = tmp_path / "gap.py.started"
    marker.write_text("")
    assert R.read_stamp(str(marker)) != R.code_stamp()


def test_a_missing_marker_is_not_accepted_as_a_stamp(tmp_path):
    marker = tmp_path / "absent.started"
    assert R.read_stamp(str(marker)) is None
    assert R.read_stamp(str(marker)) != R.code_stamp()


def test_a_marker_written_now_matches_the_current_stamp(tmp_path):
    marker = tmp_path / "gap.py.started"
    marker.write_text(R.code_stamp())
    assert R.read_stamp(str(marker)) == R.code_stamp()


def test_the_stamp_changes_when_the_analyser_code_changes(tmp_path, monkeypatch):
    before = R.code_stamp()
    target = os.path.join(ROOT, "agentpathtriage", "gap.py")
    original = open(target, "rb").read()
    try:
        with open(target, "ab") as fh:
            fh.write(b"\n# stamp probe\n")
        assert R.code_stamp() != before
    finally:
        with open(target, "wb") as fh:
            fh.write(original)
    assert R.code_stamp() == before


def test_the_stamp_changes_when_the_corpus_grows(tmp_path):
    """Measured on a throwaway directory, never on the real corpus.

    The first version of this test made a directory inside corpus_tier2 and
    removed it in a finally block. Deletion is not always permitted in that
    folder, so the directory survived and the corpus was one larger than every
    committed number said. A test must not be able to do that.
    """
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "owner__repo").mkdir()
    before = R.code_stamp(str(corpus))
    (corpus / "owner__second").mkdir()
    assert R.code_stamp(str(corpus)) != before


def test_the_stamp_is_stable_for_an_unchanged_corpus(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "owner__repo").mkdir()
    assert R.code_stamp(str(corpus)) == R.code_stamp(str(corpus))

"""Which duplicate survives must not depend on cache insertion order.

topology.py de-duplicates templates by content hash. It used to de-duplicate
in the order the cache file happened to list them and sort only the
survivors, so the output order was stable while the choice of survivor was
not. On 2026-10-15 a cache seeded with the 351 repositories collected first
kept X-GPT__mymemo-agent, and a single walk of all 1647 kept
MyMemoAI__mymemo-agent. The rows were identical and only the name moved,
which is still enough to make the committed artifact fail to reproduce.

Sorting before de-duplication makes the survivor the alphabetically first
path, whatever order the cache was filled in.
"""

import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOPO = os.path.join(ROOT, "evaluation", "benchmark", "topology.py")


def _load():
    sys.path.insert(0, os.path.join(ROOT, "evaluation", "benchmark"))
    spec = importlib.util.spec_from_file_location("topology_under_test", TOPO)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["topology_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


T = _load()

SHARED_HASH = "a" * 64


def _row(t):
    return {"t": t, "h": SHARED_HASH, "n_agents": 2, "handoffs": []}


def _write(path, rows):
    with open(path, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
            fh.write(json.dumps({"_repo_done": r["t"].split("/")[0]}) + "\n")
    return str(path)


def test_the_surviving_duplicate_does_not_depend_on_cache_order(tmp_path):
    early = _write(tmp_path / "early.jsonl",
                   [_row("X-GPT__mymemo-agent/infra"), _row("MyMemoAI__mymemo-agent/infra")])
    late = _write(tmp_path / "late.jsonl",
                  [_row("MyMemoAI__mymemo-agent/infra"), _row("X-GPT__mymemo-agent/infra")])
    a = [r["t"] for r in T.load_rows(early)]
    b = [r["t"] for r in T.load_rows(late)]
    assert a == b, f"cache order changed the survivor: {a} vs {b}"


def test_the_survivor_is_the_alphabetically_first_path(tmp_path):
    cache = _write(tmp_path / "c.jsonl",
                   [_row("zz__later/infra"), _row("aa__earlier/infra")])
    kept = [r["t"] for r in T.load_rows(cache)]
    assert kept == ["aa__earlier/infra"], kept


def test_templates_with_different_hashes_are_all_kept(tmp_path):
    rows = [{"t": "b__two/infra", "h": "b" * 64, "n_agents": 1, "handoffs": []},
            {"t": "a__one/infra", "h": "c" * 64, "n_agents": 1, "handoffs": []}]
    cache = _write(tmp_path / "c.jsonl", rows)
    kept = [r["t"] for r in T.load_rows(cache)]
    assert kept == ["a__one/infra", "b__two/infra"], kept


def test_the_hash_is_not_carried_into_the_output(tmp_path):
    cache = _write(tmp_path / "c.jsonl", [_row("a__one/infra")])
    assert all("h" not in r for r in T.load_rows(cache))

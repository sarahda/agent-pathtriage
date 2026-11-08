#!/usr/bin/env python3
"""Re-derive every corpus number after the corpus changes, as a delta.

Why this exists
    collect_corpus_v3.sh grows the corpus. Every number that has the corpus
    as its denominator then has to be recomputed, and the committed JSON
    artifacts in evaluation/benchmark/ describe the old corpus. Overwriting
    them directly would move the numbers silently, so this driver writes to a
    staging directory first, prints committed value against new value for
    every headline field, and only replaces the artifacts under --promote.

    evaluation/reproduce.py answers "do the committed artifacts still follow
    from the committed code". This answers the different question "what does
    the new corpus change". Run this one first, promote, then run reproduce.py
    to confirm the new artifacts are themselves reproducible.

Resumability
    gap.py, topology.py and corpus_population.py each take a per-repository
    cache and a time budget. The caches live in the workdir and are keyed by
    repository directory name, so after the corpus grows only the new
    repositories are walked. With --budget, a stage that runs out of time
    leaves its cache in place and this exits 2; re-run to continue.

Usage
    python3 evaluation/benchmark/remeasure.py --corpus corpus_tier2
    python3 evaluation/benchmark/remeasure.py --budget 1800     # slice it
    python3 evaluation/benchmark/remeasure.py --promote         # adopt
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
GAP = os.path.join(ROOT, "agentpathtriage", "gap.py")

# staged name -> committed artifact path
ARTIFACTS = {
    "corpus_population": os.path.join(HERE, "corpus_population_tier2.json"),
    "gap":               os.path.join(HERE, "gap_tier2_v1.json"),
    "topology":          os.path.join(HERE, "topology_tier2.json"),
    "shared_role":       os.path.join(HERE, "shared_role_tier2.json"),
    "adjudication":      os.path.join(HERE, "adjudication_tier2.json"),
}


def load(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return None


# Each entry: (artifact, label, extractor). The extractor returns None when the
# field cannot be derived, which prints as "n/a" rather than as a zero. A
# missing number must not be able to masquerade as a measured zero.
def _len(x):
    return len(x) if isinstance(x, (list, dict)) else None


def _get(key):
    return lambda d: d.get(key) if isinstance(d, dict) else None


def _multi_agent(topo):
    if not isinstance(topo, list):
        return None
    return sum(1 for t in topo if (t.get("n_agents") or 0) >= 2)


def _handoff_declared(topo):
    if not isinstance(topo, list):
        return None
    return sum(1 for t in topo if t.get("handoffs"))


def _verdict(name):
    def f(adj):
        if not isinstance(adj, list):
            return None
        return sum(1 for r in adj if r.get("verdict") == name)
    return f


def _edges(evidence):
    def f(topo):
        if not isinstance(topo, list):
            return None
        return sum(1 for t in topo for h in (t.get("handoffs") or [])
                   if h.get("evidence") == evidence)
    return f


def _scope(scope):
    def f(topo):
        if not isinstance(topo, list):
            return None
        return sum(1 for t in topo for h in (t.get("handoffs") or [])
                   if h.get("scope") == scope)
    return f


def _declared_but_any(topo):
    """Agents wired to one named callee whose role still permits calling any.

    The gap between what the deployment says an agent talks to and what its
    identity allows it to talk to. This is the headline of the hand-off
    analysis, so it is tracked rather than left to be read off a log.
    """
    if not isinstance(topo, list):
        return None
    n = 0
    for t in topo:
        hs = t.get("handoffs") or []
        by_src = {}
        for h in hs:
            by_src.setdefault(h.get("from"), []).append(h)
        for src, edges in by_src.items():
            declared = [h for h in edges if str(h.get("evidence", "")).startswith("declared")]
            permits_any = any(h.get("scope") == "any" for h in edges)
            if len(declared) == 1 and permits_any:
                n += 1
    return n


FIELDS = [
    ("corpus_population", "repositories cloned",      _get("repositories")),
    ("corpus_population", "  no .tf at all",          _get("no_tf")),
    ("corpus_population", "  .tf but no runtime",     _get("tf_no_runtime")),
    ("corpus_population", "  with runtime",           _get("with_runtime")),
    ("corpus_population", "template dirs",            _get("template_dirs")),
    ("corpus_population", "  excluded",               _get("excluded")),
    ("corpus_population", "  fork copies",            _get("fork_copies")),
    ("corpus_population", "final templates",          _get("final_templates")),
    ("corpus_population", "last commit before cutoff", _get("last_commit_before")),
    ("corpus_population", "last commit after cutoff",  _get("last_commit_after")),
    ("corpus_population", "policy_document blocks",   _get("policy_document_blocks")),
    ("corpus_population", "  templates using one",    _get("templates_using_policy_document")),

    ("gap", "agent runtimes",                 _get("n_runtimes")),
    ("gap", "templates",                      _get("n_templates")),
    ("gap", "wired recovered",                _get("wired_recovered")),
    ("gap", "wired by reference",             _get("wired_by_reference")),
    ("gap", "resource-scope gap",             _get("resource_scope_gap")),
    ("gap", "full ac:*",                      _get("full_ac_star")),
    ("gap", "role unresolved",                _get("role_unresolved")),
    ("gap", "roles w/ unread attachments",    _get("roles_with_unread_attachments")),

    ("topology", "templates in topology",     _len),
    ("topology", "multi-agent templates",     _multi_agent),
    ("topology", "hand-off declared",         _handoff_declared),
    ("topology", "  edges declared_resolved",  _edges("declared_resolved")),
    ("topology", "  edges declared_unresolved", _edges("declared_unresolved")),
    ("topology", "  edges permitted",          _edges("permitted")),
    ("topology", "  scope any",                _scope("any")),
    ("topology", "  scope exact",              _scope("exact")),
    ("topology", "declared 1 but may call any", _declared_but_any),

    ("shared_role", "multi-agent templates",  _get("multi_agent_templates")),
    ("shared_role", "shared execution role",  lambda d: _len(d.get("shared_role")) if isinstance(d, dict) else None),
    ("shared_role", "distinct roles",         lambda d: _len(d.get("distinct_roles")) if isinstance(d, dict) else None),
    ("shared_role", "undecided",              lambda d: _len(d.get("undecided")) if isinstance(d, dict) else None),

    ("adjudication", "gaps adjudicated",      _len),
    ("adjudication", "  cross-agent",         _verdict("cross-agent")),
    ("adjudication", "  shared-role",         _verdict("shared-role")),
    ("adjudication", "  single-agent",        _verdict("single-agent")),
    ("adjudication", "  narrow",              _verdict("narrow")),
]


def code_stamp(corpus):
    """What a cached corpus walk depends on: the analyser code and the corpus.

    A cache written by earlier code describes an earlier measurement. Reusing
    it silently is how a stale row survives a fix: on 2026-10-15 a cache
    written before the is_excluded fix carried 160 wrongly excluded templates
    into a later verification, and a cache seeded in two sittings disagreed
    with a single walk about which de-duplicated template name survives.
    """
    h = hashlib.sha256()
    for d in (os.path.join(ROOT, "agentpathtriage"), HERE):
        for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if f.endswith(".py"):
                with open(os.path.join(d, f), "rb") as fh:
                    h.update(f.encode())
                    h.update(fh.read())
    n = len([x for x in os.listdir(corpus)
             if os.path.isdir(os.path.join(corpus, x))]) if os.path.isdir(corpus) else -1
    h.update(str(n).encode())
    return h.hexdigest()


def fresh_cache(path, corpus):
    """Return path, deleting it first if it was written by different code."""
    stamp = code_stamp(corpus)
    marker = path + ".stamp"
    try:
        with open(marker) as fh:
            current = fh.read().strip()
    except Exception:
        current = None
    if current != stamp:
        if os.path.exists(path):
            os.remove(path)
            print(f"   cache discarded, written by different code: {path}")
        with open(marker, "w") as fh:
            fh.write(stamp)
    return path


def run(cmd, label):
    print(f"-- {label}")
    print("   " + " ".join(cmd))
    proc = subprocess.run(cmd, cwd=ROOT)
    return proc.returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus_tier2")
    ap.add_argument("--workdir", default=".remeasure")
    ap.add_argument("--budget", type=float, default=0,
                    help="seconds per resumable stage; 0 means no limit")
    ap.add_argument("--promote", action="store_true",
                    help="replace the committed artifacts with the staged ones")
    ap.add_argument("--report", help="write the delta table here as JSON")
    ap.add_argument("--only", help="comma separated subset of stages to run: "
                    "corpus_population,gap,topology,shared_role,adjudication. "
                    "Stages not run keep whatever the workdir already holds, "
                    "and any stage with no staged output reports n/a rather "
                    "than a zero.")
    a = ap.parse_args()

    corpus = os.path.abspath(a.corpus)
    work = os.path.abspath(a.workdir)
    os.makedirs(work, exist_ok=True)
    if not os.path.isdir(corpus):
        sys.exit(f"corpus not found: {corpus}")

    n_repos = len([d for d in os.listdir(corpus)
                   if os.path.isdir(os.path.join(corpus, d))])
    print(f"corpus: {corpus}  ({n_repos} repository directories)")
    print(f"workdir: {work}\n")

    staged = {k: os.path.join(work, k + ".json") for k in ARTIFACTS}
    budget = ["--budget", str(a.budget)] if a.budget else []
    incomplete = []

    all_stages = ["corpus_population", "gap", "topology", "shared_role", "adjudication"]
    if a.only:
        want = [x.strip() for x in a.only.split(",") if x.strip()]
        unknown = [x for x in want if x not in all_stages]
        if unknown:
            sys.exit("unknown stage(s): " + ", ".join(unknown))
    else:
        want = all_stages
    # a stage that was not asked for is not incomplete, it is just not run,
    # so --promote must still refuse unless every stage has a staged output
    skipped = [x for x in all_stages if x not in want]
    if skipped:
        print("not running: " + ", ".join(skipped) + "\n")

    # corpus_population, gap and topology each walk the corpus, so each gets
    # its own cache and its own slice of the budget.
    stages = [
        (["corpus_population"], [sys.executable, os.path.join(HERE, "corpus_population.py"),
                                 "--corpus", corpus, "--json", staged["corpus_population"],
                                 "--cache", fresh_cache(os.path.join(work, "corpus_population.cache"), corpus)] + budget),
        (["gap"], [sys.executable, GAP,
                   "--corpus", corpus, "--json", staged["gap"],
                   "--cache", fresh_cache(os.path.join(work, "gap.cache"), corpus)] + budget),
        (["topology"], [sys.executable, os.path.join(HERE, "topology.py"),
                        "--corpus", corpus, "--json", staged["topology"],
                        "--cache", fresh_cache(os.path.join(work, "topology.cache"), corpus)] + budget),
    ]
    for names, cmd in stages:
        if names[0] not in want:
            continue
        rc = run(cmd, names[0])
        if rc != 0:
            incomplete.append(names[0])
            print(f"   stage did not complete (exit {rc})")

    # these two read the stage outputs above rather than the corpus directly
    if "shared_role" not in want:
        pass
    elif "topology" not in incomplete and os.path.exists(staged["topology"]):
        rc = run([sys.executable, os.path.join(HERE, "shared_role.py"),
                  "--topology", staged["topology"], "--corpus", corpus,
                  "--json", staged["shared_role"]], "shared_role")
        if rc != 0:
            incomplete.append("shared_role")
    else:
        incomplete.append("shared_role")
        print("-- shared_role skipped: topology is incomplete")

    if "adjudication" not in want:
        pass
    elif "gap" not in incomplete and os.path.exists(staged["gap"]):
        rc = run([sys.executable, os.path.join(HERE, "adjudicate_gaps.py"),
                  "--gap", staged["gap"], "--corpus", corpus,
                  "--json", staged["adjudication"]], "adjudication")
        if rc != 0:
            incomplete.append("adjudication")
    else:
        incomplete.append("adjudication")
        print("-- adjudication skipped: gap is incomplete")

    # ------------------------------------------------------------- delta
    old = {k: load(v) for k, v in ARTIFACTS.items()}
    new = {k: load(v) for k, v in staged.items()}

    print()
    print(f"{'measurement':<32} {'committed':>12} {'new':>12} {'delta':>10}")
    print("-" * 70)
    rows = []
    for art, label, fn in FIELDS:
        o = fn(old.get(art)) if old.get(art) is not None else None
        n = fn(new.get(art)) if new.get(art) is not None else None
        if isinstance(o, int) and isinstance(n, int):
            d = n - o
            ds = f"{d:+d}" if d else "="
        else:
            ds = ""
        print(f"{label:<32} {('n/a' if o is None else o)!s:>12} "
              f"{('n/a' if n is None else n)!s:>12} {ds:>10}")
        rows.append({"artifact": art, "label": label.strip(),
                     "committed": o, "new": n})

    print()
    if incomplete:
        print("INCOMPLETE stages: " + ", ".join(sorted(set(incomplete))))
        print("Caches are kept. Re-run to continue. Nothing was promoted.")
    if a.report:
        with open(a.report, "w") as fh:
            json.dump({"corpus": corpus, "repositories": n_repos,
                       "incomplete": sorted(set(incomplete)), "rows": rows},
                      fh, indent=2)
        print(f"delta written to {a.report}")

    if a.promote:
        if incomplete:
            sys.exit("refusing to promote: some stages did not complete")
        missing = [k for k, p in staged.items() if not os.path.exists(p)]
        if skipped:
            print("note: " + ", ".join(skipped) + " were not re-run this time; "
                  "they are promoted from whatever the workdir holds")
        if missing:
            sys.exit("refusing to promote: staged output missing for "
                     + ", ".join(missing))
        for k, dst in ARTIFACTS.items():
            shutil.copyfile(staged[k], dst)
            print(f"promoted {staged[k]} -> {dst}")
        print("\nNow re-run evaluation/reproduce.py to confirm the new "
              "artifacts are reproducible, and update the numbers table.")

    sys.exit(2 if incomplete else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Multi-agent topology and the declared-versus-permitted hand-off gap.

Measures, over a corpus of real Terraform, how many AgentCore deployments place
more than one agent in one template, how many wire a hand-off between them, and
how the hand-off that is DECLARED in the platform configuration compares with the
hand-off the IAM policy PERMITS. That second number is the one the thesis turns
on: an agent configured to call one named agent while permitted to call any agent
is a confused deputy waiting for an input that names a different target.

Resumable by repository. The corpus is large and often sits on a network or FUSE
mount where a single recursive walk costs minutes, so the run is sliced: each
invocation works until --budget seconds have passed, appends one JSON line per
template directory to --cache, and exits. Running it again picks up at the next
unfinished repository. With the cache complete, the aggregate is printed and
written. Deleting the cache forces a clean re-measurement, which is what to do
after changing the extractor, because a cached row is a row produced by the code
as it was then.

Usage:
  python3 topology.py --corpus corpus_tier2 --json topology_tier2.json
  # on a slow mount, repeat until it prints COMPLETE:
  python3 topology.py --corpus corpus_tier2 --json topology_tier2.json --budget 120
"""
import argparse, collections, glob, hashlib, json, os, re, sys, warnings

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "agentpathtriage"))
import tf_to_state as T, extract_graph as X          # noqa: E402
import gap as _g                                     # noqa: E402

RUNTIME_BLOCK = re.compile(r'resource\s+"aws_bedrockagentcore_agent_runtime"\s+"')


def scan_dir(d, rel):
    """One template directory to one result row, or an error row."""
    try:
        state, _ = T.to_state(d)
        G, ix = X.build(state)
    except Exception as e:
        return {"t": rel, "err": f"{type(e).__name__}: {str(e)[:60]}"}
    agents = {n: m for n, m in ix.agents.items()
              if m["type"] == "aws_bedrockagentcore_agent_runtime"}
    ho = []
    for u, v, dd in G.edges(data=True):
        if dd.get("rel") != "handoff":
            continue
        ho.append({"from": u, "to": v, "evidence": dd.get("evidence"),
                   "permitted": bool(dd.get("permitted")),
                   "scope": dd.get("permitted_scope"), "var": dd.get("via_variable")})
    return {"t": rel, "n_agents": len(agents), "agents": sorted(agents), "handoffs": ho}


def collect(corpus, cache, budget):
    """Fill the cache one repository at a time. Returns True when the corpus is done."""
    import time
    deadline = time.time() + budget if budget else None

    done_repos = set()
    if os.path.exists(cache):
        for ln in open(cache):
            try:
                row = json.loads(ln)
            except Exception:
                continue
            if row.get("_repo_done"):
                done_repos.add(row["_repo_done"])

    repos = sorted(x for x in os.listdir(corpus)
                   if os.path.isdir(os.path.join(corpus, x)))
    todo = [r for r in repos if r not in done_repos]
    if not todo:
        return True

    out = open(cache, "a")
    for repo in todo:
        if deadline and time.time() > deadline:
            out.close()
            print(f"budget reached: {len(done_repos)}/{len(repos)} repositories cached, "
                  f"run again to continue", file=sys.stderr)
            return False
        root = os.path.join(corpus, repo)
        dirs = sorted({os.path.dirname(p)
                       for p in glob.glob(os.path.join(root, "**", "*.tf"), recursive=True)
                       if os.sep + ".terraform" + os.sep not in p})
        for d in dirs:
            if _g.is_excluded(d, corpus):
                continue
            try:
                txt = "\n".join(open(f, encoding="utf-8", errors="ignore").read()
                                for f in sorted(glob.glob(os.path.join(d, "*.tf"))))
            except Exception:
                continue
            if not RUNTIME_BLOCK.search(txt):
                continue
            row = scan_dir(d, os.path.relpath(d, corpus))
            # the content hash de-duplicates vendored copies of the same template,
            # and lives in the cache so de-duplication survives resumption
            row["h"] = hashlib.sha256(txt.encode("utf-8", "ignore")).hexdigest()
            out.write(json.dumps(row) + "\n")
        out.write(json.dumps({"_repo_done": repo}) + "\n")
        out.flush()
        done_repos.add(repo)
    out.close()
    return True


def load_rows(cache):
    """Cache to de-duplicated rows, in a deterministic order.

    Entries are sorted BEFORE de-duplication, not after. Two templates with the
    same content hash are one template seen twice, and which of the two names
    survives must not depend on the order the cache happened to be filled in.
    Sorting afterwards fixes the output order while leaving the survivor to
    insertion order, so a corpus walked in one sitting and the same corpus
    walked in two disagree on the name of every de-duplicated template. That
    is what happened on 2026-10-15: a cache seeded with the 351 repositories
    collected first kept X-GPT__mymemo-agent, while a single walk of all 1647
    kept MyMemoAI__mymemo-agent. The rows were identical; only the surviving
    name moved, which is enough to make the artifact irreproducible.

    gap.load_rows sorts first for the same reason.
    """
    entries = []
    for ln in open(cache):
        try:
            row = json.loads(ln)
        except Exception:
            continue
        if row.get("_repo_done"):
            continue
        entries.append(row)
    rows, seen = [], set()
    for row in sorted(entries, key=lambda r: r["t"]):
        h = row.pop("h", None)
        if h and h in seen:
            continue
        if h:
            seen.add(h)
        rows.append(row)
    return rows


def report(rows, out_json):
    ok = [r for r in rows if "err" not in r]
    n_t = len(ok)
    n_a = sum(r["n_agents"] for r in ok)
    multi = [r for r in ok if r["n_agents"] > 1]
    ev = collections.Counter(h["evidence"] for r in ok for h in r["handoffs"])
    scopes = collections.Counter(h["scope"] for r in ok for h in r["handoffs"]
                                 if h["permitted"])
    with_ho = [r for r in ok if r["handoffs"]]
    declared = [r for r in ok
                if any(h["evidence"].startswith("declared") for h in r["handoffs"])]

    gap = []
    for r in ok:
        per_agent = collections.defaultdict(lambda: {"declared": set(), "permitted": set()})
        for h in r["handoffs"]:
            if h["evidence"] == "declared_resolved":
                per_agent[h["from"]]["declared"].add(h["to"])
            if h["permitted"]:
                per_agent[h["from"]]["permitted"].add((h["to"], h["scope"]))
        for a, s in per_agent.items():
            if s["declared"] and any(sc == "any" for _, sc in s["permitted"]):
                gap.append((r["t"], a, len(s["declared"])))

    pct = (lambda k: f"  ({100 * k / n_t:.1f}%)") if n_t else (lambda k: "")
    print(f"templates with an AgentCore runtime : {n_t}")
    print(f"agent runtimes                      : {n_a}")
    print(f"templates with 2 or more agents     : {len(multi)}{pct(len(multi))}")
    print(f"templates with any hand-off edge    : {len(with_ho)}{pct(len(with_ho))}")
    print(f"templates with a declared hand-off  : {len(declared)}")
    print(f"parse failures                      : {len(rows) - len(ok)}")
    print("\nhand-off edges by evidence:")
    for k, v in ev.most_common():
        print(f"   {k:22s} {v}")
    print("\npermitted hand-off scope:")
    for k, v in scopes.most_common():
        print(f"   {str(k):22s} {v}")
    print(f"\nagents configured to call a specific agent but permitted to call any: {len(gap)}")
    for t, a, n in gap:
        print(f"   {t[:60]:62s} {a} declared={n} permitted=any")
    print("\nall declared hand-offs:")
    for r in ok:
        for h in r["handoffs"]:
            if h["evidence"].startswith("declared"):
                print(f"   {r['t'][:56]:58s} {h['from']} -> {h['to']}  "
                      f"[{h['evidence']}, var={h['var']}]")
    if rows and len(ok) != len(rows):
        print("\nparse failures, one by one:")
        for r in rows:
            if "err" in r:
                print(f"   {r['t'][:70]:72s} {r['err']}")
    json.dump(rows, open(out_json, "w"), indent=1)
    print(f"\nwritten: {out_json}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus_tier2")
    ap.add_argument("--json", default="topology.json")
    ap.add_argument("--cache", help="resumable per-repository cache "
                                    "(default: <json>.cache.jsonl)")
    ap.add_argument("--budget", type=float, default=0,
                    help="stop after this many seconds and exit for resumption; "
                         "0 runs to completion")
    a = ap.parse_args()
    cache = a.cache or a.json + ".cache.jsonl"

    complete = collect(a.corpus, cache, a.budget)
    if not complete:
        print("INCOMPLETE")
        return 1
    report(load_rows(cache), a.json)
    print("COMPLETE")
    return 0


if __name__ == "__main__":
    sys.exit(main())

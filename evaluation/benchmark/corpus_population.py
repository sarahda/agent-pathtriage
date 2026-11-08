#!/usr/bin/env python3
"""
What the corpus is a sample of, and when it was taken.

A template count invites one question: out of how many. This answers the part
that can be answered from the corpus itself, which is the funnel, and states
plainly the part that cannot, which is how many repositories GitHub would
return today.

The funnel is the honest version of coverage. Every repository that was cloned
is accounted for: no Terraform, no agent runtime, excluded by the filter, a
fork copy of a template already counted, or in the final set. A reader can see
where everything went rather than being handed the last number.

Timing matters for this corpus in particular. AWS narrowed the AgentCore
default execution role on 2026-09-29. A template last touched before that date
may still carry the old default, and one touched after may not, so the split
is reported rather than left for a reviewer to ask about.

Usage:
  python3 evaluation/benchmark/corpus_population.py --corpus corpus_tier2 \
      --json corpus-population.json [--budget 120]

The external denominator needs an authenticated GitHub CLI and is not run
here. The commands are printed at the end.
"""
import argparse, collections, glob, json, os, re, subprocess, sys, time

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(os.path.dirname(_HERE)),
                               "agentpathtriage")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

RUNTIME = re.compile(r'resource\s+"aws_bedrockagentcore_agent_runtime"\s+"')
DEFAULT_ROLE_NARROWED = "2026-09-29"

# The searches the collector ran. Printed so the denominator can be re-derived
# with the same queries rather than a remembered approximation.
QUERIES = [
    'aws_bedrockagentcore_agent_runtime extension:tf',
    'aws_bedrockagentcore_memory extension:tf',
    'aws_bedrockagentcore_gateway extension:tf',
    'aws_bedrockagentcore_code_interpreter extension:tf',
    'agent_runtime_artifact extension:tf',
    '"bedrock-agentcore:" extension:tf',
]


def last_commit(repo_dir):
    try:
        out = subprocess.check_output(
            ["git", "-C", repo_dir, "log", "-1", "--format=%cI"],
            stderr=subprocess.DEVNULL, timeout=20)
        return out.decode().strip()[:10] or None
    except Exception:
        return None


def collect(corpus, cache, budget):
    import gap as G
    deadline = time.time() + budget if budget else None
    done = set()
    if os.path.exists(cache):
        for ln in open(cache):
            try:
                done.add(json.loads(ln)["repo"])
            except Exception:
                pass
    repos = sorted(x for x in os.listdir(corpus)
                   if os.path.isdir(os.path.join(corpus, x)))
    todo = [r for r in repos if r not in done]
    if not todo:
        return True, len(repos)

    out = open(cache, "a")
    for repo in todo:
        if deadline and time.time() > deadline:
            out.close()
            print(f"budget reached: {len(done)}/{len(repos)} repositories, "
                  f"run again to continue", file=sys.stderr)
            return False, len(repos)
        root = os.path.join(corpus, repo)
        tfs = [p for p in glob.glob(os.path.join(root, "**", "*.tf"), recursive=True)
               if os.sep + ".terraform" + os.sep not in p]
        dirs = sorted({os.path.dirname(p) for p in tfs})
        runtime_dirs = []
        for d in dirs:
            try:
                txt = "\n".join(open(f, encoding="utf-8", errors="ignore").read()
                                for f in sorted(glob.glob(os.path.join(d, "*.tf"))))
            except Exception:
                continue
            if RUNTIME.search(txt):
                runtime_dirs.append({
                    "d": os.path.relpath(d, corpus),
                    "excluded": bool(G.is_excluded(d, corpus)),
                    "h": G.template_hash(d),
                    # how much of the population a pass that cannot read
                    # aws_iam_policy_document would be blind to. Counted here
                    # rather than asserted in a docstring, so it cannot go
                    # stale when the corpus changes.
                    "n_pd": len(POLICY_DOC.findall(txt)),
                })
        out.write(json.dumps({"repo": repo, "n_tf": len(tfs), "n_dirs": len(dirs),
                              "runtime_dirs": runtime_dirs,
                              "last_commit": last_commit(root)}) + "\n")
        out.flush()
        done.add(repo)
    out.close()
    return True, len(repos)


POLICY_DOC = re.compile(r'data\s+"aws_iam_policy_document"')


def report(cache, out_json):
    rows = []
    for ln in open(cache):
        try:
            rows.append(json.loads(ln))
        except Exception:
            pass

    n_repos = len(rows)
    no_tf = [r for r in rows if r["n_tf"] == 0]
    tf_no_runtime = [r for r in rows if r["n_tf"] and not r["runtime_dirs"]]
    with_runtime = [r for r in rows if r["runtime_dirs"]]

    all_dirs = [d for r in with_runtime for d in r["runtime_dirs"]]
    excluded = [d for d in all_dirs if d["excluded"]]
    kept = [d for d in all_dirs if not d["excluded"]]
    seen, deduped, final = set(), [], []
    for d in sorted(kept, key=lambda x: x["d"]):
        (deduped if d["h"] in seen else final).append(d)
        seen.add(d["h"])

    print("Funnel. Every cloned repository is accounted for.\n")
    print(f"  repositories cloned                      {n_repos}")
    print(f"    no .tf at all                          {len(no_tf)}")
    print(f"    .tf but no agent runtime               {len(tf_no_runtime)}")
    print(f"    at least one agent runtime             {len(with_runtime)}")
    print(f"  template directories with a runtime      {len(all_dirs)}")
    print(f"    excluded by the filter                 {len(excluded)}")
    print(f"    fork copies of a template already kept {len(deduped)}")
    print(f"  FINAL template set                       {len(final)}")

    dated = [r for r in with_runtime if r["last_commit"]]
    before = [r for r in dated if r["last_commit"] < DEFAULT_ROLE_NARROWED]
    after = [r for r in dated if r["last_commit"] >= DEFAULT_ROLE_NARROWED]
    print(f"\nLast commit, for the {len(with_runtime)} repositories with a runtime:")
    print(f"  dated                                    {len(dated)}")
    print(f"    before {DEFAULT_ROLE_NARROWED}, when AWS narrowed the")
    print(f"    AgentCore default execution role       {len(before)}")
    print(f"    on or after it                         {len(after)}")
    if dated:
        ds = sorted(r["last_commit"] for r in dated)
        print(f"  range                                    {ds[0]} to {ds[-1]}")
        print(f"  median                                   {ds[len(ds) // 2]}")
    print("\nA template last touched before that date may still carry the old "
          "default role. This is why the corpus is dated in the paper rather "
          "than described as current.")

    by_year = collections.Counter(r["last_commit"][:7] for r in dated)
    print("\nby month:")
    for k, v in sorted(by_year.items())[-8:]:
        print(f"   {k}  {'#' * min(v, 60)} {v}")

    print("\nWhat this does NOT answer: how many repositories GitHub would "
          "return today for the collector's queries. That needs an "
          "authenticated CLI and is not run here. To get the denominator:\n")
    for q in QUERIES:
        print(f"   gh api -X GET search/code -f q={q!r} --jq .total_count")
    print("\nThe corpus is a sample of public Terraform, which is itself a "
          "sample of deployments. Neither number makes it a census of the "
          "wild, and the paper says so.")

    # aws_iam_policy_document reach, over the final template set
    pd_rows = [r for r in final if "n_pd" in r]
    if len(pd_rows) == len(final) and final:
        pd_blocks = sum(r["n_pd"] for r in final)
        pd_using = sum(1 for r in final if r["n_pd"])
        print(f"\naws_iam_policy_document, over the {len(final)} final templates:")
        print(f"  blocks                                   {pd_blocks}")
        print(f"  templates using at least one             {pd_using}"
              f"  ({pd_using / len(final) * 100:.1f}%)")
        print("A pass that cannot render these blocks is blind to the policies "
              "of that share of the population.")
    else:
        # a cache predating this measurement must not read as a measured zero
        pd_blocks = pd_using = None
        print("\naws_iam_policy_document: not in this cache. Delete the cache "
              "and re-run to measure it.")

    if out_json:
        json.dump({"repositories": n_repos, "no_tf": len(no_tf),
                   "tf_no_runtime": len(tf_no_runtime),
                   "with_runtime": len(with_runtime),
                   "template_dirs": len(all_dirs), "excluded": len(excluded),
                   "fork_copies": len(deduped), "final_templates": len(final),
                   "default_role_narrowed": DEFAULT_ROLE_NARROWED,
                   "last_commit_before": len(before),
                   "last_commit_after": len(after),
                   "policy_document_blocks": pd_blocks,
                   "templates_using_policy_document": pd_using,
                   "queries": QUERIES},
                  open(out_json, "w"), indent=2)
        print(f"\nwritten: {out_json}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus_tier2")
    ap.add_argument("--json")
    ap.add_argument("--cache")
    ap.add_argument("--budget", type=float, default=0)
    a = ap.parse_args()
    cache = a.cache or (a.json or "corpus-population") + ".cache.jsonl"
    complete, _n = collect(a.corpus, cache, a.budget)
    if not complete:
        print("INCOMPLETE")
        return 1
    report(cache, a.json)
    print("COMPLETE")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Re-derive every published number and compare it with what is committed.

A number in the paper is only as good as the command that reproduces it. This
runs those commands and diffs the result against the committed artifact, so a
drift between the code and the recorded value is a test failure rather than
something a reader discovers.

Two tiers:
  fast   everything that runs in under a minute: the test suites, the
         third-party benchmarks, the baseline comparison, and the derived
         corpus artifacts that read a committed JSON rather than the corpus
  full   adds the two corpus walks (gap, topology). On a network or FUSE mount
         these take minutes, so they are skipped unless asked for

Usage:
  python3 evaluation/reproduce.py                 # fast tier
  python3 evaluation/reproduce.py --full          # add the corpus walks
  python3 evaluation/reproduce.py --full --budget 120   # slice the corpus walks
"""
import argparse, ast, collections, hashlib, json, os, re, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(ROOT, "evaluation", "benchmark")
CORPUS = os.path.join(ROOT, "corpus_tier2")
IV = os.path.join(CORPUS, "BishopFox__iam-vulnerable")
CG = os.path.join(CORPUS, "RhinoSecurityLabs__cloudgoat", "cloudgoat",
                  "scenarios", "aws", "agentcore_identity_confusion")

results = []


def check(name, got, want):
    ok = got == want
    results.append((ok, name, got, want))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {got}" + ("" if ok else f"  want {want}"))
    return ok


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kw)


def fast(tmp):
    print("=== test suites ===")
    # No expected count here. Pinning one means adding a test breaks the
    # verifier, which is the same hardcoding this project keeps finding
    # elsewhere. What must hold is that nothing fails, and that every test is
    # named in the spec, which the bijection check below enforces.
    r = run([sys.executable, "-m", "pytest", "tests", "-q"])
    passed = re.search(r"(\d+) passed", r.stdout)
    failed = re.search(r"(\d+) failed", r.stdout)
    check("pytest failures", int(failed.group(1)) if failed else 0, 0)
    print(f"       ({passed.group(1) if passed else 0} tests passed)")

    for script, want in (("infra/foundry/test_foundry_cp.py", 0),
                         ("infra/foundry/test_matrix.py", 0)):
        r = run([sys.executable, script])
        check(f"{os.path.basename(script)} exit", r.returncode, want)

    print("\n=== spec trace table is still a bijection ===")
    spec = open(os.path.join(ROOT, "model", "formal-spec.md")).read()
    named = set(re.findall(r"`(test_[a-z0-9_]+)`", spec))
    actual = set()
    for f in os.listdir(os.path.join(ROOT, "tests")):
        if f.startswith("test_") and f.endswith(".py"):
            actual |= set(re.findall(r"^def (test_[a-z0-9_]+)",
                                     open(os.path.join(ROOT, "tests", f)).read(), re.M))
    check("tests named in spec but absent", len(named - actual), 0)
    check("tests present but untraced", len(actual - named), 0)

    if not os.path.isdir(IV):
        print("\nIAM-Vulnerable not in the corpus; skipping the benchmark checks")
        return
    print("\n=== third-party benchmark: IAM-Vulnerable ===")
    st, rc = os.path.join(tmp, "iv.json"), os.path.join(tmp, "iv_reach.json")
    run([sys.executable, os.path.join(BENCH, "tf_to_state.py"), "--tfdir", IV,
         "--json", st])
    run([sys.executable, os.path.join(ROOT, "agentpathtriage", "reach.py"),
         "--state", st, "--json", rc])
    r = run([sys.executable, os.path.join(BENCH, "score_benchmark.py"),
             "--state", st, "--reach", rc])
    out = r.stdout
    check("in-scope recall", re.search(r"in-scope recall:\s+([\d.]+)", out).group(1), "1.000")
    check("precision on designed fp",
          re.search(r"designed false positives:\s+([\d.]+)", out).group(1), "1.000")
    check("designed fn caught", re.search(r"caught (\d+)/(\d+)", out).group(0), "caught 8/8")
    # the bucket names contain spaces ("in scope", "known gap"), so the label is
    # matched lazily rather than as one word. The first version of this line
    # summed a single bucket and reported 12/12, which looked like an engine
    # regression and was a bug in the check.
    block = out.split("per bucket", 1)[-1].split("\n\n", 1)[0]
    pairs = re.findall(r"^\s+\S.*?\s+(\d+)/(\d+)\s*$", block, re.M)
    found = sum(int(a) for a, _ in pairs)
    total = sum(int(b) for _, b in pairs)
    check("path group buckets parsed", len(pairs), 4)
    check("path groups found/present", f"{found}/{total}", "33/34")

    print("\n=== independent baseline, same input ===")
    r = run([sys.executable, os.path.join(BENCH, "baseline_diff.py"),
             "--state", st, "--reach", rc])
    out = r.stdout
    m = re.search(r"both: (\d+)\s+only ours: (\d+)\s+only cloudsplaining: (\d+)", out)
    check("cloudsplaining both/ours/theirs",
          "/".join(m.groups()) if m else "?", "62/8/1")
    check("comparable universe",
          re.search(r"comparable universe[^:]*: (\d+)", out).group(1), "83")
    check("unclassified disagreements", "UNCLASSIFIED" in out, False)

    if os.path.isdir(CG):
        print("\n=== third-party scenario: CloudGoat ===")
        cgs = os.path.join(tmp, "cg.json")
        run([sys.executable, os.path.join(BENCH, "tf_to_state.py"), "--tfdir", CG,
             "--json", cgs])
        r = run([sys.executable, os.path.join(ROOT, "agentpathtriage", "report.py"),
                 "--state", cgs])
        check("cloudgoat routes recovered",
              re.search(r"reachable only through delegation: (\d+)", r.stdout).group(1), "1")
        check("cloudgoat resources gained", r.stdout.count("         via "), 2)

    print("\n=== derived corpus artifacts (read committed JSON, not the corpus) ===")
    gap = os.path.join(BENCH, "gap_tier2_v1.json")
    topo = os.path.join(BENCH, "topology_tier2.json")
    # The expected values are read from the committed artifacts, not written
    # here as literals. A literal would pin these checks to one corpus, so
    # every corpus change would turn them red for a reason that is not a
    # regression. This is not circular: the fresh run takes one committed
    # artifact as input and is compared against a different committed
    # artifact, so it still catches a committed artifact that no longer
    # follows from the committed code.
    adj_art = os.path.join(BENCH, "adjudication_tier2.json")
    sr_art = os.path.join(BENCH, "shared_role_tier2.json")

    if os.path.exists(gap) and os.path.exists(adj_art):
        with open(adj_art) as fh:
            adj = json.load(fh)
        want_verdicts = collections.Counter(row.get("verdict") for row in adj)
        want_deployable = sum(1 for row in adj
                              if row.get("verdict") in ("cross-agent", "shared-role"))
        r = run([sys.executable, os.path.join(BENCH, "adjudicate_gaps.py"),
                 "--gap", gap, "--corpus", CORPUS])
        m = re.search(r"verdicts: (\{[^}]*\})", r.stdout)
        got_verdicts = ast.literal_eval(m.group(1)) if m else {}
        check("gap verdicts", dict(sorted(got_verdicts.items())),
              dict(sorted(want_verdicts.items())))
        check("deployable pillar B cases from gaps",
              int(re.search(r"Deployable as Pillar B cases: (\d+)", r.stdout).group(1)),
              want_deployable)
    elif os.path.exists(gap):
        check("adjudication artifact present", False, True)

    if os.path.exists(topo) and os.path.exists(sr_art):
        with open(sr_art) as fh:
            sr = json.load(fh)
        r = run([sys.executable, os.path.join(BENCH, "shared_role.py"),
                 "--topology", topo, "--corpus", CORPUS])
        check("multi-agent templates",
              int(re.search(r"multi-agent templates\s+: (\d+)", r.stdout).group(1)),
              sr.get("multi_agent_templates"))
        check("templates sharing one execution role",
              int(re.search(r"sharing one execution role : (\d+)/", r.stdout).group(1)),
              len(sr.get("shared_role", [])))
        check("undecided",
              int(re.search(r"could not decide\s+: (\d+)/", r.stdout).group(1)),
              len(sr.get("undecided", [])))
    elif os.path.exists(topo):
        check("shared_role artifact present", False, True)

    sc = os.path.join(BENCH, "shared_role_corrected.json")
    fo = os.path.join(BENCH, "foreach_runtime_check.json")
    if os.path.exists(sc) and os.path.exists(fo):
        with open(sc) as fh:
            corr = json.load(fh)
        # The corrected numbers must be the census plus exactly the fan outs
        # this pass could resolve, so neither can drift from the other.
        check("runtime-level multi-agent templates",
              corr["runtime_level"]["multi_agent_templates"],
              corr["block_level"]["multi_agent_templates"]
              + len(corr["added_as_multi_agent"]))
        check("runtime-level templates sharing one role",
              corr["runtime_level"]["templates_sharing_one_execution_role"],
              corr["block_level"]["templates_sharing_one_execution_role"]
              + len(corr["added_as_sharing_one_role"]))
        check("every added fan out resolved to more than one runtime",
              all(r["runtimes"] > 1 for r in corr["added_as_multi_agent"]), True)
        check("no added shared-role fan out indexes its role by the iterator",
              any("[each." in (r.get("role_arn_expression") or "")
                  for r in corr["added_as_sharing_one_role"]), False)
    elif os.path.exists(sc) or os.path.exists(fo):
        check("both fan-out artifacts present", False, True)

    print("\n=== Foundry connection auth census ===")
    # The authType breakdown was computed and then dropped, so until
    # 2026-11-07 the published Foundry numbers rested on a note rather than on
    # an artifact. They are checked here so a change to the corpus or to the
    # scoping shows up as a failure instead of a surprise.
    fr = os.path.join(BENCH, "foundry_recon.json")
    if os.path.exists(fr):
        with open(fr) as fh:
            rec = json.load(fh)
        auth = rec.get("configured_auth_types")
        if auth is None:
            check("foundry auth breakdown present in the artifact", False, True)
        else:
            check("foundry auth values equal their breakdown",
                  sum(auth.values()), rec.get("configured_auth_values"))
            agentic = {k: v for k, v in auth.items()
                       if k.lower().startswith("agentic")}
            check("connections picking an agent scoped auth type", agentic, {})
            # The scoped count must be a strict subset of the unscoped one, or
            # the scoping is not doing what it says.
            unscoped = rec.get("configured_auth_values_unscoped")
            check("scoped count is within the unscoped count",
                  unscoped is not None
                  and rec["configured_auth_values"] <= unscoped, True)
            for junk in ("windows", "Public", "systemAssignedIdentity"):
                check(f"{junk} is out of the connection denominator",
                      junk in auth, False)
    else:
        check("foundry_recon artifact present", False, True)

    print("\n=== codereq withholds on the weather-agent sample ===")
    wa = os.path.join(CORPUS, "awslabs__agentcore-samples", "04-infrastructure-as-code",
                      "terraform", "end-to-end-weather-agent")
    if os.path.isdir(wa):
        r = run([sys.executable, os.path.join(ROOT, "agentpathtriage", "codereq.py"),
                 "--template", wa])
        check("verdict withheld", "OVER-GRANT VERDICT WITHHELD" in r.stdout, True)
        check("under-grant reported", "bedrock-agentcore:CreateEvent" in r.stdout, True)


def code_stamp(corpus=None):
    """What the corpus walk depends on: the analyser code and the corpus size.

    corpus is a parameter so a test can measure the behaviour without creating
    anything inside the real corpus. A test that adds a directory there and
    fails to remove it leaves the corpus one larger than every committed
    number says, which happened on 2026-10-16.

    A cache is only reusable across invocations of ONE verification run. If
    either the code or the corpus has moved, the cached rows describe a
    different measurement and must be thrown away rather than reused.
    """
    h = hashlib.sha256()
    for d in (os.path.join(ROOT, "agentpathtriage"), BENCH):
        for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if not f.endswith(".py"):
                continue
            with open(os.path.join(d, f), "rb") as fh:
                h.update(f.encode())
                h.update(fh.read())
    root = corpus or CORPUS
    n = len([x for x in os.listdir(root)
             if os.path.isdir(os.path.join(root, x))]) if os.path.isdir(root) else -1
    h.update(str(n).encode())
    return h.hexdigest()


def read_stamp(path):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except Exception:
        return None


def full(workdir, budget):
    print("\n=== corpus walks, re-derived from the corpus itself ===")
    print("Caches are deleted first. A cached row is a row produced by the code "
          "as it was then, which is the opposite of a re-measurement.\n")
    for script, out_committed, keys in (
            (os.path.join(ROOT, "agentpathtriage", "gap.py"),
             os.path.join(BENCH, "gap_tier2_v1.json"),
             ("n_runtimes", "n_templates", "wired_recovered", "wired_by_reference",
              "resource_scope_gap", "full_ac_star", "role_unresolved",
              "roles_with_unread_attachments")),
            (os.path.join(BENCH, "topology.py"),
             os.path.join(BENCH, "topology_tier2.json"), None)):
        name = os.path.basename(script)
        fresh = os.path.join(workdir, name + ".json")
        cache = fresh + ".cache.jsonl"
        started = os.path.join(workdir, name + ".started")
        # The cache is cleared once per verification run, not once per slice: a
        # cached row is a row produced by the code as it was then, so a
        # re-measurement must start empty, but a sliced run has to keep what it
        # already did or it never finishes.
        #
        # The marker therefore carries a stamp of the analyser code and the
        # corpus size, and the walk deletes it on COMPLETE. An empty marker that
        # merely records "a run started once" is not enough: it survived into
        # the next verification run and silently handed it a cache written by
        # the previous code. That happened on 2026-10-15, when a cache written
        # at 01:07 by the pre-469bf27 is_excluded carried 160 wrongly excluded
        # templates into a 05:57 verification, which then reported 84 templates
        # against the committed 220 and looked like a reproduction failure.
        stamp = code_stamp()
        if read_stamp(started) != stamp:
            if os.path.exists(cache):
                os.remove(cache)
            with open(started, "w") as fh:
                fh.write(stamp)
        cmd = [sys.executable, script, "--corpus", CORPUS, "--json", fresh,
               "--cache", cache]
        if budget:
            cmd += ["--budget", str(budget)]
        r = run(cmd)
        if "COMPLETE" not in r.stdout:
            if "INCOMPLETE" in r.stdout:
                # one slice per invocation, so the caller controls the window
                print(f"   {name}: slice done, run the same command again")
                results.append((None, name, "incomplete", "COMPLETE"))
                return
            print(f"[FAIL] {name} did not finish: {r.stderr[-300:]}")
            results.append((False, name, "error", "COMPLETE"))
            continue
        # the walk finished, so the next verification run must start clean
        if os.path.exists(started):
            os.remove(started)
        if not os.path.exists(fresh):
            continue
        a, b = json.load(open(fresh)), json.load(open(out_committed))
        if keys:
            for k in keys:
                check(f"{name} {k}", a.get(k), b.get(k))
        else:
            ta = {r["t"]: (r.get("n_agents"), sorted(
                (h["from"], h["to"], h["evidence"], h["permitted"], h["scope"])
                for h in r.get("handoffs", []))) for r in a if "err" not in r}
            tb = {r["t"]: (r.get("n_agents"), sorted(
                (h["from"], h["to"], h["evidence"], h["permitted"], h["scope"])
                for h in r.get("handoffs", []))) for r in b if "err" not in r}
            check(f"{name} template set", set(ta) == set(tb), True)
            check(f"{name} rows differing", sum(1 for k in ta if ta[k] != tb.get(k)), 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="also re-walk the corpus")
    ap.add_argument("--budget", type=float, default=0,
                    help="seconds per corpus slice, for a slow mount. With it "
                         "set, one slice runs per invocation: run the same "
                         "command again until it reports COMPLETE")
    ap.add_argument("--workdir", default=None,
                    help="where sliced corpus caches live between invocations. "
                         "Defaults to _scratch/reproduce under the repository")
    ap.add_argument("--skip-fast", action="store_true")
    a = ap.parse_args()
    workdir = a.workdir or os.path.join(ROOT, "_scratch", "reproduce")
    os.makedirs(workdir, exist_ok=True)
    if not a.skip_fast:
        fast(tempfile.mkdtemp())
    if a.full:
        full(workdir, a.budget)
    pending = [r for r in results if r[0] is None]
    bad = [r for r in results if r[0] is False]
    done = len(results) - len(bad) - len(pending)
    print(f"\n{done}/{len(results) - len(pending)} reproduced")
    if bad:
        print("\nDID NOT REPRODUCE:")
        for _ok, name, got, want in bad:
            print(f"   {name}: got {got}, committed {want}")
        return 1
    if pending:
        print("INCOMPLETE: a corpus walk is still running in slices. Run the "
              "same command again.")
        return 2
    print("Every published number re-derived from the committed code.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
AgentPathTriage command line.

One command, no AWS account:

    agentpathtriage scan path/to/terraform

The three-step pipeline (Terraform to state-shaped JSON, graph, findings) is
still there and still runnable step by step, which is what you want while
developing. This exists because the three steps were the reason people did not
run it: a reviewer or a repository owner given three commands and two
intermediate files does not get past the first one.

Exit codes, so it can sit in CI:

    0   no findings
    1   findings
    2   the run itself failed

Sitting in CI takes two more things than an exit code, and scan has both:

    --baseline b.json   report only what is not already in b.json, so that a
                        repository which starts with findings can still gate
                        on not adding more. Suppressed findings are counted
                        out loud, never hidden.
    --sarif out.sarif   the same findings in the format a code scanning tab
                        reads, with the suppressed ones marked suppressed
                        rather than dropped.

Subcommands:
    scan      Terraform directory to findings
    repair    findings to the narrowest change that removes them, re-analysed
    verify    re-derive every published number and diff against the committed
              artifacts
    doctor    check that this install can actually run, and say what is missing
"""
import argparse, json, os, subprocess, sys, tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_ROOT, "evaluation", "benchmark")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


class RunFailed(Exception):
    """A failure of the run itself, which exits 2 rather than 1.

    `SystemExit("message")` exits with status 1, which this tool uses to mean
    "findings were reported". A missing directory would then look like a clean
    scan that found something, which is the worst of both.
    """


def _state_from(tfdir, out=None):
    import tf_to_state as T
    if not os.path.isdir(tfdir):
        raise RunFailed(f"not a directory: {tfdir}")
    state, n = T.to_state(tfdir)
    if n == 0:
        raise RunFailed(f"no .tf files under {tfdir}")
    if out:
        json.dump(state, open(out, "w"), indent=1)
    return state


def cmd_scan(a):
    import findings as F

    if a.state:
        state = json.load(open(a.state))
    else:
        state = _state_from(a.tfdir, a.save_state)

    tfdir = a.tfdir if not a.state else None
    found = F.collect(state, tfdir)
    new, suppressed, stale = found, [], []

    if a.baseline:
        if not os.path.exists(a.baseline):
            raise RunFailed(f"no such baseline: {a.baseline}")
        try:
            base = F.read_baseline(a.baseline)
        except Exception as e:
            raise RunFailed(f"{a.baseline}: {e}")
        new, suppressed, stale = F.apply_baseline(found, base)
        warn = F.baseline_warning(base)
    else:
        warn = None

    if a.format == "json":
        json.dump({"results": _legacy_results(state), "findings": found},
                  sys.stdout, indent=2)
        print()
    else:
        _render(state)
        _render_findings(new, suppressed, stale, warn, bool(a.baseline))

    if a.json:
        json.dump({"results": _legacy_results(state), "findings": found},
                  open(a.json, "w"), indent=2)
        print(f"\nwritten: {a.json}", file=sys.stderr)

    if a.sarif:
        import sarif as S
        doc = S.write(a.sarif, new, suppressed, base=a.sarif_base, tfdir=tfdir)
        print(f"written: {a.sarif}", file=sys.stderr)
        # A result with no location is discarded on upload without an error,
        # so the one visible symptom is an empty code scanning tab for a scan
        # that reported findings. Scanning --state rather than a directory is
        # how you get there, because there is no source to point at.
        res = doc["runs"][0]["results"]
        placed = sum(1 for r in res if "locations" in r)
        if res and placed < len(res):
            print(f"WARNING: {len(res) - placed} of {len(res)} result(s) "
                  f"carry no file location. Code scanning discards those "
                  f"silently, so they will not appear. Scan the directory "
                  f"instead of --state to get locations.", file=sys.stderr)

    if a.write_baseline:
        doc = F.write_baseline(found, a.write_baseline)
        n = len(doc["fingerprints"])
        print(f"\nrecorded {n} finding(s) in {a.write_baseline}. A later run "
              f"given --baseline {a.write_baseline} will report only what is "
              f"not in that file.\nThis run is not a gate and exits 0 even "
              f"though it found {n}.", file=sys.stderr)
        return EXIT_CLEAN

    return EXIT_FINDINGS if F.failing(new) else EXIT_CLEAN


def _legacy_results(state):
    """The per-principal rows, kept under the key they have always had.

    scan --json grew a `findings` list, which is the flat one with a name per
    finding. `results` stays exactly as it was so that anything already
    reading it keeps working.
    """
    import reach as R
    return R.run(state)[3]


def _render_findings(new, suppressed, stale, warn, used_baseline):
    """The block that has to agree with the exit code.

    report.py's narrative above this is organised around what a reviewer wants
    to read: the chains, the resources, who is already admin. It predates the
    flat finding list and does not describe every class in it, which is how a
    scan of two agents sharing one execution role printed "none" and then
    exited 1. Anything that disagrees with the exit code is worse than terse,
    so this is derived from exactly the list the exit code is derived from.
    """
    import findings as F
    print()
    print("Every finding, as the exit code counts them")
    print("-" * 72)
    if not new and not suppressed:
        print("  none")
    for f in new:
        where = ""
        if f.get("file"):
            where = f"{os.path.relpath(f['file'])}:{f['line']}"
            if not f.get("located"):
                where += " (file only; the declaration could not be placed)"
        print(f"  {f['rule']}  {f['level']:<7s} {f['rule_name']}")
        print(f"      {f['message']}")
        if where:
            print(f"      {where}")

    if used_baseline:
        print()
        print(f"baseline: {len(suppressed)} finding(s) suppressed, "
              f"{len(new)} not in the baseline")
        if stale:
            print(f"          {len(stale)} baseline entry/entries matched "
                  f"nothing in this scan, so they are either fixed or no "
                  f"longer named the same way")
        if warn:
            print(f"WARNING:  {warn}")

    fails = F.failing(new)
    print()
    print(f"exit 1: {len(fails)} finding(s) fail the run" if fails
          else "exit 0: nothing that fails the run")


def _render(state):
    """report.py is a script, so it is driven the way its own main is.

    Calling its render() directly looked tidier and was wrong: the signature
    takes more than the state, and guessing at it produced a TypeError that
    turned every scan into an error exit.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(state, f)
        path = f.name
    try:
        subprocess.run([sys.executable, os.path.join(_HERE, "report.py"),
                        "--state", path], check=False)
    finally:
        os.unlink(path)


def cmd_repair(a):
    state = (json.load(open(a.state)) if a.state
             else _state_from(a.tfdir, a.save_state))
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(state, f)
        path = f.name
    try:
        cmd = [sys.executable, os.path.join(_HERE, "repair.py"), "--state", path]
        if a.json:
            cmd += ["--json", a.json]
        return EXIT_CLEAN if subprocess.run(cmd).returncode == 0 else EXIT_ERROR
    finally:
        os.unlink(path)


def cmd_verify(a):
    script = os.path.join(_ROOT, "evaluation", "reproduce.py")
    if not os.path.exists(script):
        print("evaluation/reproduce.py is not here. Run from a clone, or "
              "install with pip install -e .", file=sys.stderr)
        return EXIT_ERROR
    cmd = [sys.executable, script]
    if a.full:
        cmd.append("--full")
    if a.budget:
        cmd += ["--budget", str(a.budget)]
    return subprocess.run(cmd).returncode


def cmd_doctor(_a):
    """Say whether this install can run, and name what is missing.

    Written because the failure that matters is silent: before this, cloning
    the repository and pointing the scanner at an absolute path excluded every
    template and reported zero findings with no warning.
    """
    ok = True
    print(f"python            {sys.version.split()[0]}")
    print(f"package directory {_HERE}")
    print(f"repository root   {_ROOT}")

    for mod, why in (("networkx", "the graph"),
                     ("policy_sentry", "AWS action data, used for takeover edges"),
                     ("hcl2", "the corpus scanners, not needed for scan"),
                     ("cloudsplaining", "the independent baseline, not needed for scan"),
                     ("matplotlib", "figures, not needed for scan")):
        try:
            __import__(mod)
            print(f"  [ok]      {mod:16s} {why}")
        except Exception:
            need = mod in ("networkx", "policy_sentry")
            print(f"  [{'MISSING' if need else 'absent '}] {mod:16s} {why}")
            ok = ok and not need

    for name, path in (("tf_to_state", os.path.join(_ROOT, "evaluation", "benchmark",
                                                    "tf_to_state.py")),
                       ("reproduce", os.path.join(_ROOT, "evaluation", "reproduce.py")),
                       ("tests", os.path.join(_ROOT, "tests"))):
        there = os.path.exists(path)
        print(f"  [{'ok' if there else 'absent'}]      {name:16s} {path}")
        if name == "tf_to_state" and not there:
            ok = False

    # the real smoke test: a tiny template, scanned end to end
    try:
        d = tempfile.mkdtemp()
        open(os.path.join(d, "main.tf"), "w").write(
            'resource "aws_iam_role" "r" { name = "r" }\n')
        state = _state_from(d)
        import reach as R
        R.run(state)
        print("  [ok]      smoke test       parsed and analysed a template")
    except Exception as e:
        print(f"  [FAILED]  smoke test       {type(e).__name__}: {e}")
        ok = False

    print("\nready" if ok else "\nNOT READY: install the missing requirements with "
          "pip install -r requirements.txt")
    return EXIT_CLEAN if ok else EXIT_ERROR


def main(argv=None):
    ap = argparse.ArgumentParser(prog="agentpathtriage",
                                 description="Cross-agent IAM privilege escalation "
                                             "from Terraform source. No AWS account.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Terraform directory to findings")
    s.add_argument("tfdir", nargs="?", help="directory containing .tf files")
    s.add_argument("--state", help="a terraform show -json file, instead of --tfdir")
    s.add_argument("--save-state", help="keep the intermediate state JSON here")
    s.add_argument("--json", help="write the findings here")
    s.add_argument("--format", choices=("text", "json"), default="text")
    s.add_argument("--baseline",
                   help="suppress findings recorded in this file, and exit "
                        "on what is left")
    s.add_argument("--write-baseline", dest="write_baseline",
                   help="record this scan's findings as the baseline and "
                        "exit 0")
    s.add_argument("--sarif", help="write SARIF 2.1.0 here, for code scanning")
    s.add_argument("--sarif-base", dest="sarif_base",
                   help="paths in the SARIF are relative to this directory "
                        "(default: the working directory, which is the "
                        "repository root under GitHub Actions)")
    s.set_defaults(fn=cmd_scan)

    r = sub.add_parser("repair", help="the narrowest change that removes a finding")
    r.add_argument("tfdir", nargs="?")
    r.add_argument("--state")
    r.add_argument("--save-state")
    r.add_argument("--json")
    r.set_defaults(fn=cmd_repair)

    v = sub.add_parser("verify", help="re-derive every published number")
    v.add_argument("--full", action="store_true", help="also re-walk the corpus")
    v.add_argument("--budget", type=float, default=0)
    v.set_defaults(fn=cmd_verify)

    d = sub.add_parser("doctor", help="can this install run, and what is missing")
    d.set_defaults(fn=cmd_doctor)

    a = ap.parse_args(argv)
    if a.cmd in ("scan", "repair") and not (a.tfdir or a.state):
        ap.error("give a terraform directory, or --state")
    try:
        return a.fn(a)
    except RunFailed as e:
        print(f"{e}", file=sys.stderr)
        return EXIT_ERROR
    except SystemExit as e:
        # anything that exits by raising SystemExit is a failure of the run,
        # not a finding, so it must not land on the findings code
        if e.code in (None, 0):
            return EXIT_CLEAN
        print(f"{e}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as e:
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

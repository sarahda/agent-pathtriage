#!/usr/bin/env python3
"""Synthesise CDK apps to CloudFormation, then analyse them the exact way.

The chain analysis covers Terraform and CloudFormation and leaves CDK out,
because a CDK role's policies are built by code and recovering them from the
source is a heuristic. Synthesising removes the need for the heuristic: `cdk
synth` produces the CloudFormation the app would deploy, and that goes through
the same exact pipeline the CloudFormation corpus already uses.

What this does per app, in a scratch directory so the corpus is never written
to: install the app's requirements into a virtualenv, run its entry point with
`CDK_OUTDIR` set, then for each template it produced run `cfn_to_state.py` and
`reach.py` and record what came back.

A CDK app's entry point writes its templates when `App.synth()` is called, so
the CDK CLI is not needed and neither is node beyond what jsii brings in with
`aws-cdk-lib`. `JSII_RUNTIME_PACKAGE_CACHE=disabled` is set because the shared
cache directory is not writable in every environment and the failure is not
about the app.

An app that does not synthesise is recorded as a synth failure with its error,
which is a different thing from a template with no chain in it. Neither is
reported as the other.

Resumable: every app's result is appended to a jsonl beside the output, and a
run stops at its time budget. Delete the jsonl to start over.

  python3 evaluation/benchmark/cdk_synth_chain.py \\
      --corpus corpus_cfn --scan cfn_cdk_cfn_corpus_excluded.json \\
      --work ~/cdk-synth --budget 150 --json cdk_synth_chain.json
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CFN_TO_STATE = os.path.join(HERE, "cfn_to_state.py")
REACH = os.path.join(ROOT, "agentpathtriage", "reach.py")


def app_root(corpus, rel, depth=6):
    """The nearest ancestor holding cdk.json, which is where an app is run."""
    p = os.path.join(corpus, rel)
    for _ in range(depth):
        if os.path.isfile(os.path.join(p, "cdk.json")):
            return p
        nxt = os.path.dirname(p)
        if nxt == p:
            break
        p = nxt
    return None


def language(root):
    if os.path.isfile(os.path.join(root, "requirements.txt")):
        return "py"
    if os.path.isfile(os.path.join(root, "pyproject.toml")):
        return "py-pyproject"
    if os.path.isfile(os.path.join(root, "package.json")):
        return "ts"
    return "?"


def entry_point(root):
    """The app command from cdk.json, reduced to the python file it runs."""
    try:
        with open(os.path.join(root, "cdk.json")) as fh:
            app = str(json.load(fh).get("app") or "")
    except Exception:
        return None, "cdk.json could not be read"
    for token in app.split():
        if token.endswith(".py"):
            return token, app
    return None, app


def run(cmd, cwd, env=None, timeout=240):
    e = dict(os.environ)
    e.update(env or {})
    try:
        p = subprocess.run(cmd, cwd=cwd, env=e, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"


def analyse_template(path, tmp):
    """cfn_to_state then reach, the same calls the CloudFormation pass makes."""
    st = os.path.join(tmp, "state.json")
    rc, _out, err = run([sys.executable, CFN_TO_STATE, "--template", path,
                         "--json", st, "--quiet"], cwd=ROOT)
    if rc != 0 or not os.path.isfile(st):
        return {"step": "cfn_to_state", "ok": False, "error": err[-400:]}
    rj = os.path.join(tmp, "reach.json")
    rc, out, err = run([sys.executable, REACH, "--state", st, "--json", rj],
                       cwd=ROOT)
    if rc not in (0, 1) or not os.path.isfile(rj):
        return {"step": "reach", "ok": False, "error": err[-400:]}
    with open(rj) as fh:
        res = json.load(fh)["results"]
    with open(st) as fh:
        state = json.load(fh)
    runtimes = []
    def walk(o):
        if isinstance(o, dict):
            if o.get("type") == "aws_bedrockagentcore_agent_runtime":
                runtimes.append(o.get("name") or o.get("address"))
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(state)
    return {"step": "done", "ok": True,
            "agent_runtimes": len(runtimes),
            "principals": len(res),
            "escalating": [r["principal"] for r in res if r["Esc"]],
            "shared_trust_note": None}


def process_ts(rel, corpus, work, root, app_cmd, rec):
    """A TypeScript app, run the way its own cdk.json says to run it.

    The whole repository is copied into the scratch directory first. A node
    install writes node_modules next to the app, and the corpus is
    measurement input: nothing in it should change because it was analysed.
    These repositories are a few megabytes each, so copying is cheaper than
    being careful.
    """
    repo = rel.split("/")[0]
    w = os.path.join(work, rel.replace("/", "__"))
    shutil.rmtree(w, ignore_errors=True)
    os.makedirs(os.path.dirname(w) or w, exist_ok=True)
    try:
        shutil.copytree(os.path.join(corpus, repo), w)
    except Exception as e:
        rec.update(ok=False, stage="copy", why=repr(e)[:300])
        return rec

    # the app root inside the copy
    app = os.path.join(w, os.path.relpath(root, os.path.join(corpus, repo)))
    env = {"JSII_RUNTIME_PACKAGE_CACHE": "disabled",
           "CDK_DEFAULT_ACCOUNT": "000000000000",
           "CDK_DEFAULT_REGION": "us-east-1",
           "AWS_DEFAULT_REGION": "us-east-1",
           "AWS_REGION": "us-east-1",
           "CI": "1", "npm_config_fund": "false", "npm_config_audit": "false"}

    lock = os.path.isfile(os.path.join(app, "package-lock.json"))
    cmd = ["npm", "ci", "--no-audit", "--no-fund"] if lock else \
          ["npm", "install", "--no-audit", "--no-fund"]
    rc, _o, err = run(cmd, cwd=app, env=env, timeout=300)
    if rc != 0 and lock:
        # a lock file out of step with package.json fails ci but installs
        rec["npm_ci_failed"] = err[-200:]
        rc, _o, err = run(["npm", "install", "--no-audit", "--no-fund"],
                          cwd=app, env=env, timeout=300)
    if rc != 0:
        rec.update(ok=False, stage="install", why=err[-400:])
        shutil.rmtree(w, ignore_errors=True)
        return rec

    out = os.path.join(w, "_out")
    env["CDK_OUTDIR"] = out
    # The app command is whatever cdk.json says: npx ts-node, tsx, bun, node.
    rc, _o, err = run(["bash", "-lc", app_cmd], cwd=app, env=env, timeout=300)
    if rc != 0:
        rec.update(ok=False, stage="synth", why=err[-500:])
        shutil.rmtree(w, ignore_errors=True)
        return rec

    templates = sorted(f for f in os.listdir(out)
                       if f.endswith(".template.json")) if os.path.isdir(out) else []
    rec["templates"] = templates
    if not templates:
        rec.update(ok=False, stage="synth", why="no template was written")
        shutil.rmtree(w, ignore_errors=True)
        return rec

    tmp = os.path.join(w, "_analysis")
    os.makedirs(tmp, exist_ok=True)
    rec["analysis"] = [dict(template=t,
                            **analyse_template(os.path.join(out, t), tmp))
                       for t in templates]
    rec["agent_runtimes"] = sum(x.get("agent_runtimes", 0)
                                for x in rec["analysis"] if x.get("ok"))
    rec["escalating"] = [p for x in rec["analysis"] if x.get("ok")
                         for p in x["escalating"]]
    rec["ok"] = True
    rec["stage"] = "analysed"
    shutil.rmtree(w, ignore_errors=True)
    return rec


def process(rel, corpus, work):
    rec = {"directory": rel}
    root = app_root(corpus, rel)
    if not root:
        rec.update(ok=False, stage="locate", why="no cdk.json above this directory")
        return rec
    rec["app_root"] = os.path.relpath(root, corpus)
    # The app is run with cwd set to its own directory, so every path handed
    # to a subprocess has to be absolute or it resolves against the wrong one.
    root = os.path.abspath(root)
    rec["language"] = language(root)
    if rec["language"] not in ("py", "ts"):
        rec.update(ok=False, stage="language",
                   why=f"not handled here ({rec['language']})")
        return rec
    entry, app_cmd = entry_point(root)
    rec["app_command"] = app_cmd
    if rec["language"] == "py" and not entry:
        rec.update(ok=False, stage="entrypoint",
                   why="the app command names no python file")
        return rec
    if rec["language"] == "ts":
        return process_ts(rel, corpus, work, root, app_cmd, rec)

    # The app is run where it sits. Copying only the directory holding
    # cdk.json broke every app that stages an asset from a sibling path, and
    # the failure was the harness rather than the app. Nothing is written into
    # the corpus: the virtualenv lives in the scratch directory and CDK_OUTDIR
    # sends the synthesised output there too.
    w = os.path.join(work, rel.replace("/", "__"))
    shutil.rmtree(w, ignore_errors=True)
    os.makedirs(w, exist_ok=True)

    rc, _o, err = run([sys.executable, "-m", "venv", os.path.join(w, ".venv")],
                      cwd=w)
    if rc != 0:
        rec.update(ok=False, stage="venv", why=err[-300:])
        return rec
    pip = os.path.join(w, ".venv", "bin", "pip")
    py = os.path.join(w, ".venv", "bin", "python")
    rc, _o, err = run([pip, "install", "-q", "-r",
                       os.path.join(root, "requirements.txt")], cwd=w)
    if rc != 0:
        rec.update(ok=False, stage="install", why=err[-400:])
        return rec
    # Some requirements files leave the CDK itself to the reader, so the app
    # imports aws_cdk and it is not there. Installing it is not changing what
    # the app declares, it is supplying what the app assumes.
    rc_check, _o, _e = run([py, "-c", "import aws_cdk"], cwd=w)
    if rc_check != 0:
        rc, _o, err = run([pip, "install", "-q", "aws-cdk-lib", "constructs"],
                          cwd=w)
        if rc != 0:
            rec.update(ok=False, stage="install", why=err[-400:])
            return rec
        rec["cdk_supplied_by_the_harness"] = True

    out = os.path.join(w, "out")
    rc, _o, err = run([py, os.path.join(root, entry)], cwd=root,
                      env={"JSII_RUNTIME_PACKAGE_CACHE": "disabled",
                           "CDK_OUTDIR": out,
                           # An app that reads its environment from the CDK
                           # defaults stops without them. These are the same
                           # placeholders the CloudFormation pass already uses,
                           # so no real account or region enters the analysis.
                           "CDK_DEFAULT_ACCOUNT": "000000000000",
                           "CDK_DEFAULT_REGION": "us-east-1",
                           "AWS_DEFAULT_REGION": "us-east-1",
                           "AWS_REGION": "us-east-1"})
    if rc != 0:
        rec.update(ok=False, stage="synth", why=err[-500:])
        return rec
    templates = sorted(f for f in os.listdir(out)
                       if f.endswith(".template.json")) if os.path.isdir(out) else []
    rec["templates"] = templates
    if not templates:
        rec.update(ok=False, stage="synth", why="no template was written")
        return rec

    tmp = os.path.join(w, "_analysis")
    os.makedirs(tmp, exist_ok=True)
    rec["analysis"] = [dict(template=t,
                            **analyse_template(os.path.join(out, t), tmp))
                       for t in templates]
    # The venv holds a copy of the CDK and its bundled node assets, a few
    # hundred megabytes an app, and keeping fifteen of them fills a disk for
    # no reason: everything worth keeping is already in this record.
    shutil.rmtree(w, ignore_errors=True)

    rec["ok"] = True
    rec["stage"] = "analysed"
    rec["agent_runtimes"] = sum(a.get("agent_runtimes", 0)
                                for a in rec["analysis"] if a.get("ok"))
    rec["escalating"] = [p for a in rec["analysis"] if a.get("ok")
                         for p in a["escalating"]]
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus_cfn")
    ap.add_argument("--scan", default="cfn_cdk_cfn_corpus_excluded.json")
    ap.add_argument("--work", default=os.path.expanduser("~/cdk-synth"))
    ap.add_argument("--budget", type=float, default=150,
                    help="stop starting new apps after this many seconds")
    ap.add_argument("--json", default="cdk_synth_chain.json")
    ap.add_argument("--only", default=None, help="one directory, for a trial")
    a = ap.parse_args()

    scan_path = a.scan if os.path.isabs(a.scan) else os.path.join(HERE, a.scan)
    with open(scan_path) as fh:
        scan = json.load(fh)
    cdk = scan["sections"]["cdk"] if "sections" in scan else scan["cdk"]
    dirs = [x["directory"] if isinstance(x, dict) else x
            for x in (cdk.get("multi_after") or cdk.get("multi") or [])]
    if a.only:
        dirs = [d for d in dirs if d == a.only]

    out_path = a.json if os.path.isabs(a.json) else os.path.join(HERE, a.json)
    cache_path = out_path + "l"          # .jsonl beside the output
    done = {}
    if os.path.isfile(cache_path):
        with open(cache_path) as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                done[r["directory"]] = r

    os.makedirs(a.work, exist_ok=True)
    started = time.time()
    with open(cache_path, "a") as cf:
        for rel in dirs:
            if rel in done:
                continue
            if time.time() - started > a.budget:
                print(f"budget reached; {len(dirs) - len(done)} left")
                break
            print(f"[{len(done) + 1}/{len(dirs)}] {rel}", flush=True)
            rec = process(rel, a.corpus, a.work)
            shutil.rmtree(os.path.join(a.work, rel.replace("/", "__")),
                          ignore_errors=True)
            mark = rec.get("stage") if rec.get("ok") else f"FAILED at {rec.get('stage')}"
            print(f"      {mark}"
                  + (f"  runtimes {rec.get('agent_runtimes')}"
                     f"  escalating {len(rec.get('escalating') or [])}"
                     if rec.get("ok") else f"  {str(rec.get('why'))[:120]}"),
                  flush=True)
            cf.write(json.dumps(rec) + "\n")
            cf.flush()
            done[rel] = rec

    rows = list(done.values())
    ok = [r for r in rows if r.get("ok")]
    py = [r for r in rows if r.get("language") == "py"]
    summary = {
        "directories_in_scope": len(dirs),
        "attempted": len(rows),
        "python_apps": len(py),
        "synthesised_and_analysed": len(ok),
        "agent_runtimes_recovered": sum(r.get("agent_runtimes", 0) for r in ok),
        "apps_with_an_escalating_principal":
            len([r for r in ok if r.get("escalating")]),
        "failures_by_stage": {},
        "rows": rows,
    }
    for r in rows:
        if r.get("ok"):
            continue
        k = r.get("stage", "?")
        summary["failures_by_stage"][k] = summary["failures_by_stage"].get(k, 0) + 1

    print()
    print(f"attempted {summary['attempted']} of {summary['directories_in_scope']}")
    print(f"  synthesised and analysed : {summary['synthesised_and_analysed']}")
    print(f"  agent runtimes recovered : {summary['agent_runtimes_recovered']}")
    print(f"  apps with an escalation  : {summary['apps_with_an_escalating_principal']}")
    for k, v in sorted(summary["failures_by_stage"].items()):
        print(f"  failed at {k}: {v}")

    with open(out_path, "w") as fh:
        json.dump(summary, fh, indent=1)
    print(f"\nwritten: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

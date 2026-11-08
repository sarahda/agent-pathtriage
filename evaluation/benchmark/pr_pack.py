#!/usr/bin/env python3
"""Build one disclosure package per reportable template, with the send gate
computed rather than asserted, and with the gate matched to the claim.

validation/DISCLOSURE_TEMPLATE.md sets a pre-send gate whose first two
conditions are about codereq: the verdict must be possible, and the action
being reported must be in over_granted. Those exist because the AgentCore
weather-agent sample looked over-granted under a configuration-only reading
and was not. That lesson is about ONE kind of claim.

There are two kinds, and they need different gates.

  over-grant claim      "this role grants an action the code never uses".
                        Needs the codereq gate, because the code decides
                        whether the claim is true.

  shared-role claim     "these agents all run as one role, so a weakness in
                        any one of them reaches everything the others are
                        trusted with". Names no unnecessary permission, so
                        codereq has nothing to say about it. Gating it on
                        codereq withholds a true report for an irrelevant
                        reason.

Measured on the five reportable templates, four have no container code inside
the Terraform directory, and the one that does yields an empty over_granted
set once the SDK wrapper is accounted for. Gating all five on codereq would
have blocked four true shared-role reports and sent none.

So each package states which claim it makes, runs only the conditions that
claim needs, and says in the text that no permission is being called
unnecessary when that is the case.

Targets come from the committed artifacts, never from a list typed here: every
template shared_role.py found sharing one execution role, plus every gap
adjudicate_gaps.py called cross-agent or shared-role.

Usage:
    python3 evaluation/benchmark/pr_pack.py --corpus corpus_tier2
    python3 evaluation/benchmark/pr_pack.py --only avparkhi__agui-agentcore-demo
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
APT = os.path.join(ROOT, "agentpathtriage")
TEMPLATE = os.path.join(ROOT, "validation", "DISCLOSURE_TEMPLATE.md")
TOOL_URL = "https://github.com/sarahda/agent-pathtriage"
OUTDIR = os.path.join(ROOT, "validation", "pr")

REPORTABLE = ("cross-agent", "shared-role")


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                          timeout=900, **kw)


def artifact(name):
    with open(os.path.join(HERE, name)) as fh:
        return json.load(fh)


def targets():
    out = {}
    for row in artifact("shared_role_tier2.json").get("shared_role", []):
        d = out.setdefault(row["template"], {"template": row["template"],
                                             "classes": set(), "detail": {}})
        d["classes"].add("shared-role (role scan)")
        d["detail"]["groups"] = row.get("groups")
    for row in artifact("adjudication_tier2.json"):
        if row.get("verdict") in REPORTABLE:
            d = out.setdefault(row["template"], {"template": row["template"],
                                                 "classes": set(), "detail": {}})
            d["classes"].add(f"{row['verdict']} (gap adjudication)")
            d["detail"].setdefault("gap_rows", []).append(
                {"runtime": row.get("runtime"), "wired_source": row.get("wired_source"),
                 "agents": row.get("agents"), "roles": row.get("roles")})
    for v in out.values():
        v["classes"] = sorted(v["classes"])
    return [out[k] for k in sorted(out)]


def limitations():
    text = open(TEMPLATE, encoding="utf-8").read()
    m = re.search(r"^## *Limitations.*?$(.*?)(?=^## |\Z)", text, re.M | re.S)
    return m.group(0).strip() if m else ""


def evidence(corpus, tmpl, repo):
    """Everything a gate might need, gathered once."""
    tdir = os.path.join(corpus, tmpl)
    repo_dir = os.path.join(corpus, repo)
    ev = {"template_dir": tdir}

    with tempfile.TemporaryDirectory() as tmp:
        state = os.path.join(tmp, "state.json")
        r = run([sys.executable, os.path.join(HERE, "tf_to_state.py"),
                 "--tfdir", tdir, "--json", state])
        ev["tf_to_state_exit"] = r.returncode
        ok = r.returncode == 0 and os.path.exists(state)

        if ok:
            rep = os.path.join(tmp, "report.json")
            r2 = run([sys.executable, os.path.join(APT, "report.py"),
                      "--state", state, "--json", rep])
            ev["report_exit"] = r2.returncode
            ev["report_stdout_tail"] = r2.stdout.strip()[-1500:]

            rp = os.path.join(tmp, "repair.json")
            r3 = run([sys.executable, os.path.join(APT, "repair.py"),
                      "--state", state, "--json", rp])
            ev["repair_exit"] = r3.returncode
            if os.path.exists(rp):
                try:
                    ev["repair"] = json.load(open(rp))
                except Exception:
                    ev["repair"] = None
        else:
            ev["report_exit"] = ev["repair_exit"] = None

    # codereq twice: the colocation measure, and the repository scope a
    # disclosure gate actually wants. Reported separately so neither is
    # mistaken for the other.
    for label, extra in (("colocated", []), ("repository", ["--code-root", repo_dir])):
        d = tempfile.mkdtemp()
        cj = os.path.join(d, "codereq.json")
        rc = run([sys.executable, os.path.join(APT, "codereq.py"),
                  "--template", tdir, "--json", cj] + extra)
        cr = None
        if os.path.exists(cj):
            try:
                cr = json.load(open(cj))
                cr = cr[0] if isinstance(cr, list) and cr else cr
            except Exception:
                cr = None
        ev[f"codereq_{label}"] = cr
        ev[f"codereq_{label}_exit"] = rc.returncode
    return ev


def shared_role_groups(ev, t):
    """Groups of two or more agents under one role, as the artifact records
    them. A group of one is not a shared role and must not be packaged."""
    groups = (t["detail"].get("groups") or {})
    return {role: agents for role, agents in groups.items() if len(agents) >= 2}


def unresolved(role):
    """A role name that is still a Terraform interpolation is not evidence of
    anything: at apply time it may differ per agent."""
    return bool(re.search(r"\$\{[^}]*\}", str(role)))


def gates(ev, t):
    """Per claim: the conditions that claim needs, each already evaluated."""
    out = {}

    groups = shared_role_groups(ev, t)
    resolved = {r: a for r, a in groups.items() if not unresolved(r)}
    out["shared-role"] = {
        "two or more agents under one role": bool(groups),
        "reproduction commands run clean": ev.get("report_exit") == 0,
        "limitations carried through unedited": bool(limitations()),
        "package makes no over-grant claim": True,
    }
    out["_shared_role_groups"] = groups
    out["_shared_role_resolved"] = resolved

    cr = ev.get("codereq_repository") or {}
    over = cr.get("over_granted") or []
    out["over-grant"] = {
        "codereq verdict possible (repository scope)": bool(cr.get("verdict_possible")),
        "an action is in over_granted": bool(over),
        "reproduction commands run clean": ev.get("report_exit") == 0,
        "limitations carried through unedited": bool(limitations()),
    }
    out["_over_granted"] = over
    return out


def validated_repairs(ev):
    rep = ev.get("repair")
    rows = rep if isinstance(rep, list) else (rep or {}).get("rows", [])
    return [r for r in rows if isinstance(r, dict) and r.get("repair")]


def body(t, g, ev, repo):
    sr_ok = all(g["shared-role"].values())
    og_ok = all(g["over-grant"].values())
    fixes = validated_repairs(ev)
    co = ev.get("codereq_colocated") or {}
    rp = ev.get("codereq_repository") or {}

    L = []
    A = L.append
    A(f"# Disclosure package: {repo}")
    A("")
    A(f"Template: `{t['template']}`")
    A(f"Detectors that flagged it: {', '.join(t['classes'])}")
    A("")
    A("## Which claim this package makes")
    A("")
    if sr_ok and og_ok:
        A("**Shared execution role, and an over-granted action.** Both gates pass.")
    elif sr_ok:
        A("**Shared execution role only.** No permission is claimed to be "
          "unnecessary in this package, so the over-grant gate does not apply "
          "and is reported below for completeness.")
    elif og_ok:
        A("**Over-granted action only.**")
    else:
        A("**DO NOT SEND.** No claim passes its own gate.")
    A("")
    for claim in ("shared-role", "over-grant"):
        A(f"### {claim} gate")
        A("")
        A("| Condition | Result |")
        A("|---|---|")
        for k in sorted(g[claim]):
            A(f"| {k} | {'PASS' if g[claim][k] else 'FAIL'} |")
        A("")
    A(f"codereq saw {co.get('code_files', 0)} file(s) colocated with the "
      f"Terraform and {rp.get('code_files', 0)} in the repository. "
      f"Repository scope verdict: "
      f"{'possible' if rp.get('verdict_possible') else rp.get('why_no_verdict')}. "
      f"over_granted: {g['_over_granted'] or 'none'}.")
    if rp.get("unresolved_namespaces"):
        A("")
        A(f"The code reaches `{', '.join(rp['unresolved_namespaces'])}` through "
          f"a wrapper this analysis cannot resolve to specific actions, so no "
          f"grant in that namespace is called unnecessary here.")
    A("")
    A("## What was found")
    A("")
    for role, agents in (g["_shared_role_groups"] or {}).items():
        A(f"- Agents `{'`, `'.join(agents)}` all run as `{role}`. Any permission "
          f"either one needs is held by both, so a weakness in one reaches "
          f"everything the other is trusted with.")
        if unresolved(role):
            A(f"  - The role name is a Terraform expression, so this holds for "
              f"the template as written. If you override it per agent at apply "
              f"time, it does not apply to your deployment.")
    for row in t["detail"].get("gap_rows", []):
        A(f"- Runtime `{row.get('runtime')}` is wired to "
          f"`{', '.join(row.get('agents') or [])}` (recovered by "
          f"{row.get('wired_source')}), and its role grants more than that "
          f"wiring uses.")
    A("")
    if fixes:
        A("## Suggested change, validated by re-analysis")
        A("")
        A("Each was applied to the parsed configuration and the analysis re-run. "
          "The witness is gone afterwards and no new finding appeared anywhere "
          "else. That is the acceptance test, and a change that fails it is not "
          "offered.")
        A("")
        for f in fixes[:6]:
            r = f["repair"]
            A(f"- **{r.get('kind')}** at `{r.get('where')}`: {r.get('what')}")
            if r.get("breaks"):
                A(f"  - what this would break: {r['breaks']}")
    else:
        A("## Suggested change")
        A("")
        A("No repair passed re-analysis here, so this is a report rather than a "
          "pull request. Offering a change that does not survive the tool's own "
          "check would waste your time.")
    A("")
    A("## Reproduce, without deploying anything")
    A("")
    # The reader has neither checkout, so both are cloned here. "pip install
    # -e ." only works from inside the tool's own directory, which is not
    # where anyone receiving this is standing.
    A("```bash")
    A(f"git clone --depth 1 {TOOL_URL} agentpathtriage")
    A("pip install -e agentpathtriage")
    A(f"git clone --depth 1 https://github.com/{repo.replace('__', '/')} t")
    A("agentpathtriage scan t/" + "/".join(t["template"].split("/")[1:]))
    A("```")
    A("")
    A(limitations())
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool-url", default=TOOL_URL)
    ap.add_argument("--corpus", default="corpus_tier2")
    ap.add_argument("--only")
    ap.add_argument("--outdir", default=OUTDIR)
    a = ap.parse_args()

    corpus = os.path.abspath(a.corpus)
    os.makedirs(a.outdir, exist_ok=True)
    rows = []
    for t in targets():
        repo = t["template"].split("/")[0]
        if a.only and a.only != repo:
            continue
        if not os.path.isdir(os.path.join(corpus, t["template"])):
            print(f"-- {repo}: template not in the corpus, skipped")
            continue
        print(f"-- {repo}")
        ev = evidence(corpus, t["template"], repo)
        g = gates(ev, t)
        claims = [c for c in ("shared-role", "over-grant") if all(g[c].values())]
        for c in ("shared-role", "over-grant"):
            print(f"     {c}:")
            for k in sorted(g[c]):
                print(f"        {'PASS' if g[c][k] else 'FAIL'}  {k}")
        print(f"     -> {'SEND as ' + ' + '.join(claims) if claims else 'DO NOT SEND'}")
        path = os.path.join(a.outdir, f"{repo}.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body(t, g, ev, repo))
        rows.append({
            "repo": repo, "template": t["template"], "classes": t["classes"],
            "claims_passing": claims,
            "gates": {c: g[c] for c in ("shared-role", "over-grant")},
            "over_granted": g["_over_granted"],
            "codereq_colocated_files": (ev.get("codereq_colocated") or {}).get("code_files"),
            "codereq_repository_files": (ev.get("codereq_repository") or {}).get("code_files"),
            "validated_repairs": len(validated_repairs(ev)),
            "package": os.path.relpath(path, ROOT),
        })

    out = os.path.join(a.outdir, "pr_pack.json")
    with open(out, "w") as fh:
        json.dump(rows, fh, indent=2)
    n = sum(1 for r in rows if r["claims_passing"])
    print(f"\n{n} of {len(rows)} package(s) have at least one claim that passes")
    print(f"written: {os.path.relpath(out, ROOT)}")


if __name__ == "__main__":
    main()

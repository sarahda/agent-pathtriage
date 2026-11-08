#!/usr/bin/env python3
"""What each blocked takeover candidate actually is, read back from the source.

The census counts 26 candidates blocked on `iam:PassRole`. Read as a sentence
that is "26 deployments one permission away from a cross-agent escalation",
and that is not what all of them are. Two things narrow it.

A candidate in a configuration that declares one agent has no sibling to take
over. The precondition is there and the second agent is not, which is latent
at module level rather than a finding, the same way a single-agent resource
scope gap is.

A candidate whose principal is not an agent's execution role is a takeover,
but not an agent-to-agent one. A gateway role or a build role reaching an
agent runtime is a different claim from one agent reaching another, and the
paper says the second.

This pass re-derives each configuration's agent execution roles from the raw
Terraform, by the same route as `shared_role_source_check.py`, and sorts the
candidates by which of those they are. It reports the figure the paper should
carry alongside the 26, rather than replacing it.

  python3 evaluation/benchmark/blocked_takeover_source_check.py \\
      --corpus corpus_tier2 --json blocked_takeover_source_check.json
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from shared_role_source_check import scan_template  # noqa: E402

IAM_ROLE = re.compile(
    r'resource\s+"aws_iam_role"\s+"([^"]+)"\s*\{(.*?)\n\}', re.S)
NAME = re.compile(r'^\s*name\s*=\s*(.+?)\s*$', re.M)
REF = re.compile(r'aws_iam_role\.([A-Za-z0-9_\-]+)')


def unquote(expr):
    """Terraform writes a name as a quoted string or an interpolation."""
    if expr is None:
        return None
    e = expr.strip()
    if len(e) >= 2 and e[0] == e[-1] and e[0] in "\"'":
        return e[1:-1]
    return e


def role_names(template_dir):
    """Every aws_iam_role in the template, as resource label -> declared name."""
    out = {}
    for root, _dirs, files in os.walk(template_dir):
        for fn in sorted(files):
            if not fn.endswith(".tf"):
                continue
            try:
                with open(os.path.join(root, fn), encoding="utf-8",
                          errors="ignore") as fh:
                    text = fh.read()
            except Exception:
                continue
            for label, body in IAM_ROLE.findall(text):
                m = NAME.search(body)
                out[label] = unquote(m.group(1)) if m else None
    return out


def agent_role_names(template_dir):
    """The declared names of the roles the template's agent runtimes run as."""
    labels = role_names(template_dir)
    names = set()
    for rt in scan_template(template_dir):
        expr = rt.get("role_arn_expression") or ""
        for label in REF.findall(expr):
            if labels.get(label):
                names.add(labels[label])
    return names, labels


def load_blocked(bench, census_name):
    """The blocked candidates, from the artifact if it carries them, else from
    the shard caches the census wrote."""
    path = os.path.join(bench, census_name)
    if os.path.isfile(path):
        with open(path) as fh:
            cen = json.load(fh)
        detail = cen.get("expanded", {}).get("blocked_detail")
        if detail:
            return detail, "artifact"

    rows = []
    stem = os.path.splitext(census_name)[0]
    for f in sorted(glob.glob(os.path.join(bench, stem + "*.jsonl"))):
        with open(f) as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if r.get("error") or "expanded" not in r:
                    continue
                for b in r["expanded"]["blocked_takeovers"]:
                    rows.append(dict(b, config=r["config"],
                                     n_agents=r.get("n_agents")))
    return rows, "shard cache"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus_tier2")
    ap.add_argument("--census", default="corpus_takeover_census.json")
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    blocked, src = load_blocked(HERE, a.census)
    if not blocked:
        print("no blocked candidates found; nothing to check")
        return 2
    print(f"{len(blocked)} blocked candidates, read from the {src}")

    agents_by_config = {}
    rows = []
    for b in blocked:
        cfg = b["config"]
        if cfg not in agents_by_config:
            agents_by_config[cfg] = agent_role_names(
                os.path.join(a.corpus, cfg))
        names, _labels = agents_by_config[cfg]

        principal_is_agent_role = b["principal"] in names
        target_is_agent_role = b["target_role"] in names
        if (b.get("n_agents") or 0) < 2:
            verdict = "single-agent"
        elif not principal_is_agent_role:
            verdict = "principal is not an agent execution role"
        elif not target_is_agent_role:
            verdict = "target is not an agent execution role"
        elif b["principal"] == b["target_role"]:
            verdict = "principal and target are the same role"
        else:
            verdict = "agent to agent"

        rows.append({**b,
                     "agent_execution_roles_in_config": sorted(names),
                     "principal_is_an_agent_execution_role": principal_is_agent_role,
                     "target_is_an_agent_execution_role": target_is_agent_role,
                     "verdict": verdict})

    counts = collections.Counter(r["verdict"] for r in rows)
    a2a = counts.get("agent to agent", 0)
    print()
    for k, v in counts.most_common():
        print(f"  {v:3}  {k}")
    print(f"\n  {a2a} of {len(rows)} are one permission away from one agent "
          f"reaching another")
    print(f"  across {len({r['config'] for r in rows if r['verdict'] == 'agent to agent'})} "
          f"configurations")

    if a2a:
        print("\nthe agent to agent ones:")
        for r in rows:
            if r["verdict"] != "agent to agent":
                continue
            print(f"  {r['config']}")
            print(f"    {r['principal']}  ->  {r['target_role']}")
            print(f"    via {r['action']}, missing "
                  f"{', '.join(r['missing_dependent_actions'])}")

    if a.json:
        dst = a.json if os.path.isabs(a.json) else os.path.join(HERE, a.json)
        with open(dst, "w") as fh:
            json.dump({
                "read_from": src,
                "method": ("each configuration's agent execution roles are "
                           "re-derived from the raw Terraform, then every "
                           "blocked candidate is sorted by whether its "
                           "principal and its target are among them"),
                "candidates": len(rows),
                "by_verdict": dict(counts),
                "agent_to_agent": a2a,
                "rows": rows,
            }, fh, indent=1)
        print(f"\nwritten: {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

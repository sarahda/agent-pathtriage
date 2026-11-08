#!/usr/bin/env python3
"""Count multi-agent deployments per repository as well as per template.

The headline numbers so far are per template directory: 220 analysed
templates, 18 with two or more agents, 5 of those sharing one execution role.
A template directory is one Terraform root, so two agents declared in two
roots of the same repository are counted as two single-agent templates even
though they ship together and land in one account.

Both units are defensible and they answer different questions. The template
unit asks whether one deployable unit declares several agents. The repository
unit asks whether a project ships several agents. The paper has to report
both, say which one each figure uses, and never mix them. An earlier version
of this project reported 15.0% and 92.7% for the same quantity under two
units, which is the mistake this script exists to prevent.

Everything is read from the committed artifacts. Nothing about the corpus is
written into this file.

  python3 repo_level.py --topology evaluation/benchmark/topology_tier2.json \\
      --shared evaluation/benchmark/shared_role_tier2.json \\
      --json evaluation/benchmark/repo_level_tier2.json
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys


def repo_of(template_path: str) -> str:
    """Corpus paths are owner__repo/subdir/..., so the first segment is the repo."""
    return template_path.split("/", 1)[0]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--topology", required=True, type=pathlib.Path)
    ap.add_argument("--shared", required=True, type=pathlib.Path)
    ap.add_argument("--json", type=pathlib.Path)
    args = ap.parse_args()

    topo = json.loads(args.topology.read_text())
    shared = json.loads(args.shared.read_text())

    # --- template unit, recomputed rather than quoted ---
    n_templates = len(topo)
    multi_templates = [t for t in topo if t.get("n_agents", 0) >= 2]
    shared_templates = {e["template"] if isinstance(e, dict) else e
                        for e in shared.get("shared_role", [])}

    # --- repository unit ---
    by_repo = collections.defaultdict(list)
    for t in topo:
        by_repo[repo_of(t["t"])].append(t)

    repos = {}
    for repo, entries in by_repo.items():
        agents = []
        for e in entries:
            agents.extend(e.get("agents") or [])
        repos[repo] = {
            "templates": len(entries),
            "agents": len(agents),
            "agent_names": agents,
            "multi_agent_templates": sum(
                1 for e in entries if e.get("n_agents", 0) >= 2),
            "has_shared_role_template": any(
                e["t"] in shared_templates for e in entries),
        }

    n_repos = len(repos)
    multi_repos = {r: v for r, v in repos.items() if v["agents"] >= 2}
    shared_repos = {r: v for r, v in repos.items() if v["has_shared_role_template"]}

    # A repository that is multi-agent only because several single-agent
    # templates sit side by side is the interesting difference between the two
    # units, so it is counted separately rather than folded in.
    multi_only_at_repo_level = {
        r: v for r, v in multi_repos.items() if v["multi_agent_templates"] == 0}

    out = {
        "_unit_warning": (
            "repositories_contributing_an_analysed_template is NOT the funnel's "
            "'182 repositories with runtimes'. The funnel counts repositories "
            "before test fixtures and forks are removed; this counts the "
            "repositories the 220 surviving templates come from. Do not use "
            "one label for the other."),
        "template_unit": {
            "analysed_templates": n_templates,
            "multi_agent_templates": len(multi_templates),
            "sharing_one_execution_role": len(shared_templates),
            "share": round(len(shared_templates) / len(multi_templates), 4)
            if multi_templates else None,
        },
        "repository_unit": {
            "repositories_contributing_an_analysed_template": n_repos,
            "multi_agent_repositories": len(multi_repos),
            "repositories_with_a_shared_role_template": len(shared_repos),
            "multi_agent_only_at_repository_level": len(multi_only_at_repo_level),
        },
        "multi_agent_only_at_repository_level_list": sorted(
            multi_only_at_repo_level),
        "note": ("The two units answer different questions and must never be "
                 "mixed. A repository that is multi-agent only because several "
                 "single-agent templates sit beside each other is a weaker "
                 "observation than one template declaring several agents, "
                 "because nothing says the templates are applied to one "
                 "account. The shared-role finding is only computed within a "
                 "template, so the repository unit carries no shared-role "
                 "claim of its own."),
    }

    t, r = out["template_unit"], out["repository_unit"]
    print("template unit")
    print(f"  analysed templates                 {t['analysed_templates']}")
    print(f"  two or more agents                 {t['multi_agent_templates']}")
    print(f"  sharing one execution role         {t['sharing_one_execution_role']}")
    print()
    print("repository unit")
    print(f"  repos contributing a template      {r['repositories_contributing_an_analysed_template']}")
    print(f"  two or more agents                 {r['multi_agent_repositories']}")
    print(f"  of those, multi agent ONLY because")
    print(f"  separate templates sit side by side {r['multi_agent_only_at_repository_level']}")
    print(f"  repos containing a shared-role template {r['repositories_with_a_shared_role_template']}")
    print()
    if out["multi_agent_only_at_repository_level_list"]:
        print("multi agent only at repository level:")
        for x in out["multi_agent_only_at_repository_level_list"]:
            print("   ", x)
        print()
    print(out["note"])

    if args.json:
        args.json.write_text(json.dumps(out, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

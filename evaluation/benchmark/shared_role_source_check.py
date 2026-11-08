#!/usr/bin/env python3
"""Re-derive the shared execution role finding straight from the source text.

The census in `shared_role_tier2.json` reaches its answer through the parser
and the graph. This pass asks the same question of the raw Terraform, by a
different route: find every `aws_bedrockagentcore_agent_runtime` block, read
the `role_arn` expression out of the block, and group the runtimes by it.

Two routes agreeing is worth more than one route repeated, and it gives a
precision for a claim that otherwise rests on the census alone. It also writes
down where to look, so a reader can check a row in a few seconds without
running anything.

This reads published source. It is not a check of a deployment, and it cannot
see what Terraform would resolve the expression to at apply time. Two call
sites with the same expression text are treated as the same role, which is
what makes it a cross check rather than an independent oracle.

  python3 evaluation/benchmark/shared_role_source_check.py \
      --corpus corpus_tier2 --json shared_role_source_check.json
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys

RUNTIME = re.compile(
    r'resource\s+"aws_bedrockagentcore_agent_runtime"\s+"([^"]+)"\s*\{', re.M)
ROLE_ARN = re.compile(r'^\s*role_arn\s*=\s*(.+?)\s*$', re.M)
NAME = re.compile(r'^\s*agent_runtime_name\s*=\s*(.+?)\s*$', re.M)


def block_of(text, start):
    """The text of one braced block, from the brace that `start` points past."""
    depth, i = 0, text.index("{", start - 1)
    begin = i
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[begin:i + 1]
        i += 1
    return text[begin:]


def line_of(text, index):
    return text.count("\n", 0, index) + 1


def scan_template(template_dir):
    """Every runtime in one template directory, with the role expression."""
    found = []
    for root, _dirs, files in os.walk(template_dir):
        for fn in sorted(files):
            if not fn.endswith(".tf"):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except Exception:
                continue
            for m in RUNTIME.finditer(text):
                body = block_of(text, m.end())
                role = ROLE_ARN.search(body)
                name = NAME.search(body)
                found.append({
                    "runtime": m.group(1),
                    "file": os.path.relpath(path, template_dir),
                    "line": line_of(text, m.start()),
                    "agent_runtime_name": name.group(1) if name else None,
                    "role_arn_expression": role.group(1) if role else None,
                })
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus_tier2")
    ap.add_argument("--census", default=None,
                    help="shared_role_tier2.json, to compare against")
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    census_path = a.census or os.path.join(here, "shared_role_tier2.json")
    with open(census_path) as fh:
        census = json.load(fh)

    # The 18 the census calls multi-agent: the 5 it calls shared plus the 13
    # it says use distinct roles. Both are checked, because the claim being
    # tested is "this template declares two or more agents", and a template
    # with one agent would be wrong in either list.
    multi = ([e["template"] for e in census["shared_role"]]
             + list(census.get("distinct_roles", [])))
    multi_rows, multi_ok = [], 0
    for template in multi:
        found = scan_template(os.path.join(a.corpus, template))
        ok = len(found) >= 2
        multi_ok += ok
        multi_rows.append({
            "template": template,
            "runtimes_in_source": len(found),
            "source_confirms_two_or_more": ok,
            "runtimes": [{"runtime": f["runtime"], "file": f["file"],
                          "line": f["line"]} for f in found],
        })

    print(f"census says {len(multi)} templates declare two or more agents")
    for r in multi_rows:
        if not r["source_confirms_two_or_more"]:
            print(f"  NOT CONFIRMED  {r['template']}  "
                  f"({r['runtimes_in_source']} runtime(s) in source)")
    print(f"source confirms {multi_ok} of {len(multi)}")
    if multi:
        print(f"precision of the multi-agent claim against a source read: "
              f"{multi_ok / len(multi):.3f}\n")

    rows, agreed, disagreed = [], 0, 0
    for entry in census["shared_role"]:
        template = entry["template"]
        found = scan_template(os.path.join(a.corpus, template))
        by_role = collections.defaultdict(list)
        for f in found:
            by_role[f["role_arn_expression"]].append(f)
        shared = {r: v for r, v in by_role.items() if r and len(v) > 1}
        ok = bool(shared)
        agreed += ok
        disagreed += not ok
        rows.append({
            "template": template,
            "runtimes_in_source": len(found),
            "distinct_role_expressions": len(by_role),
            "source_confirms_sharing": ok,
            "shared_by": {
                r: [{"runtime": x["runtime"], "file": x["file"],
                     "line": x["line"]} for x in v]
                for r, v in shared.items()},
            "all_runtimes": found,
        })

    print(f"census says {len(census['shared_role'])} templates share one "
          f"execution role")
    for r in rows:
        mark = "confirmed" if r["source_confirms_sharing"] else "NOT CONFIRMED"
        print(f"\n  {r['template']}  [{mark}]")
        for role, members in r["shared_by"].items():
            print(f"    {role}")
            for m in members:
                print(f"      {m['runtime']}  {m['file']}:{m['line']}")
        if not r["source_confirms_sharing"]:
            print(f"    runtimes found in source: {r['runtimes_in_source']}, "
                  f"distinct role expressions: {r['distinct_role_expressions']}")

    total = len(rows)
    print(f"\nsource confirms {agreed} of {total}")
    if total:
        print(f"precision of the shared-role claim against a source read: "
              f"{agreed / total:.3f}")

    if a.json:
        out = a.json if os.path.isabs(a.json) else os.path.join(here, a.json)
        with open(out, "w") as fh:
            json.dump({
                "multi_agent": {
                    "templates_checked": len(multi),
                    "source_confirms": multi_ok,
                    "precision": (multi_ok / len(multi)) if multi else None,
                    "rows": multi_rows,
                },
                "method": ("every aws_bedrockagentcore_agent_runtime block is "
                           "found in the raw Terraform and grouped by the "
                           "role_arn expression text. Two call sites with the "
                           "same expression are treated as the same role."),
                "scope": "published source, not a deployment",
                "templates_checked": total,
                "source_confirms": agreed,
                "source_does_not_confirm": disagreed,
                "precision": (agreed / total) if total else None,
                "rows": rows,
            }, fh, indent=1)
        print(f"\nwritten: {out}")
    return 0 if disagreed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

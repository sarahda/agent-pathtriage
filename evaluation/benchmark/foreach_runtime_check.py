#!/usr/bin/env python3
"""Runtime blocks that create more than one runtime, and what the census made
of them.

The shared-role census counts `aws_bedrockagentcore_agent_runtime` blocks. A
block carrying `count` or `for_each` creates as many runtimes as the thing it
iterates has elements, so counting blocks and counting runtimes are not the
same number. Nothing in the census says which one it reports, and a template
whose single block fans out to several runtimes is counted as one agent.

This pass finds every runtime block with `count` or `for_each`, sorts them,
and resolves the collection where the source makes that possible.

  toggle        the expression yields 0 or 1. A conditional deploy, not a fan
                out, and the census is right to count it as one.
  literal       the collection is written in the template, so the number of
                runtimes is readable.
  undecidable   the collection comes from a variable with no default, or from
                files read at apply time. The count is not in the source, and
                saying one is a guess.

A literal fan out whose block carries a single `role_arn` is a shared
execution role by construction: every runtime it makes takes the same role.

This does not change any published number. Whether two runtimes from one block
are two agents is a question about the claim, not about the parse: a blue and
a green release of one agent are arguably one agent deployed twice, and two
variants with different behaviour are arguably two agents. The rows are here
so that question can be answered on the evidence.

  python3 evaluation/benchmark/foreach_runtime_check.py \\
      --corpus corpus_tier2 --json foreach_runtime_check.json
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from shared_role_source_check import block_of  # noqa: E402

RUNTIME = re.compile(
    r'resource\s+"aws_bedrockagentcore_agent_runtime"\s+"([^"]+)"\s*\{', re.M)
ROLE_ARN = re.compile(r'^\s*role_arn\s*=\s*(.+?)\s*$', re.M)

# `? [1] : []`, `? 1 : 0`, and `? [something] : []`: at most one element either
# way, so the block makes at most one runtime.
TOGGLE = re.compile(
    r'\?\s*(\[[^\[\]]*\]|1|0)\s*:\s*(\[[^\[\]]*\]|1|0)\s*$')

LOCAL_REF = re.compile(r'^(?:toset\()?\s*local\.([A-Za-z0-9_]+)')
VAR_REF = re.compile(r'^(?:toset\()?\s*var\.([A-Za-z0-9_]+)')


def read_all(template_dir):
    """Every .tf file's text, and the whole directory as one blob."""
    files = {}
    for root, _dirs, names in os.walk(template_dir):
        for fn in sorted(names):
            if not fn.endswith(".tf"):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    files[os.path.relpath(path, template_dir)] = fh.read()
            except Exception:
                pass
    return files


def count_entries(body):
    """Top level `key = ...` entries of a literal block body."""
    depth, n = 0, 0
    for line in body.splitlines():
        stripped = line.strip()
        if depth == 1 and re.match(r'^[A-Za-z0-9_"\-]+\s*=', stripped):
            n += 1
        depth += line.count("{") + line.count("[")
        depth -= line.count("}") + line.count("]")
    return n


def resolve_local(files, name):
    """The cardinality of `local.<name>` when it is written out in the source."""
    pat = re.compile(r'^\s*' + re.escape(name) + r'\s*=\s*(\{|\[)', re.M)
    for text in files.values():
        m = pat.search(text)
        if not m:
            continue
        body = block_of(text, m.end()) if m.group(1) == "{" else None
        if body is None:
            return None, "a list literal, not counted here"
        if "for " in body:
            return None, "built by a for expression over something else"
        return count_entries(body), "literal map in the template"
    return None, "not found in this template"


def resolve_var(files, name):
    """A variable's default, when it has one."""
    pat = re.compile(r'variable\s+"' + re.escape(name) + r'"\s*\{', re.M)
    for text in files.values():
        m = pat.search(text)
        if not m:
            continue
        body = block_of(text, m.end())
        if not re.search(r'^\s*default\s*=', body, re.M):
            return None, "a variable with no default, so the caller decides"
        return None, "a variable with a default, not counted here"
    return None, "not found in this template"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus_tier2")
    ap.add_argument("--topology", default="topology_tier2.json")
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    topo_path = (a.topology if os.path.isabs(a.topology)
                 else os.path.join(HERE, a.topology))
    with open(topo_path) as fh:
        topo = {e["t"]: e["n_agents"] for e in json.load(fh)}

    rows = []
    for template, n_census in topo.items():
        d = os.path.join(a.corpus, template)
        if not os.path.isdir(d):
            continue
        files = read_all(d)
        for rel, text in files.items():
            for m in RUNTIME.finditer(text):
                body = block_of(text, m.end())
                expr = kw = None
                for k in ("for_each", "count"):
                    mm = re.search(rf'^\s*{k}\s*=\s*(.+?)\s*$', body, re.M)
                    if mm:
                        kw, expr = k, mm.group(1).strip()
                        break
                if expr is None:
                    continue

                role = ROLE_ARN.search(body)
                if TOGGLE.search(expr):
                    kind, size, how = "toggle", 1, "yields 0 or 1"
                else:
                    lm, vm = LOCAL_REF.match(expr), VAR_REF.match(expr)
                    if lm:
                        size, how = resolve_local(files, lm.group(1))
                    elif vm:
                        size, how = resolve_var(files, vm.group(1))
                    else:
                        size, how = None, "the expression is not a plain " \
                                          "local or variable reference"
                    kind = "literal" if size and size > 1 else "undecidable"

                rows.append({
                    "template": template,
                    "census_n_agents": n_census,
                    "block": m.group(1),
                    "file": rel,
                    "iterator": kw,
                    "expression": expr,
                    "kind": kind,
                    "runtimes_from_this_block": size,
                    "how": how,
                    "role_arn_expression": role.group(1) if role else None,
                })

    kinds = collections.Counter(r["kind"] for r in rows)
    print(f"runtime blocks carrying count or for_each: {len(rows)}")
    for k, v in kinds.most_common():
        print(f"  {v:3}  {k}")

    interesting = [r for r in rows
                   if r["kind"] != "toggle" and r["census_n_agents"] < 2]
    print(f"\nblocks that fan out in a template the census counted as "
          f"single-agent: {len(interesting)}")
    for r in interesting:
        size = r["runtimes_from_this_block"]
        print(f"\n  {r['template']}")
        print(f"    {r['block']}  {r['iterator']} = {r['expression'][:70]}")
        print(f"    {r['kind']}: {r['how']}"
              + (f", {size} runtimes" if size else ""))
        print(f"    role_arn = {r['role_arn_expression']}")

    literal = [r for r in interesting if r["kind"] == "literal"]
    print(f"\n{len(literal)} of them resolve to more than one runtime in the "
          f"source, each under one role_arn expression.")
    print("Whether that is two agents or one agent deployed twice is a "
          "question about the claim, not about the parse.")

    if a.json:
        dst = a.json if os.path.isabs(a.json) else os.path.join(HERE, a.json)
        with open(dst, "w") as fh:
            json.dump({
                "note": ("the shared-role census counts runtime blocks. A "
                         "block with count or for_each creates as many "
                         "runtimes as its collection has elements."),
                "blocks": len(rows),
                "by_kind": dict(kinds),
                "fan_out_in_a_single_agent_template": len(interesting),
                "resolved_to_more_than_one": len(literal),
                "rows": rows,
            }, fh, indent=1)
        print(f"\nwritten: {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

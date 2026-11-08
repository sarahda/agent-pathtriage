#!/usr/bin/env python3
"""The shared-role census counted at the runtime, not at the resource block.

`shared_role.py` counts `aws_bedrockagentcore_agent_runtime` blocks, because
that is what the parser produces: one block is one agent. A block carrying
`for_each` over a collection written in the template creates one runtime per
element, and when its `role_arn` is a single expression with no `each.key`
index, every one of those runtimes takes the same execution role.

So a template can deploy two agents on one role and be counted as one agent.
`foreach_runtime_check.py` finds those, and this pass applies them.

Both numbers are reported. The block count is what the parser saw and it is
what `verify` re-derives; the runtime count is what gets deployed. A reader
can see the adjustment and the templates it came from rather than a single
number that moved.

Only a fan out this pass can resolve from the source is applied. A collection
that comes from a variable or from files read at apply time is left alone and
named, because its size is not in the template and assuming one is the same
mistake in the other direction.

  python3 evaluation/benchmark/shared_role_corrected.py \\
      --json shared_role_corrected.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# A role argument indexed by the iterator gives each runtime its own role, so
# a fan out there is several agents and several roles, not a shared one.
INDEXED = re.compile(r'\[\s*each\.')


def load(name):
    path = os.path.join(HERE, name)
    if not os.path.isfile(path):
        return None
    with open(path) as fh:
        return json.load(fh)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--census", default="shared_role_tier2.json")
    ap.add_argument("--foreach", default="foreach_runtime_check.json")
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    census = load(a.census)
    fo = load(a.foreach)
    if census is None or fo is None:
        print("stop: need both the census and the for_each check")
        return 2

    already = set([e["template"] for e in census["shared_role"]]
                  + list(census.get("distinct_roles", []))
                  + [e["template"] if isinstance(e, dict) else e
                     for e in census.get("undecided", [])])

    added_multi, added_shared, left_alone = [], [], []
    for r in fo["rows"]:
        if r["kind"] == "toggle":
            continue
        t = r["template"]
        n = r.get("runtimes_from_this_block")
        role = r.get("role_arn_expression") or ""
        if r["kind"] != "literal" or not n or n < 2:
            if t not in already:
                left_alone.append({
                    "template": t, "block": r["block"],
                    "expression": r["expression"], "why": r["how"],
                    "role_arn_expression": role})
            continue
        if t in already:
            # the census already calls it multi-agent; the fan out changes how
            # many agents it has, not whether it has two
            continue
        rec = {"template": t, "block": r["block"], "file": r["file"],
               "runtimes": n, "role_arn_expression": role,
               "iterator": f'{r["iterator"]} = {r["expression"]}'}
        added_multi.append(rec)
        if not INDEXED.search(role):
            added_shared.append(rec)

    n_multi_blocks = census["multi_agent_templates"]
    n_shared_blocks = len(census["shared_role"])
    out = {
        "block_level": {
            "multi_agent_templates": n_multi_blocks,
            "templates_sharing_one_execution_role": n_shared_blocks,
            "what_it_counts": ("aws_bedrockagentcore_agent_runtime blocks, "
                               "which is what the parser produces"),
        },
        "runtime_level": {
            "multi_agent_templates": n_multi_blocks + len(added_multi),
            "templates_sharing_one_execution_role":
                n_shared_blocks + len(added_shared),
            "what_it_counts": ("runtimes, so a block that fans out over a "
                               "collection written in the template counts "
                               "once per element"),
        },
        "added_as_multi_agent": added_multi,
        "added_as_sharing_one_role": added_shared,
        "fan_out_left_alone": left_alone,
        "rule": ("a fan out counts only when the collection is written in the "
                 "template. A role argument indexed by the iterator gives "
                 "each runtime its own role and is not a shared one."),
    }

    b, rl = out["block_level"], out["runtime_level"]
    print("                                    blocks   runtimes")
    print(f"  multi-agent templates             {b['multi_agent_templates']:6}"
          f"{rl['multi_agent_templates']:11}")
    print(f"  sharing one execution role        "
          f"{b['templates_sharing_one_execution_role']:6}"
          f"{rl['templates_sharing_one_execution_role']:11}")
    print()
    if added_multi:
        print("added, because one block makes several runtimes:")
        for r in added_multi:
            mark = ("  and they share one role"
                    if r in added_shared else "  each gets its own role")
            print(f"  {r['template']}")
            print(f"    {r['block']}  {r['iterator']}  -> {r['runtimes']} "
                  f"runtimes{mark}")
            print(f"    role_arn = {r['role_arn_expression']}")
    if left_alone:
        print(f"\nleft alone, because the size is not in the template "
              f"({len(left_alone)}):")
        for r in left_alone:
            print(f"  {r['template']}  {r['block']}: {r['why']}")

    if a.json:
        dst = a.json if os.path.isabs(a.json) else os.path.join(HERE, a.json)
        with open(dst, "w") as fh:
            json.dump(out, fh, indent=1)
        print(f"\nwritten: {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

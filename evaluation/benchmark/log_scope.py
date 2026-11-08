#!/usr/bin/env python3
"""Does sharing an execution role go with widening the log group scope?

AWS publishes an AgentCore Runtime execution role in "IAM Permissions for
AgentCore Runtime". Its log group statement is scoped per agent:

    arn:aws:logs:REGION:ACCOUNT:log-group:/aws/bedrock-agentcore/runtimes/agentName-*

and the page says to decide the agent name before creating the role. One role
shared by two agents cannot carry one agent's name, so following the published
template and sharing a role are not both possible: the scope has to widen.

That makes a prediction, and the corpus can check it. Templates that share an
execution role should widen this scope; templates that give each agent its own
role have no such pressure and could keep it narrow.

The grouping is read from the shared role analysis rather than recomputed, so
this measures the same 18 templates that number is reported from.

  python3 log_scope.py --shared evaluation/benchmark/shared_role_tier2.json \\
                       --corpus corpus_tier2 --json log_scope.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

# The segment after runtimes/ decides it. The published form has an agent name
# in front of the wildcard; the widened form is the bare wildcard.
LOGGROUP = re.compile(
    r"log-group:/aws/bedrock-agentcore/runtimes/(?P<tail>[^\"'\s,\]]*)")


def classify(tail: str) -> str:
    t = tail.strip()
    # Strip a trailing log-stream selector, which says nothing about the group.
    t = re.sub(r":log-stream:.*$", "", t)
    if t in ("*", ""):
        return "widened"
    if t == "*:*":
        return "widened"
    return "narrowed"


def template_dirs(entry) -> str:
    return entry if isinstance(entry, str) else entry.get("template", "")


def scan(corpus: pathlib.Path, rel: str):
    """Every log group ARN under one template directory, classified."""
    base = corpus / rel
    found = []
    if not base.is_dir():
        return None, found
    for f in sorted(base.rglob("*.tf")):
        try:
            text = f.read_text(errors="replace")
        except Exception:
            continue
        for m in LOGGROUP.finditer(text):
            found.append({"file": str(f.relative_to(corpus)),
                          "tail": m.group("tail"),
                          "class": classify(m.group("tail"))})
    if not found:
        return "absent", found
    classes = {x["class"] for x in found}
    if classes == {"narrowed"}:
        return "narrowed", found
    if classes == {"widened"}:
        return "widened", found
    return "mixed", found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--shared", required=True, type=pathlib.Path,
                    help="shared_role_tier2.json, for the grouping")
    ap.add_argument("--corpus", required=True, type=pathlib.Path)
    ap.add_argument("--json", type=pathlib.Path)
    args = ap.parse_args()

    data = json.loads(args.shared.read_text())
    groups = {
        "shared_role": [template_dirs(e) for e in data.get("shared_role", [])],
        "distinct_roles": [template_dirs(e) for e in data.get("distinct_roles", [])],
    }
    if not groups["shared_role"] or not groups["distinct_roles"]:
        print("stop: the shared role file has no groups to compare",
              file=sys.stderr)
        return 2

    out = {"published_form": "/aws/bedrock-agentcore/runtimes/agentName-*",
           "source": "AWS, IAM Permissions for AgentCore Runtime",
           "groups": {}}
    for gname, rels in groups.items():
        rows = []
        for rel in rels:
            verdict, found = scan(args.corpus, rel)
            if verdict is None:
                rows.append({"template": rel, "verdict": "not in corpus"})
                continue
            rows.append({"template": rel, "verdict": verdict,
                         "occurrences": len(found),
                         "tails": sorted({x["tail"] for x in found})})
        out["groups"][gname] = rows

    print(f"published form: {out['published_form']}")
    print(f"({out['source']})\n")
    totals = {}
    for gname, rows in out["groups"].items():
        counts = {}
        for r in rows:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        totals[gname] = counts
        print(f"{gname}  ({len(rows)} templates)")
        for r in rows:
            tails = ", ".join(r.get("tails", []))[:70]
            print(f"   {r['verdict']:14} {r['template'][:58]}")
            if tails:
                print(f"   {'':14} tail: {tails}")
        print(f"   -> {counts}\n")

    out["totals"] = totals
    sh = totals.get("shared_role", {})
    di = totals.get("distinct_roles", {})
    print("summary")
    print(f"  shared role    : widened {sh.get('widened',0)}, "
          f"narrowed {sh.get('narrowed',0)}, absent {sh.get('absent',0)}, "
          f"mixed {sh.get('mixed',0)}")
    print(f"  distinct roles : widened {di.get('widened',0)}, "
          f"narrowed {di.get('narrowed',0)}, absent {di.get('absent',0)}, "
          f"mixed {di.get('mixed',0)}")
    if di.get("narrowed", 0) == 0 and di.get("widened", 0) > 0:
        print("\n  Note: templates with their own role per agent widen it too, "
              "so widening is not evidence that sharing caused it. What the "
              "numbers support is that the published narrow form is not used, "
              "not that sharing is why.")
    elif sh.get("narrowed", 0) == 0 and di.get("narrowed", 0) > 0:
        print("\n  Narrowing appears only where each agent has its own role, "
              "which is what the published template's per agent form predicts.")

    if args.json:
        args.json.write_text(json.dumps(out, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

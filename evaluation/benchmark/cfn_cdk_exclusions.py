#!/usr/bin/env python3
"""Apply the deployment-unit rule to the CloudFormation and CDK role census.

The chain analysis already states its rule: a file under a test fixture, a
snapshot directory or a vendored copy is not a deployment and is not counted.
The role sharing census did not apply it, so its counts include test fixtures
and, in one case, the CDK library's own source vendored into a `.venv`. Those
are not deployments and a runtime construct found in them is not someone's
agent.

This pass reads the census artifact, applies the same rule, and writes a
corrected one. Nothing is dropped silently: every excluded unit is named in
the output with the pattern that matched it, and the original count is kept
beside the corrected one.

The fuller fix belongs in `cfn_cdk_runtimes.py`, so a fresh run never produces
the inflated numbers. That needs a re-scan of the whole corpus, so this pass
exists to correct the published numbers without waiting for one, and to give
the producer's fix something to be checked against.

  python3 evaluation/benchmark/cfn_cdk_exclusions.py \
      --census cfn_cdk_cfn_corpus.json --json cfn_cdk_cfn_corpus_excluded.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

# One pattern per reason, so the output can say why a unit was excluded
# rather than only that it was.
RULES = [
    ("vendored dependency",
     re.compile(r'(^|/)(\.venv|venv|site-packages|node_modules|vendor|'
                r'third_party)(/|$)', re.I)),
    ("test fixture or test directory",
     re.compile(r'(^|/)(tests?|__tests__|fixtures?|testdata)(/|$)', re.I)),
    ("build output or snapshot",
     re.compile(r'(^|/)(cdk\.out|snapshots?|\.tox|dist|build)(/|$)', re.I)),
]

LISTS = ("multi", "shared", "undecidable")


def path_of(item):
    if isinstance(item, str):
        return item
    for k in ("directory", "template", "file", "path"):
        if item.get(k):
            return item[k]
    return ""


def reason(path):
    for label, rx in RULES:
        if rx.search(path):
            return label
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--census", required=True)
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    src = a.census if os.path.isabs(a.census) else os.path.join(here, a.census)
    with open(src) as fh:
        census = json.load(fh)

    out = {"source": os.path.basename(src),
           "rule": ("a unit under a vendored dependency, a test directory or "
                    "a build output is not a deployment. This is the rule the "
                    "chain analysis already applies to its denominator."),
           "sections": {}}

    for sect in ("cloudformation", "cdk"):
        if sect not in census:
            continue
        s = census[sect]
        rec = {"unit": s.get("unit"), "counts": {}, "excluded": []}
        for key in LISTS:
            items = s.get(key)
            if items is None:
                continue
            kept, dropped = [], []
            for item in items:
                p = path_of(item)
                why = reason(p)
                if why:
                    dropped.append({"list": key, "path": p, "reason": why})
                else:
                    kept.append(item)
            rec["counts"][key] = {"before": len(items), "after": len(kept),
                                  "excluded": len(dropped)}
            rec["excluded"].extend(dropped)
            rec[f"{key}_after"] = kept

        # the scalar counters that travel with the lists
        for scalar, key in (("templates_with_two_or_more", "multi"),
                            ("templates_sharing_a_role", "shared"),
                            ("templates_undecidable", "undecidable"),
                            ("directories_with_two_or_more", "multi"),
                            ("directories_sharing_a_role", "shared"),
                            ("directories_undecidable", "undecidable")):
            if scalar in s and key in rec["counts"]:
                rec["counts"].setdefault("scalars", {})[scalar] = {
                    "published": s[scalar],
                    "corrected": rec["counts"][key]["after"],
                }
        out["sections"][sect] = rec

    for sect, rec in out["sections"].items():
        print(f"[{sect}]  unit: {rec['unit']}")
        for key in LISTS:
            c = rec["counts"].get(key)
            if not c:
                continue
            arrow = "" if c["before"] == c["after"] else "   <-- changed"
            print(f"   {key:12} {c['before']:4} -> {c['after']:4}"
                  f"   excluded {c['excluded']}{arrow}")
        for d in rec["excluded"]:
            print(f"      [{d['list']}] {d['reason']}: {d['path']}")
        print()

    if a.json:
        dst = a.json if os.path.isabs(a.json) else os.path.join(here, a.json)
        with open(dst, "w") as fh:
            json.dump(out, fh, indent=1)
        print(f"written: {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

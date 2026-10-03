#!/usr/bin/env python3
"""
S1 pilot driver - run extract_static.scan_template at TEMPLATE granularity over a
corpus of cloned vendor-official repos.

Unit = a Terraform directory: any dir DIRECTLY containing >=1 *.tf (excluding
.terraform/). This is the deployable-module unit; submodules under modules/ are
counted too and flagged, so inflation is visible, not hidden. Each dir is scored on
its OWN .tf only (recursive=False), so units are disjoint. Bicep / CloudFormation
are out of this pilot's scope (HCL only) and reported as a coverage gap.

Usage:
    python3 scan_s1.py --root /tmp/corpus_s1 --json s1_prevalence.json
"""
import argparse, json, os, glob, collections
from extract_static import scan_template


def tf_dirs(repo):
    seen = set()
    for p in glob.glob(os.path.join(repo, "**", "*.tf"), recursive=True):
        if os.sep + ".terraform" + os.sep in p:
            continue
        seen.add(os.path.dirname(p))
    return sorted(seen)


def is_submodule(repo, d):
    rel = os.path.relpath(d, repo)
    return ("modules" + os.sep) in (rel + os.sep) or (os.sep + "modules" + os.sep) in (os.sep + rel + os.sep)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--json", default="s1_prevalence.json")
    a = ap.parse_args()

    repos = sorted(d for d in glob.glob(os.path.join(a.root, "*")) if os.path.isdir(d))
    rows = []
    per_repo = collections.OrderedDict()
    for repo in repos:
        rn = os.path.basename(repo)
        rc = {"templates": 0, "delegation": 0, "overprivilege_classic": 0,
              "overprivilege_agentic": 0, "chainable_classic": 0, "chainable_agentic": 0,
              "chainable": 0, "wildcard_passrole": 0, "submodule": 0, "parse_errors": 0}
        for d in tf_dirs(repo):
            f = scan_template(d, recursive=False)
            if f["files"] == 0:
                continue
            f["template"] = f"{rn}/{os.path.relpath(d, repo)}"
            f["is_submodule"] = is_submodule(repo, d)
            rows.append(f)
            rc["templates"] += 1
            for k in ("delegation", "overprivilege_classic", "overprivilege_agentic",
                      "chainable_classic", "chainable_agentic", "chainable", "parse_errors"):
                rc[k] += int(f[k]) if isinstance(f[k], bool) else f[k]
            rc["wildcard_passrole"] += int(f["has_wildcard_passrole"])
            rc["submodule"] += int(f["is_submodule"])
        if rc["templates"]:
            per_repo[rn] = rc

    n = len(rows)
    roots = [r for r in rows if not r["is_submodule"]]

    def pct(rowset, key):
        c = sum(1 for r in rowset if r[key])
        return c, (100.0 * c / len(rowset) if rowset else 0.0)

    print("=== S1 (vendor-official) static pilot - Terraform templates ===")
    print(f"corpus repos: {len(per_repo)}   tf templates (dirs): {n}   (root modules: {len(roots)}, submodules: {n-len(roots)})\n")
    print("per-repo (templates / delegation / chain-classic / chain-agentic):")
    for rn, rc in per_repo.items():
        print(f"  {rn:52s} t={rc['templates']:<4d} deleg={rc['delegation']:<4d} chainC={rc['chainable_classic']:<3d} chainA={rc['chainable_agentic']}")
    print()
    for label, rs in (("ALL templates", rows), ("ROOT modules only", roots)):
        print(f"[{label}]  n={len(rs)}")
        for k in ("delegation", "overprivilege_classic", "overprivilege_agentic",
                  "chainable_classic", "chainable_agentic", "chainable", "has_wildcard_passrole"):
            c, p = pct(rs, k)
            print(f"    {k:24s}: {c}/{len(rs)}  ({p:.1f}%)")
    print(f"\n  parse errors (fail-closed, counted as no-finding): {sum(r['parse_errors'] for r in rows)}")
    json.dump({"n": n, "root_modules": len(roots), "per_repo": per_repo, "rows": rows},
              open(a.json, "w"), indent=2)
    print(f"written: {a.json}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
C1 feasibility sizing: of the wired-recovered agent templates, how many ship agent
container source (.py) in the same repo? This is the code-colocation rate, the
number that gates whether code-based action-level extraction (C1) is a headline
result or a case study. Run from the repo root.

    python3 codecolo_check.py --gap evaluation/benchmark/gap_tier2.json --corpus corpus_tier2
"""
import json, os, glob, argparse

def walk(repo_dir):
    pys, dockers, reqs = [], [], []
    for p in glob.glob(os.path.join(repo_dir, "**", "*"), recursive=True):
        if os.sep + ".terraform" + os.sep in p or os.sep + ".git" + os.sep in p:
            continue
        b = os.path.basename(p)
        if os.path.isfile(p) and p.endswith(".py"):
            pys.append(os.path.normpath(p))
        if b == "Dockerfile":
            dockers.append(os.path.normpath(p))
        if b in ("requirements.txt", "pyproject.toml"):
            reqs.append(os.path.normpath(p))
    return pys, dockers, reqs

def under(root, path):
    root = os.path.normpath(root)
    try:
        return os.path.commonpath([root, path]) == root
    except ValueError:
        return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gap", default="evaluation/benchmark/gap_tier2.json")
    ap.add_argument("--corpus", default="corpus_tier2")
    a = ap.parse_args()

    d = json.load(open(a.gap))
    rows = [r for r in d["rows"] if r.get("wired_recovered")]
    strong, medium, weak, none = [], [], [], []
    for r in rows:
        tmpl = r["template"]
        repo = tmpl.split("/")[0]
        repo_dir = os.path.join(a.corpus, repo)
        tdir = os.path.join(a.corpus, tmpl)
        pys, dockers, reqs = walk(repo_dir)
        # colocated: a .py under the Dockerfile dir, the template dir, or its parent
        roots = [os.path.dirname(x) for x in dockers] + [tdir, os.path.dirname(tdir)]
        coloc = any(under(rt, py) for rt in roots for py in pys)
        if pys and dockers and coloc:
            strong.append(tmpl)
        elif pys and coloc:
            medium.append(tmpl)
        elif pys:
            weak.append(tmpl)
        else:
            none.append(tmpl)

    n = len(rows)
    code_avail = len(strong) + len(medium)
    print(f"wired-recovered templates: {n}")
    print(f"  strong (Dockerfile + colocated .py): {len(strong)}  <- best C1 candidates")
    print(f"  medium (colocated .py, no Dockerfile): {len(medium)}")
    print(f"  weak   (.py elsewhere in repo):        {len(weak)}")
    print(f"  none   (no .py in repo):               {len(none)}")
    if n:
        print(f"  => code-colocated subset (strong+medium): {code_avail}/{n} ({100.0*code_avail/n:.0f}%)")
    print("\nstrong candidates (start C1 here):")
    for t in strong:
        print("  " + t)
    print("\nmedium candidates:")
    for t in medium:
        print("  " + t)

if __name__ == "__main__":
    main()

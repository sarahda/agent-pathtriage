#!/usr/bin/env python3
"""
External benchmark runner (IAM Vulnerable, BishopFox).

Scores the real single-hop `check` and multi-hop `propagate` against the
benchmark's documented ground truth, over ALL principals (roles AND users).

Ground truth (independent of the tool):
  - "escalating"     : documented escalation entry principals that SHOULD be flagged
  - "safe"           : documented non-exploitable principals that should NOT be flagged
  - everything else  : out of scope (single-principal policy self-mod, credential
                       creation, group membership); excluded from scoring

Reports recall (on escalating) and precision (on escalating + safe) for each mode.
The headline is the recall gap: single-hop cannot see multi-hop delegation, so it
misses the PassRole and AssumeRole-chain entries that propagate recovers.

Usage:
  python3 run_benchmark.py --graph iam_graph.json --truth ground_truth.json
"""
import argparse, json, sys
sys.path.insert(0, "../../agentpathtriage")   # so check.py / propagate.py import
import check as CK, propagate as PR


def principals(G):
    return [n for n, d in G.nodes(data=True) if d.get("kind") in ("role", "user")]

def esc_single(G, p):
    return len(CK.witnesses_for(G, p)) > 0

def esc_multi(G, p):
    return PR.analyse(G, p)["Esc_multi"] if p in G else False

def metrics(flagged, esc, safe):
    tp = len(flagged & esc); fp = len(flagged & safe); fn = len(esc - flagged)
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    return tp, fp, fn, prec, rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", required=True)
    ap.add_argument("--truth", required=True)
    a = ap.parse_args()
    G = PR.load_graph(a.graph)
    gt = json.load(open(a.truth))
    esc = set(gt["escalating"]); safe = set(gt.get("safe", []))
    inscope = esc | safe
    present = set(principals(G))

    missing = sorted(inscope - present)
    if missing:
        print(f"[!] {len(missing)} ground-truth principals not found in graph "
              f"(name mismatch or not deployed): {missing}\n")

    single = {p for p in present & inscope if esc_single(G, p)}
    multi  = {p for p in present & inscope if esc_multi(G, p)}

    print(f"{'principal':52s} | single | multi | truth")
    print("-" * 82)
    for p in sorted(present & inscope):
        label = "ESC" if p in esc else "safe"
        print(f"  {p:50s} | {str(esc_single(G,p)):5s}  | {str(esc_multi(G,p)):5s} | {label}")

    print()
    for mode, flagged in (("single-hop (check)    ", single), ("multi-hop  (propagate)", multi)):
        tp, fp, fn, prec, rec = metrics(flagged, esc & present, safe & present)
        print(f"{mode}: recall={rec:.3f}  precision={prec:.3f}   (TP={tp} FP={fp} FN={fn})")

    recovered = sorted((multi & esc) - single)
    print(f"\nRecovered ONLY by propagate (single-hop missed): {recovered}")
    n_oos = len(present) - len(present & inscope)
    print(f"Out-of-scope principals excluded from scoring: {n_oos}")

    out = {"single_hop_recall": len(single & esc)/len(esc & present) if esc & present else 1.0,
           "multi_hop_recall": len(multi & esc)/len(esc & present) if esc & present else 1.0,
           "recovered_by_propagate": recovered,
           "escalating": sorted(esc), "safe": sorted(safe),
           "flagged_single": sorted(single), "flagged_multi": sorted(multi)}
    json.dump(out, open("benchmark_results.json", "w"), indent=2)
    print("\nwritten: benchmark_results.json")


if __name__ == "__main__":
    main()

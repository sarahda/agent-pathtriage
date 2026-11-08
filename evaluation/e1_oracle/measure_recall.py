#!/usr/bin/env python3
"""
E1 recall: does `check` recover the documented oracle paths from the graph alone?

Oracle = the third-party documented AgentCore paths (Mitigant / Unit 42). Each
oracle path corresponds to a specific cross-agent resource type an over-privileged
role should be able to reach. We do NOT tell `check` which paths exist; we run it
on the extracted graph and see which oracle resource types show up as witnesses.

    recall = (oracle paths whose witness check found) / (oracle paths total)

Honest by construction: if extract missed an edge, check cannot invent it, so a
miss lowers recall rather than being hidden.
"""
import json, sys

# Documented oracle -> the resource-type node its witness should reach.
ORACLE = {
    "P1 ECR image exfiltration (Mitigant)":      "ECR images",
    "P2 memory access + poisoning (Mitigant)":   "Agent memory",
    "P3 code interpreter escalation (Mitigant)": "Code interpreters",
    "P4 runtime hijack (Mitigant)":              "Agent runtimes",
    "Unit42 God-Mode invoke-any-runtime":        "Agent runtimes",
}


def main():
    if len(sys.argv) < 2:
        print("usage: measure_recall.py check_results.json"); sys.exit(2)
    results = json.load(open(sys.argv[1]))

    reached = set()
    for r in results:
        for w in r.get("witnesses", []):
            reached.add(w["reaches"])

    rows, found = [], 0
    for path, res_type in ORACLE.items():
        hit = res_type in reached
        found += hit
        rows.append((path, res_type, hit))

    print("E1 recall against the documented oracle\n")
    for path, res_type, hit in rows:
        print(f"  [{'FOUND' if hit else 'miss '}] {path}  ->  {res_type}")
    recall = found / len(ORACLE)
    print(f"\nrecall = {found} / {len(ORACLE)} = {recall:.2f}")
    print("(a miss means extract did not recover that edge, not that check hid it)")

    json.dump({"recall": recall, "found": found, "total": len(ORACLE),
               "detail": [{"path": p, "resource": rt, "found": h} for p, rt, h in rows]},
              open("recall.json", "w"), indent=2)
    print("written: recall.json")


if __name__ == "__main__":
    main()

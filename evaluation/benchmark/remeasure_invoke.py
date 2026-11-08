#!/usr/bin/env python3
"""The same corpus, with and without invocation reach, side by side.

A rule change that moves a headline figure has to be reported as a before and
an after on identical input, or a reader cannot tell the change from the data.
This runs every multi-agent project twice, once with `delegate` edges alone
and once with permitted hand-off edges as well, and prints what moved.

What it is careful about. The agent and data split applies in both runs, so
the two columns differ only by whether invocation is followed. Projects that
fail to parse are named rather than dropped, because a project missing from
both columns silently shrinks the denominator the bound is computed over.

  python3 remeasure_invoke.py --corpus corpus_tier2 \\
      --topology evaluation/benchmark/topology_tier2.json \\
      --json evaluation/benchmark/invoke_reach_tier2.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
PKG = HERE.parent.parent / "agentpathtriage"
TF_TO_STATE = HERE / "tf_to_state.py"
sys.path.insert(0, str(PKG))


def bound(n: int, conf: float = 0.95) -> float:
    return (1 - (1 - conf) ** (1.0 / n)) * 100 if n > 0 else 100.0


def analyse(state, invoke: bool):
    """Run the predicate once, with invocation reach on or off."""
    import extract_graph as X
    import reach as R
    R.INVOKE_REACH = invoke
    try:
        G, ix = X.build(state)
        R.enable_delegations(G, ix)
        universe = R.build_universe(ix)
        cache = {}
        return [R.analyse(G, ix, p, universe, cache) for p in sorted(ix.kind)]
    finally:
        R.INVOKE_REACH = False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, type=pathlib.Path)
    ap.add_argument("--topology", required=True, type=pathlib.Path)
    ap.add_argument("--json", type=pathlib.Path)
    a = ap.parse_args()

    import reach as R
    if not hasattr(R, "INVOKE_REACH"):
        print("stop: reach.py has no INVOKE_REACH. Apply "
              "_scratch/tomorrow_01_invoke_reach.py first.", file=sys.stderr)
        return 2

    topo = json.loads(a.topology.read_text())
    multi = [t for t in topo if (t.get("n_agents") or 0) >= 2]
    rows, failed = [], []

    with tempfile.TemporaryDirectory() as tmp:
        st = pathlib.Path(tmp) / "s.json"
        for i, t in enumerate(multi, 1):
            rel = t["t"]
            d = a.corpus / rel
            if not d.is_dir():
                failed.append({"project": rel, "why": "not in the corpus"})
                continue
            p = subprocess.run(
                [sys.executable, str(TF_TO_STATE), "--tfdir", str(d),
                 "--json", str(st)], capture_output=True, text=True)
            if p.returncode != 0 or not st.exists():
                failed.append({"project": rel, "why": "did not parse"})
                continue
            state = json.loads(st.read_text())
            try:
                off = analyse(state, False)
                on = analyse(state, True)
            except Exception as e:
                failed.append({"project": rel,
                               "why": f"{type(e).__name__}: {e}"})
                continue

            esc_off = sorted(r["principal"] for r in off if r["Esc"])
            esc_on = sorted(r["principal"] for r in on if r["Esc"])
            new = [r for r in on
                   if r["Esc"] and r["principal"] not in esc_off]
            rows.append({
                "project": rel,
                "esc_without_invocation": esc_off,
                "esc_with_invocation": esc_on,
                "changed": esc_off != esc_on,
                "new_escalations": [
                    {"principal": r["principal"],
                     "agents_reached": r.get("agents_reached", []),
                     "witnesses": r["witnesses"][:4]} for r in new],
            })
            mark = "  <-- changed" if esc_off != esc_on else ""
            print(f"[{i}/{len(multi)}] {len(esc_off)} -> {len(esc_on)}  "
                  f"{rel}{mark}")

    n = len(rows)
    off_total = sum(1 for r in rows if r["esc_without_invocation"])
    on_total = sum(1 for r in rows if r["esc_with_invocation"])
    changed = [r for r in rows if r["changed"]]

    out = {
        "corpus": str(a.corpus),
        "projects_with_two_or_more_agents": len(multi),
        "projects_measured": n,
        "projects_failed": len(failed),
        "failed": failed,
        "projects_with_an_escalation": {
            "identity_borrowing_only": off_total,
            "including_invocation": on_total,
        },
        "changed": changed,
        "bound_95_percent": {
            "identity_borrowing_only":
                round(bound(n), 1) if off_total == 0 else None,
            "including_invocation":
                round(bound(n), 1) if on_total == 0 else None,
        },
        "note": "the agent and data split applies in both columns, so the "
                "two differ only by whether permitted hand-off edges are "
                "followed.",
        "rows": rows,
    }

    print()
    print(f"projects measured                      {n}")
    print(f"  with an escalation, identity only    {off_total}")
    print(f"  with an escalation, incl. invocation {on_total}")
    print(f"  projects whose verdict moved         {len(changed)}")
    if failed:
        print(f"  could not be measured                {len(failed)}")
        for f in failed[:5]:
            print(f"      {f['project']}: {f['why']}")
    print()
    if changed:
        print("the verdict moved on:")
        for r in changed:
            print(f"  {r['project']}")
            for e in r["new_escalations"]:
                for w in e["witnesses"]:
                    via = " via invocation" if w.get("via_invocation") else ""
                    print(f"      {e['principal']} reaches {w['reaches']}{via}")
        print()
        print("Each of these needs a hand verdict before it is a finding. "
              "The question for each is whether what is reached is worth "
              "reaching: a sibling's container image repository is a real "
              "difference in reach and a thin one, and the paper should say "
              "which it thinks it is rather than let the count speak.")
    else:
        print("Nothing moved. The headline figure does not depend on which "
              "edges the predicate walks, and the finding is only that the "
              "prose called it hand-off when it measured identity borrowing.")

    if a.json:
        a.json.write_text(json.dumps(out, indent=2))
        print(f"\nwrote {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""What changes when AWS managed policies are expanded.

Four runs on identical input: invocation reach off or on, crossed with managed
policy expansion off or on. Reporting the grid rather than one number is the
point, because each axis was added after figures were published and a reader
has to be able to tell the rule change from the data.

The check that matters first is whether expansion bites at all. A role that
attaches BedrockAgentCoreFullAccess must gain statements, and if auth does not
grow for any principal then the snapshot is not reaching the evaluator and
every number below would be the old one under a new name. That is reported
before the verdicts.

  python3 evaluation/benchmark/managed_expansion_impact.py \
      --corpus corpus_tier2 \
      --topology evaluation/benchmark/topology_tier2.json \
      --snapshot agentpathtriage/data/aws_managed_policies.json \
      --json evaluation/benchmark/managed_expansion_tier2.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "agentpathtriage"))
TF_TO_STATE = HERE / "tf_to_state.py"


def bound(n: int, conf: float = 0.95) -> float:
    return (1 - (1 - conf) ** (1.0 / n)) * 100 if n > 0 else 100.0


def analyse(state, invoke: bool, managed):
    import extract_graph as X
    import reach as R
    R.INVOKE_REACH = invoke
    try:
        G, ix = X.build(state, managed)
        R.enable_delegations(G, ix)
        universe = R.build_universe(ix)
        cache = {}
        rows = [R.analyse(G, ix, p, universe, cache) for p in sorted(ix.kind)]
        return rows, ix
    finally:
        R.INVOKE_REACH = False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, type=pathlib.Path)
    ap.add_argument("--topology", required=True, type=pathlib.Path)
    ap.add_argument("--snapshot", required=True, type=pathlib.Path)
    ap.add_argument("--min-agents", type=int, default=2)
    ap.add_argument("--json", type=pathlib.Path)
    a = ap.parse_args()

    import managed_policies as MP
    snap = MP.load(a.snapshot, required=True)
    managed = snap.statements
    print(f"snapshot: {snap.describe()}")

    topo = json.loads(a.topology.read_text())
    sel = [t for t in topo if (t.get("n_agents") or 0) >= a.min_agents]
    print(f"configurations with {a.min_agents} or more agents: {len(sel)}\n")

    MODES = [("identity only, inline policies only", False, False),
             ("identity only, managed expanded", False, True),
             ("with invocation, inline policies only", True, False),
             ("with invocation, managed expanded", True, True)]

    rows, failed = [], []
    auth_grew = 0
    principals_seen = 0

    with tempfile.TemporaryDirectory() as tmp:
        st = pathlib.Path(tmp) / "s.json"
        for i, t in enumerate(sel, 1):
            rel = t["t"]
            d = a.corpus / rel
            if not d.is_dir():
                failed.append({"config": rel, "why": "not in the corpus"})
                continue
            p = subprocess.run(
                [sys.executable, str(TF_TO_STATE), "--tfdir", str(d),
                 "--json", str(st)], capture_output=True, text=True)
            if p.returncode != 0 or not st.exists():
                failed.append({"config": rel, "why": "did not parse"})
                continue
            state = json.loads(st.read_text())

            out, auth_by_mode = {}, {}
            try:
                for label, inv, exp in MODES:
                    r, _ix = analyse(state, inv, managed if exp else None)
                    out[label] = sorted(x["principal"] for x in r if x["Esc"])
                    auth_by_mode[label] = {x["principal"]: x["n_auth"]
                                           for x in r}
            except Exception as e:
                failed.append({"config": rel, "why": f"{type(e).__name__}: {e}"})
                continue

            base = auth_by_mode[MODES[0][0]]
            withx = auth_by_mode[MODES[1][0]]
            grew = {k: (base[k], withx[k]) for k in base
                    if withx.get(k, 0) > base[k]}
            principals_seen += len(base)
            auth_grew += len(grew)

            moved = {}
            for label, _i, _e in MODES[1:]:
                if out[label] != out[MODES[0][0]]:
                    moved[label] = out[label]

            rows.append({"config": rel, "n_agents": t.get("n_agents"),
                         "esc_by_mode": out,
                         "principals_whose_auth_grew_under_expansion":
                             {k: {"before": v[0], "after": v[1]}
                              for k, v in grew.items()},
                         "modes_that_differ_from_the_baseline": sorted(moved)})

            tag = "  <-- moved" if moved else ""
            print(f"[{i}/{len(sel)}] "
                  + " ".join(f"{len(out[l]):2d}" for l, _x, _y in MODES)
                  + f"   auth grew for {len(grew)}/{len(base)}   {rel}{tag}")

    print()
    print("Does expansion bite at all")
    print(f"  principals examined                         {principals_seen}")
    print(f"  principals whose authorised set grew        {auth_grew}")
    if auth_grew == 0:
        print("  STOP: expansion changed nothing, so the snapshot is not")
        print("  reaching the evaluator and the verdicts below are the old")
        print("  numbers under a new name.")
    print()
    n = len(rows)
    print(f"{'mode':44s} {'configs with an Esc':>20s} {'95% bound':>10s}")
    print("-" * 78)
    totals = {}
    for label, _i, _e in MODES:
        k = sum(1 for r in rows if r["esc_by_mode"][label])
        totals[label] = k
        b = f"{bound(n):.1f}%" if k == 0 else "n/a"
        print(f"{label:44s} {k:20d} {b:>10s}")
    print()
    movers = [r for r in rows if r["modes_that_differ_from_the_baseline"]]
    if movers:
        print("configurations whose verdict depends on the mode:")
        for r in movers:
            print(f"  {r['config']}")
            for label, _i, _e in MODES:
                print(f"      {label:42s} {r['esc_by_mode'][label]}")
    else:
        print("no configuration's verdict depends on the mode.")
    if failed:
        print()
        print(f"{len(failed)} configuration(s) could not be measured:")
        for f in failed[:6]:
            print(f"  {f['config']}: {f['why']}")

    if a.json:
        a.json.write_text(json.dumps({
            "snapshot": snap.describe(),
            "snapshot_path": str(a.snapshot),
            "configurations_selected": len(sel),
            "configurations_measured": n,
            "configurations_failed": len(failed),
            "failed": failed,
            "principals_examined": principals_seen,
            "principals_whose_auth_grew_under_expansion": auth_grew,
            "configs_with_an_escalation_by_mode": totals,
            "bound_95_percent_when_zero": round(bound(n), 1),
            "rows": rows,
            "limit": "the snapshot expands the AWS managed policies the corpus "
                     "names, except any listed as absent from AWS. A policy "
                     "not expanded is still reported by unreadable_managed, so "
                     "an escalation into a role carrying one is recorded with "
                     "its extent unmeasured rather than dropped.",
        }, indent=2))
        print(f"\nwrote {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

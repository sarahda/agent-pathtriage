"""The whole corpus under the sound takeover rule, with and without managed policies.

Two questions in one walk, because they need the same parse.

One. How many configurations hold a cross agent escalation once AWS managed
policies are expanded and the takeover rule requires what AWS says the call
requires. Reported with and without expansion on identical input, and with the
gain split into resources the configuration writes and resources synthesised to
probe how broad a grant is.

Two. How close the blocked ones are. A takeover candidate that fails only on
iam:PassRole is one permission away from cross agent code execution, which is a
different statement from nothing being there. Those are counted by what they
are missing, and the configurations where a role does hold a PassRole wide
enough to cover a sibling agent's role are named, because that is the set where
the chain completes.

Resumable. Each run appends to a jsonl cache and stops at a time budget, so a
long walk survives being interrupted. Run it again to continue; delete the
cache to start over.

  python3 evaluation/benchmark/corpus_takeover_census.py \\
      --corpus corpus_tier2 \\
      --topology evaluation/benchmark/topology_tier2.json \\
      --snapshot agentpathtriage/data/aws_managed_policies.json \\
      --json evaluation/benchmark/corpus_takeover_census.json --budget 150
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "agentpathtriage"))
TF_TO_STATE = HERE / "tf_to_state.py"


def bound(n, conf=0.95):
    return (1 - (1 - conf) ** (1.0 / n)) * 100 if n > 0 else 100.0


def one(state, managed):
    import extract_graph as X
    import reach as R
    G, ix = X.build(state, managed)
    R.enable_delegations(G, ix)
    universe = R.build_universe(ix)
    cache = {}
    rows = [R.analyse(G, ix, p, universe, cache) for p in sorted(ix.kind)]
    takeover = [{"from": a, "to": b, "via": d.get("via"),
                 "resource": d.get("takeover_resource"),
                 "exec_control_verified": d.get("exec_control_verified"),
                 "evidence": d.get("exec_control_evidence")}
                for a, b, d in G.edges(data=True)
                if d.get("rel") == "delegate"
                and "takeover" in str(d.get("via", ""))]
    return rows, takeover, (G.graph.get("blocked_takeovers") or []), ix


def passrole_reach(ix):
    """Roles that may pass another agent's role to the agent service.

    This is the grant that completes a blocked takeover, so the set is reported
    even where no takeover candidate exists: it is the precondition, and a
    deployment that has it is one misconfiguration away rather than two.
    """
    import iam_eval as E
    agent_roles = set()
    for meta in ix.agents.values():
        ref = meta.get("role_arn")
        if ref:
            agent_roles.add(ix._owner_name(ref))
    out = []
    for p in sorted(ix.kind):
        stmts = ix.statements(p)
        if not stmts:
            continue
        for tgt in sorted(agent_roles):
            if tgt == p or tgt not in ix.kind:
                continue
            arn = ix.arn.get(tgt) or f"arn:aws:iam::{ix.account}:role/{tgt}"
            d = E.evaluate(stmts, "iam:PassRole", arn)
            if d.allowed:
                out.append({"principal": p, "can_pass": tgt,
                            "conditional": d.conditional})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, type=pathlib.Path)
    ap.add_argument("--topology", required=True, type=pathlib.Path)
    ap.add_argument("--snapshot", required=True, type=pathlib.Path)
    ap.add_argument("--json", required=True, type=pathlib.Path)
    ap.add_argument("--budget", type=float, default=150.0)
    # Shards let several processes walk disjoint slices at once, each with its
    # own cache file, which the aggregation below reads back together. The
    # corpus is independent per configuration, so this is throughput only and
    # changes no result.
    ap.add_argument("--shard", default="", metavar="I/N")
    a = ap.parse_args()

    import managed_policies as MP
    snap = MP.load(a.snapshot, required=True)

    shard_i, shard_n = 0, 1
    if a.shard:
        shard_i, shard_n = (int(x) for x in a.shard.split("/"))
    cache_path = (a.json.with_suffix(f".shard{shard_i}.jsonl") if a.shard
                  else a.json.with_suffix(".jsonl"))

    # Every shard's results are read for the aggregate, so a partial walk still
    # reports over everything measured so far rather than over one slice.
    done = {}
    for f in sorted(a.json.parent.glob(a.json.stem + "*.jsonl")):
        for line in f.read_text().splitlines():
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("config"):
                done[r["config"]] = r

    topo = json.loads(a.topology.read_text())
    mine = [t for i, t in enumerate(topo) if i % shard_n == shard_i]
    todo = [t for t in mine if t["t"] not in done]
    print(f"configurations: {len(topo)}   already done: {len(done)}   "
          f"to do now: {len(todo)}")

    started = time.time()
    processed = 0
    with cache_path.open("a") as cf, tempfile.TemporaryDirectory() as tmp:
        st = pathlib.Path(tmp) / "s.json"
        for t in todo:
            if time.time() - started > a.budget:
                print(f"time budget reached after {processed} more; run again "
                      f"to continue")
                break
            rel = t["t"]
            rec = {"config": rel, "n_agents": t.get("n_agents") or 0}
            d = a.corpus / rel
            if not d.is_dir():
                rec["error"] = "not in the corpus"
            else:
                p = subprocess.run(
                    [sys.executable, str(TF_TO_STATE), "--tfdir", str(d),
                     "--json", str(st)], capture_output=True, text=True)
                if p.returncode != 0 or not st.exists():
                    rec["error"] = "did not parse"
                else:
                    try:
                        state = json.loads(st.read_text())
                        for label, man in (("inline", None),
                                           ("expanded", snap.statements)):
                            rows, tk, blocked, ix = one(state, man)
                            rec[label] = {
                                "principals": len(rows),
                                "esc": sorted(r["principal"] for r in rows
                                              if r["Esc"]),
                                "esc_with_literal_gain": sorted(
                                    r["principal"] for r in rows
                                    if r["Esc"] and r["n_gained_literal"] > 0),
                                "takeover_edges": tk,
                                "blocked_takeovers": blocked,
                            }
                            if label == "expanded":
                                rec["passrole_to_agent_role"] = passrole_reach(ix)
                    except Exception as e:
                        rec["error"] = f"{type(e).__name__}: {e}"
            cf.write(json.dumps(rec) + "\n")
            cf.flush()
            done[rel] = rec
            processed += 1
            mark = ""
            if rec.get("expanded", {}).get("esc_with_literal_gain"):
                mark = "  <-- escalation with a real resource gained"
            print(f"  [{len(done)}/{len(topo)}] {rel}{mark}")

    rows = [r for r in done.values() if not r.get("error")]
    failed = [r for r in done.values() if r.get("error")]
    n = len(rows)
    out = {
        "snapshot": snap.describe(),
        "configurations_in_topology": len(topo),
        "configurations_measured": n,
        "configurations_failed": len(failed),
        "failed": [{"config": r["config"], "error": r["error"]} for r in failed],
        "complete": len(done) == len(topo),
    }
    for label in ("inline", "expanded"):
        got = [r for r in rows if label in r]
        any_esc = [r for r in got if r[label]["esc"]]
        lit_esc = [r for r in got if r[label]["esc_with_literal_gain"]]
        tk = [r for r in got if r[label]["takeover_edges"]]
        # Keep which config each blocked candidate came from. Writing only the
        # count left the 26 with nothing to check them against, which is the
        # same shape of mistake as computing a breakdown and not writing it.
        blocked = [dict(b, config=r["config"], n_agents=r.get("n_agents"))
                   for r in got for b in r[label]["blocked_takeovers"]]
        by_missing = {}
        for b in blocked:
            k = ", ".join(b["missing_dependent_actions"])
            by_missing[k] = by_missing.get(k, 0) + 1
        out[label] = {
            "configurations": len(got),
            "with_an_escalation": len(any_esc),
            "with_an_escalation_gaining_a_resource_the_config_writes": len(lit_esc),
            "with_a_surviving_takeover_edge": len(tk),
            "blocked_takeover_candidates": len(blocked),
            "blocked_by": by_missing,
            "blocked_detail": blocked,
            "configs_with_a_blocked_candidate":
                len([r for r in got if r[label]["blocked_takeovers"]]),
            "bound_95_percent_if_zero":
                round(bound(len(got)), 1) if not lit_esc else None,
            "escalating_configs": [
                {"config": r["config"], "n_agents": r["n_agents"],
                 "esc": r[label]["esc"],
                 "esc_with_literal_gain": r[label]["esc_with_literal_gain"]}
                for r in any_esc],
        }
    pr = [r for r in rows if r.get("passrole_to_agent_role")]
    out["passrole_wide_enough_to_cover_a_sibling_agent_role"] = {
        "configurations": len(pr),
        "detail": [{"config": r["config"], "n_agents": r["n_agents"],
                    "grants": r["passrole_to_agent_role"]} for r in pr],
        "why_it_matters": "a takeover candidate blocked only on iam:PassRole "
                          "becomes usable in a deployment that also grants "
                          "PassRole over the sibling's role, so this is the set "
                          "where the chain completes.",
    }
    a.json.write_text(json.dumps(out, indent=2))

    print()
    print(f"measured {n} of {len(topo)}   complete: {out['complete']}")
    for label in ("inline", "expanded"):
        o = out[label]
        print(f"  {label:9s} esc {o['with_an_escalation']:3d}   "
              f"esc gaining a real resource {o['with_an_escalation_gaining_a_resource_the_config_writes']:3d}   "
              f"takeover edges {o['with_a_surviving_takeover_edge']:3d}   "
              f"blocked candidates {o['blocked_takeover_candidates']:3d}")
        if o["blocked_by"]:
            for k, v in sorted(o["blocked_by"].items(), key=lambda x: -x[1]):
                print(f"      blocked by {k}: {v}")
    print(f"  configurations granting PassRole over a sibling agent role: "
          f"{out['passrole_wide_enough_to_cover_a_sibling_agent_role']['configurations']}")
    print(f"\nwrote {a.json}")


if __name__ == "__main__":
    main()

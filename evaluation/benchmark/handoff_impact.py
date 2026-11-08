#!/usr/bin/env python3
"""Would traversing hand-off edges change the headline zero?

The question. `reach.py` computes eff by walking `delegate` edges, which are
created from sts:AssumeRole and from iam:PassRole paired with the ability to
drive a service the target role trusts. `extract_graph` separately creates
`handoff` edges, including a `permitted` one whenever an agent's role may call
InvokeAgentRuntime on another agent. The predicate never walks those, so a
caller that can invoke a more privileged agent does not gain its reach in eff.

That is the mechanism this project's own Foundry lab demonstrated and the one
`foundry_delegation.py` was written for on 2026-11-01. The same gap is on the
AWS side.

Before spending a day implementing it, this measures whether implementing it
would change anything. For every project with two or more agents it asks: is
there a hand-off edge from agent A to agent B where B's role is authorised for
something A's role is not? If no project has one, the headline zero stands
whichever way the rule is written, and the finding is only about labelling. If
some project has one, the headline changes and the paper changes with it.

This answers nothing on its own. A pair found here is a candidate, not an
escalation: it has to be confirmed by the real predicate once the rule exists,
and by hand. The output says so for each hit.

  python3 handoff_impact.py --corpus corpus_tier2 \\
      --topology evaluation/benchmark/topology_tier2.json \\
      --json evaluation/benchmark/handoff_impact_tier2.json
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
PKG = HERE.parent.parent / "agentpathtriage"
TF_TO_STATE = HERE / "tf_to_state.py"
sys.path.insert(0, str(PKG))


def auth_set(ix, reach_mod, role, universe, cache):
    """What this role can act on, using the project's own evaluator.

    `build_universe` returns a mapping of resource arn to the probe actions
    appropriate to that resource, so it is walked as a mapping.
    """
    if role in cache:
        return cache[role]
    out = set()
    stmts = ix.statements(role)
    for arn, actions in universe.items():
        for act in actions:
            if reach_mod.E.evaluate(stmts, act, arn).allowed:
                out.add(arn)
                break
    cache[role] = out
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, type=pathlib.Path)
    ap.add_argument("--topology", required=True, type=pathlib.Path)
    ap.add_argument("--json", type=pathlib.Path)
    a = ap.parse_args()

    import extract_graph as X
    import reach as R

    topo = json.loads(a.topology.read_text())
    multi = [t for t in topo if (t.get("n_agents") or 0) >= 2]
    print(f"projects with two or more agents: {len(multi)}\n")

    hits, examined, failed, same_role = [], 0, [], 0

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
            try:
                state = json.loads(st.read_text())
                G, ix = X.build(state)
            except Exception as e:
                failed.append({"project": rel, "why": f"{type(e).__name__}: {e}"})
                continue
            examined += 1

            universe = R.build_universe(ix)
            cache = {}
            role_of = {}
            for name, meta in ix.agents.items():
                ref = meta.get("role_arn")
                if ref:
                    role_of[name] = ix._owner_name(ref)

            for src, tgt, data in G.edges(data=True):
                if data.get("rel") != "handoff":
                    continue
                ra, rb = role_of.get(src), role_of.get(tgt)
                if not ra or not rb:
                    continue
                if ra == rb:
                    # One role for both agents. Nothing can be gained from an
                    # identity you already are, which is why the shared-role
                    # finding is a different class and not an escalation.
                    same_role += 1
                    continue
                gained = auth_set(ix, R, rb, universe, cache) - \
                    auth_set(ix, R, ra, universe, cache)
                if gained:
                    hits.append({
                        "project": rel, "caller": src, "callee": tgt,
                        "caller_role": ra, "callee_role": rb,
                        "evidence": data.get("evidence"),
                        "permitted_scope": data.get("permitted_scope"),
                        "would_gain": sorted(gained)[:8],
                        "n_would_gain": len(gained),
                        "status": "candidate only. The rule that would make "
                                  "this an escalation is not implemented, and "
                                  "this comparison is not that rule: it does "
                                  "not check that the hand-off is reachable "
                                  "or that the gain survives conditions.",
                    })
                    print(f"  [{i}/{len(multi)}] {rel}")
                    print(f"      {src} -> {tgt} ({data.get('evidence')}), "
                          f"callee role reaches {len(gained)} more")

    out = {
        "corpus": str(a.corpus),
        "question": "would walking hand-off edges in eff change the headline "
                    "zero on AWS",
        "projects_with_two_or_more_agents": len(multi),
        "projects_examined": examined,
        "projects_failed": len(failed),
        "handoff_edges_where_both_agents_share_one_role": same_role,
        "candidate_pairs": len(hits),
        "projects_with_a_candidate": len({h["project"] for h in hits}),
        "candidates": hits,
        "failed": failed,
        "what_this_is_not": "a candidate is not an escalation. It says the "
                            "callee's role is authorised for something the "
                            "caller's is not, and that a hand-off edge joins "
                            "them. Confirming it needs the rule implemented "
                            "and a hand audit.",
    }

    print()
    print(f"projects examined                  {examined}")
    print(f"hand-off edges on one shared role  {same_role}")
    print(f"candidate pairs                    {len(hits)}")
    print(f"projects with a candidate          {out['projects_with_a_candidate']}")
    print()
    if hits:
        print("Implementing the rule would change the headline. The zero is "
              "currently a property of which edges the predicate walks, not "
              "only of the corpus.")
    else:
        print("No candidate. The headline zero holds whichever way the rule "
              "is written, and the finding is about labelling: the number "
              "measures identity borrowing and the prose calls it hand-off.")
    if failed:
        print(f"\n{len(failed)} project(s) could not be examined:")
        for f in failed[:5]:
            print(f"  {f['project']}: {f['why']}")

    if a.json:
        a.json.write_text(json.dumps(out, indent=2))
        print(f"\nwrote {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

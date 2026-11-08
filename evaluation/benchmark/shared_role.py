#!/usr/bin/env python3
"""Across multi-agent templates: do two agents run under ONE execution role?

This is the strongest form of the confused deputy at the IAM layer, because
nothing has to be guessed. With a shared execution role each agent already holds
every permission the other holds, so a prompt that reaches the weaker agent acts
with the stronger agent's authority. It is also the case a policy linter cannot
report: it sees one role with one policy, and there is nothing wrong with that
policy. The defect is in the binding of two agents to it, which lives in the
agent platform's configuration rather than in IAM.

Usage:
  python3 evaluation/benchmark/topology.py --corpus corpus_tier2 --json topology.json
  python3 evaluation/benchmark/shared_role.py --topology topology.json \
      --corpus corpus_tier2 --json shared_role.json
"""
import argparse, collections, json, os, sys, warnings

warnings.filterwarnings("ignore")
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(_HERE)), "agentpathtriage"))
import tf_to_state as T, extract_graph as X   # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--topology", required=True, help="output of topology.py")
    ap.add_argument("--corpus", default="corpus_tier2")
    ap.add_argument("--json")
    a = ap.parse_args()

    topo = json.load(open(a.topology))
    multi = [r for r in topo if "err" not in r and r.get("n_agents", 0) > 1]
    shared, distinct, unknown = [], [], []
    for r in multi:
        try:
            st, _ = T.to_state(os.path.join(a.corpus, r["t"]))
            _, ix = X.build(st)
        except Exception as e:
            unknown.append((r["t"], f"parse {type(e).__name__}"))
            continue
        byrole = collections.defaultdict(list)
        for an, am in ix.agents.items():
            byrole[str(am.get("role_arn"))].append(an)
        groups = {k: sorted(v) for k, v in byrole.items() if len(v) > 1 and k != "None"}
        if groups:
            shared.append((r["t"], groups))
        elif "None" in byrole:
            # an unresolved role_arn could be hiding either answer, so it is
            # counted as undecided rather than as a distinct role
            unknown.append((r["t"], "a role_arn did not resolve"))
        else:
            distinct.append(r["t"])

    n = len(multi)
    pct = (lambda k: f"  ({100 * k / n:.1f}%)") if n else (lambda k: "")
    print(f"multi-agent templates             : {n}\n")
    print(f"agents sharing one execution role : {len(shared)}/{n}{pct(len(shared))}")
    for t, g in shared:
        print(f"   {t[:74]}")
        for role, ags in g.items():
            print(f"      {ags} all run as {str(role).rsplit('/', 1)[-1]}")
    print(f"\ndistinct roles per agent          : {len(distinct)}/{n}{pct(len(distinct))}")
    print(f"could not decide                  : {len(unknown)}/{n}")
    for t, why in unknown:
        print(f"   {t[:74]}  ({why})")

    if a.json:
        json.dump({"multi_agent_templates": n,
                   "shared_role": [{"template": t, "groups": g} for t, g in shared],
                   "distinct_roles": distinct,
                   "undecided": [{"template": t, "why": w} for t, w in unknown]},
                  open(a.json, "w"), indent=2)
        print(f"\nwritten: {a.json}")


if __name__ == "__main__":
    main()

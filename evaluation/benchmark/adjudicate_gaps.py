#!/usr/bin/env python3
"""Adjudicate each resource-scope gap: is the broad grant reachable cross-agent?

A resource-scope gap says a runtime's execution role holds an AgentCore action on
a resource pattern wider than the resources wired to that runtime. That is a
PRECONDITION, not a finding, and reporting the count as a prevalence of
cross-agent escalation would overstate it. This pass asks the question that
decides deployability: does the wider pattern actually cover a resource that
belongs to a different agent?

Verdicts:
  cross-agent   the pattern matches a resource another agent in the same template
                owns. Deployable as a Pillar B case.
  shared-role   two agents run under one role, so each already holds the other's
                permissions and no hand-off has to be guessed. Deployable, and
                stronger evidence than a pattern match.
  single-agent  the template declares one agent, so there is no second agent here
                to reach. Latent at module level: real only once two instances of
                the module land in one account, which a per-directory analysis
                cannot observe. Reported as latent rather than as a finding.
  narrow        the wider pattern does not in fact cover another agent's resource.

Usage:
  python3 agentpathtriage/gap.py --corpus corpus_tier2 --json gap_tier2.json
  python3 evaluation/benchmark/adjudicate_gaps.py --gap gap_tier2.json \
      --corpus corpus_tier2 --json adjudication.json
"""
import argparse, collections, json, os, sys, warnings

warnings.filterwarnings("ignore")
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(_HERE)), "agentpathtriage"))
import tf_to_state as T, extract_graph as X, iam_eval as E   # noqa: E402


def adjudicate(template_dir, runtime):
    rec = {}
    try:
        st, _ = T.to_state(template_dir)
        G, ix = X.build(st)
    except Exception as e:
        return {"verdict": f"parse-fail: {type(e).__name__}"}

    agents = dict(ix.agents)
    roles = {an: (ix.name_of_arn.get(am["role_arn"]) or
                  (str(am["role_arn"]).rsplit("/", 1)[-1] if am["role_arn"] else None))
             for an, am in agents.items()}
    rec["agents"] = sorted(agents)
    rec["roles"] = roles

    if len(agents) < 2:
        rec["verdict"] = "single-agent"
        return rec

    sharing = sorted(a for a in agents if roles[a]
                     and sum(1 for b in agents if roles[b] == roles[a]) > 1)
    if sharing:
        rec["verdict"] = "shared-role"
        rec["sharing"] = sharing
        return rec

    owned = {}
    for res in st["values"]["root_module"]["resources"]:
        arn = res["values"].get("arn")
        if isinstance(arn, str) and "bedrock-agentcore" in arn:
            owned[arn] = res["name"]

    role = roles.get(runtime)
    stmts = ix.statements(role) if role and role in ix.kind else []
    hits = []
    for arn, owner in owned.items():
        if owner == runtime:
            continue
        for s in stmts:
            if not (s.is_allow and s.resource_is_wildcard()):
                continue
            for act in (a for a in s.actions if "bedrock-agentcore" in a.lower()):
                if E.evaluate(stmts, act, arn).allowed:
                    hits.append({"action": act, "reaches": arn, "owner": owner})
                    break
            if hits:
                break
    rec["verdict"] = "cross-agent" if hits else "narrow"
    rec["hits"] = hits[:3]
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gap", required=True, help="output of agentpathtriage/gap.py")
    ap.add_argument("--corpus", default="corpus_tier2")
    ap.add_argument("--json")
    a = ap.parse_args()

    rows = json.load(open(a.gap))["rows"]
    gaps = [r for r in rows if r.get("resource_scope_gap")]
    out = []
    for r in gaps:
        rec = {"template": r["template"], "runtime": r["runtime"],
               "wired_source": r["wired_source"]}
        rec.update(adjudicate(os.path.join(a.corpus, r["template"]), r["runtime"]))
        out.append(rec)

    print(f"{len(gaps)} resource-scope gaps adjudicated\n")
    print(f"{'verdict':14s} {'src':11s} {'runtime':16s} template")
    print("-" * 110)
    for r in sorted(out, key=lambda x: (x["verdict"], x["template"])):
        print(f"{r['verdict']:14s} {r['wired_source']:11s} {r['runtime'][:16]:16s} "
              f"{r['template'][:64]}")
        for h in r.get("hits", []):
            print(f"                 -> {h['action']} on {h['reaches']} "
                  f"(owned by {h['owner']})")
        if r.get("sharing"):
            print(f"                 -> agents sharing one role: {r['sharing']}")
    counts = collections.Counter(r["verdict"] for r in out)
    print("\nverdicts:", dict(counts))
    print("\nDeployable as Pillar B cases: "
          f"{counts['cross-agent'] + counts['shared-role']}. "
          "A single-agent verdict is latent, not negative: the module can collide "
          "with another instance of itself in one account, which this analysis "
          "does not observe.")
    if a.json:
        json.dump(out, open(a.json, "w"), indent=2)
        print(f"\nwritten: {a.json}")


if __name__ == "__main__":
    main()

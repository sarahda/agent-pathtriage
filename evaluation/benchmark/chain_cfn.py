#!/usr/bin/env python3
"""Run the chain analysis on the CloudFormation templates, with the same rule.

Why this is a driver and not an analysis. The population in which a cross-agent
chain is possible was 18 Terraform projects, and 0 of 18 bounds the true rate
at only 15.3 percent. The CloudFormation and CDK scan found 18 more units, so
the population can double, but only for the measurements actually run on them.
Counting role sharing there and then quoting a bound for chains would be
claiming a denominator the chain analysis never covered.

So the chain analysis is run, and it is run by translating each template into
the state shape `extract_graph` already reads and calling `reach.py`
unchanged. The predicate, the graph, the delegation edge rule and the
evaluator are the same objects that produced the Terraform numbers. Nothing
about this adds a second implementation of Esc.

CDK is not covered and is not counted. Its roles' policies are built by code,
and recovering them from source would be a heuristic several steps deeper than
reading a role argument. Those ten directories stay in the population for role
sharing and are reported as undecidable for chains, which is the distinction
`role_arn_resolution.py` established for Terraform and the same one applies.

  python3 chain_cfn.py --corpus corpus_tier2 \\
      --scan evaluation/benchmark/cfn_cdk_tier2.json \\
      --json evaluation/benchmark/chain_cfn_tier2.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
CFN_TO_STATE = HERE / "cfn_to_state.py"
REACH = HERE.parent.parent / "agentpathtriage" / "reach.py"

AGENT_TF_TYPE = "aws_bedrockagentcore_agent_runtime"


def bound(n: int, conf: float = 0.95) -> float:
    """The 95 percent upper bound on a rate given no observations in n trials."""
    return (1 - (1 - conf) ** (1.0 / n)) * 100 if n > 0 else 100.0


def agent_roles(state_path: pathlib.Path) -> tuple[list, list]:
    """(role names the agents run as, runtimes whose role did not resolve)."""
    state = json.loads(state_path.read_text())
    rows = state["values"]["root_module"]["resources"]
    by_arn = {r["values"].get("arn"): r["values"].get("name")
              for r in rows if r["type"] == "aws_iam_role"}
    roles, unresolved = [], []
    for r in rows:
        if r["type"] != AGENT_TF_TYPE:
            continue
        ref = r["values"].get("role_arn")
        if not ref or "${" in str(ref):
            unresolved.append({"runtime": r["name"], "role_ref": ref})
            continue
        name = by_arn.get(ref) or str(ref).rsplit("/", 1)[-1]
        roles.append(name)
    return roles, unresolved


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, type=pathlib.Path)
    ap.add_argument("--scan", required=True, type=pathlib.Path,
                    help="the json cfn_cdk_runtimes.py wrote")
    ap.add_argument("--json", type=pathlib.Path)
    a = ap.parse_args()

    if not REACH.exists():
        print(f"stop: {REACH} not found", file=sys.stderr)
        return 2
    scan = json.loads(a.scan.read_text())
    cfn = scan.get("cloudformation", {})
    multi = cfn.get("multi")
    # Restrict to the deployable distinct units the scan identified. Without
    # this the denominator counts a template once per copy: on 2026-11-02 the
    # twenty-six multi-runtime templates held eight byte identical copies of
    # one awslabs sample and seven files that exist for a test or a benchmark
    # to read, so a denominator of twenty-six was really twelve. Older scan
    # output has no population block, and then every entry is used and the
    # json says the figure was not deduplicated.
    pop = cfn.get("population") or {}
    if not pop:
        # Scan output written before the scanner recorded a population block.
        # The rule lives in committed code, so it is applied here rather than
        # leaving the denominator counting copies, and the result is the same
        # object the scanner would have written.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "cfn_cdk_runtimes", str(HERE / "cfn_cdk_runtimes.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        pop = mod.deployable_units(multi or [], a.corpus, "template",
                                   lambda r: [r["template"]])
        print("the scan json predates the population block, so the "
              "deployable set was derived here with the same function")
    kept = set(pop.get("kept") or [])
    deduplicated = bool(kept)
    if deduplicated and multi:
        before = len(multi)
        multi = [e for e in multi if e["template"] in kept]
        print(f"deployable distinct units: {len(multi)} of {before} "
              f"({before - len(multi)} were copies of another template or "
              f"files that are not a deployment)")
    if multi is None:
        print("stop: the scan json has no list of multi-runtime templates. "
              "Re-run cfn_cdk_runtimes.py after applying the patch that adds "
              "it, otherwise this driver would have to guess which templates "
              "to analyse.", file=sys.stderr)
        return 2

    analysed, chains, undecidable, failed = [], [], [], []

    with tempfile.TemporaryDirectory() as tmp:
        st = pathlib.Path(tmp) / "state.json"
        rc_json = pathlib.Path(tmp) / "reach.json"
        for i, entry in enumerate(multi, 1):
            rel = entry["template"]
            path = a.corpus / rel
            print(f"[{i}/{len(multi)}] {rel}")
            if not path.is_file():
                failed.append({"template": rel, "why": "not in the corpus"})
                continue

            p = subprocess.run(
                [sys.executable, str(CFN_TO_STATE), "--template", str(path),
                 "--json", str(st), "--quiet"], capture_output=True, text=True)
            if p.returncode != 0 or not st.exists():
                failed.append({"template": rel,
                               "why": "could not be translated",
                               "stderr": (p.stderr or "")[:300]})
                continue

            roles, unres = agent_roles(st)
            if unres:
                undecidable.append({"template": rel, "runtimes": unres,
                                    "why": "an agent's role reference did not "
                                           "resolve, so this template cannot "
                                           "be judged either way"})
                print("      undecidable: a role reference did not resolve")
                continue

            p = subprocess.run(
                [sys.executable, str(REACH), "--state", str(st),
                 "--json", str(rc_json)], capture_output=True, text=True)
            if p.returncode not in (0, 1) or not rc_json.exists():
                failed.append({"template": rel, "why": "reach.py failed",
                               "stderr": (p.stderr or "")[:300]})
                print("      reach.py failed")
                continue

            res = json.loads(rc_json.read_text())["results"]
            hits = [r for r in res if r["principal"] in roles and r["Esc"]]
            unq = [r for r in res
                   if r["principal"] in roles and r.get("Esc_unquantified")]
            row = {"template": rel, "agent_roles": sorted(set(roles)),
                   "esc": [{"principal": r["principal"],
                            "witnesses": r["witnesses"][:4],
                            "delegation_hops": r["delegation_hops"]}
                           for r in hits],
                   "esc_unquantified": [r["principal"] for r in unq]}
            analysed.append(row)
            if hits:
                chains.append(row)
                print(f"      CHAIN: {len(hits)} agent role(s) with Esc true")
            elif unq:
                print("      reach grows but the extent is not measurable "
                      "from the configuration")
            else:
                print("      no chain")

    cdk = scan.get("cdk", {})
    cdk_units = cdk.get("directories_with_two_or_more", 0)
    tf_units = 18

    out = {
        "corpus": str(a.corpus),
        "method": "each template is translated to the state shape "
                  "extract_graph reads, then reach.py is called unchanged. "
                  "The predicate and the delegation edge rule are the same "
                  "objects that produced the Terraform numbers.",
        "cloudformation": {
            "multi_runtime_templates": len(multi),
            "analysed": len(analysed),
            "with_a_chain": len(chains),
            "undecidable": len(undecidable),
            "failed": len(failed),
            "chains": chains,
            "undecidable_detail": undecidable,
            "failed_detail": failed,
        },
        "cdk": {
            "multi_runtime_directories": cdk_units,
            "analysed": 0,
            "why_not": "a CDK role's policies are built by code. Recovering "
                       "them from source is a heuristic several steps deeper "
                       "than reading a role argument, so these are counted in "
                       "the population for role sharing and reported as "
                       "undecidable for chains.",
        },
        "population": {
            "terraform_projects": tf_units,
            "cloudformation_templates_analysed": len(analysed),
            "chain_denominator": tf_units + len(analysed),
            "units_in_population_not_analysed_for_chains":
                cdk_units + len(undecidable) + len(failed),
            "deduplicated": deduplicated,
            "deduplication_note": (
                "the CloudFormation side counts deployable distinct units: a "
                "template byte identical to another is counted once and a "
                "file under a test fixture, a snapshot directory or a "
                "vendored benchmark copy is not counted as a deployment"
                if deduplicated else
                "this scan json predates the population block, so every "
                "multi-runtime entry was used and copies were not removed"),
            "note": "the denominator is what the chain analysis actually "
                    "covered, not the whole population. The units it did not "
                    "cover are named above rather than assumed clean.",
        },
    }
    den = out["population"]["chain_denominator"]
    found = len(chains)
    out["population"]["chains_found"] = found
    if found == 0:
        out["population"]["upper_bound_95_percent"] = round(bound(den), 1)

    c = out["cloudformation"]
    print()
    print(f"CloudFormation multi-runtime templates   {c['multi_runtime_templates']}")
    print(f"  analysed                               {c['analysed']}")
    print(f"  with a cross-agent chain               {c['with_a_chain']}")
    print(f"  undecidable                            {c['undecidable']}")
    print(f"  failed                                 {c['failed']}")
    print()
    print(f"chain denominator: {tf_units} Terraform + {len(analysed)} "
          f"CloudFormation = {den}")
    print(f"not covered: {out['population']['units_in_population_not_analysed_for_chains']} "
          f"({cdk_units} CDK, {len(undecidable)} undecidable, {len(failed)} failed)")
    if found == 0:
        print(f"chains found: 0")
        print(f"  0 of {tf_units}  ->  {bound(tf_units):.1f}%   (before this)")
        print(f"  0 of {den}  ->  {bound(den):.1f}%   (after this)")
    else:
        print(f"chains found: {found}. The paper's claim changes: this is no "
              f"longer a bound on an unobserved rate, it is a finding.")

    if a.json:
        a.json.write_text(json.dumps(out, indent=2))
        print(f"\nwrote {a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

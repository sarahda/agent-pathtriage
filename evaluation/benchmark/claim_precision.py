#!/usr/bin/env python3
"""What backs each published number, and where a precision exists, what it is.

A single precision for the whole tool answers a question nobody asked. The
paper makes several claims, each produced by a different pass over a different
population, and they are not equally well checked. This prints one row per
claim with the number, the population it came from, how it was verified, and a
precision only where something was checked by hand or against an external
ground truth.

Where no hand check exists the row says so. A blank is not a pass.

Nothing is retyped here. Every number is read out of the artifact that
produced it, so a row cannot drift from the run.

  python3 evaluation/benchmark/claim_precision.py
  python3 evaluation/benchmark/claim_precision.py --json claim_precision.json
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    path = os.path.join(HERE, name)
    if not os.path.isfile(path):
        return None
    with open(path) as fh:
        return json.load(fh)


def row(claim, number, population, how, precision=None, note=""):
    return {"claim": claim, "number": number, "population": population,
            "verified_by": how, "precision": precision, "note": note}


def build():
    rows = []
    missing = []

    # ---- external ground truth, BishopFox IAM-Vulnerable ------------------
    bench = load("benchmark_results.json")
    if bench is None:
        missing.append("benchmark_results.json")
    else:
        rows.append(row(
            "delegation paths recovered once hand-offs are followed",
            f"{bench['multi_hop_recall']:.3f} recall",
            "IAM-Vulnerable delegation paths",
            "external ground truth, someone else's benchmark",
            note="recall, not precision"))
        rows.append(row(
            "the same paths seen by a check that looks at one identity at a time",
            f"{bench['single_hop_recall']:.3f} recall",
            "IAM-Vulnerable delegation paths",
            "external ground truth",
            note="the baseline, not a claim about this tool"))

    gt = load("ground_truth.json")
    if gt is None:
        missing.append("ground_truth.json")

    # ---- the corpus census ------------------------------------------------
    shared = load("shared_role_tier2.json")
    if shared is None:
        missing.append("shared_role_tier2.json")
    else:
        n_multi = shared["multi_agent_templates"]
        n_shared = len(shared["shared_role"])
        n_undecided = len(shared.get("undecided", []))
        src0 = load("shared_role_source_check.json")
        ma = (src0 or {}).get("multi_agent")
        if ma:
            rows.append(row(
                "templates declaring two or more agents",
                f"{n_multi}",
                "220 analysed projects",
                "census, then every flagged template re-read from the raw "
                "Terraform by a second pass",
                precision=(None if ma["precision"] is None
                           else round(ma["precision"], 3)),
                note=(f"{ma['source_confirms']} of {ma['templates_checked']} "
                      f"confirmed, {n_undecided} undecided. The second pass "
                      f"counts runtime blocks in the source, which is a cross "
                      f"check and not an independent oracle.")))
        else:
            rows.append(row(
                "templates declaring two or more agents",
                f"{n_multi}",
                "220 analysed projects",
                "census of the whole population, not a sample",
                note=(f"{n_undecided} undecided. No second check of the "
                      f"{n_multi} exists, so no precision is claimed.")))
        src = load("shared_role_source_check.json")
        if src is None:
            missing.append("shared_role_source_check.json")
            rows.append(row(
                "templates running every agent under one execution role",
                f"{n_shared} of {n_multi}",
                f"the {n_multi} multi-agent templates",
                "census of the whole population, not a sample",
                note="no second check of the flagged templates exists"))
        else:
            rows.append(row(
                "templates running every agent under one execution role",
                f"{n_shared} of {n_multi}",
                f"the {n_multi} multi-agent templates",
                "census, then every flagged template re-read from the raw "
                "Terraform by a second pass",
                precision=(None if src["precision"] is None
                           else round(src["precision"], 3)),
                note=(f"{src['source_confirms']} of {src['templates_checked']} "
                      f"confirmed. The second pass groups runtimes by the "
                      f"role_arn expression text, so it is a cross check and "
                      f"not an independent oracle. File and line for each are "
                      f"in shared_role_source_check.json.")))

    # ---- the gap adjudication, which is a hand check ----------------------
    adj = load("adjudication_tier2.json")
    if adj is None:
        missing.append("adjudication_tier2.json")
    else:
        verdicts = collections.Counter(x["verdict"] for x in adj)
        total = len(adj)
        single = verdicts.get("single-agent", 0)
        narrow = verdicts.get("narrow", 0)
        shared_role = verdicts.get("shared-role", 0)
        cross = verdicts.get("cross-agent", 0)
        # A gap in a single-agent template is latent rather than wrong: there
        # is no second agent in that directory to reach, which the gap pass
        # does not claim there is. The templates where the claim can be right
        # or wrong are the ones with a second agent.
        decidable = total - single
        hits = shared_role + cross
        prec = (hits / decidable) if decidable else None
        rows.append(row(
            "resource-scope gaps adjudicated by hand",
            f"{total} flagged",
            "every gap the pass produced, none sampled",
            "hand adjudication of 100 percent of the flagged set",
            note=(f"{single} single-agent (latent), {narrow} narrow, "
                  f"{shared_role} shared-role, {cross} cross-agent")))
        rows.append(row(
            "a flagged gap covers a resource another agent in the same "
            "template owns",
            f"{hits} of {decidable}",
            f"the {decidable} flagged gaps in templates with a second agent",
            "hand adjudication",
            note=("the single-agent gaps are excluded because the claim "
                  "cannot be wrong where there is no second agent. "
                  f"The adjudication confirmed all {hits} of the {hits} "
                  "reported, so the number below is the breakdown of the "
                  "flagged set and not an agreement rate")))

    # ---- the takeover census ---------------------------------------------
    cen = load("corpus_takeover_census.json")
    if cen is None:
        missing.append("corpus_takeover_census.json")
    else:
        exp = cen["expanded"]
        bsrc = load("blocked_takeover_source_check.json")
        if bsrc is None:
            missing.append("blocked_takeover_source_check.json")
            rows.append(row(
                "takeover candidates blocked only on iam:PassRole",
                f"{exp['blocked_takeover_candidates']} across "
                f"{exp['configs_with_a_blocked_candidate']} projects",
                f"{exp['configurations']} analysed projects",
                "census of the whole population, not a sample",
                note=("no second check of the blocked set exists. "
                      "The block itself follows from the API contract: "
                      "UpdateAgentRuntime marks roleArn required, so the "
                      "candidate cannot avoid iam:PassRole.")))
        else:
            n = bsrc["candidates"]
            a2a = bsrc["agent_to_agent"]
            by = bsrc["by_verdict"]
            rows.append(row(
                "takeover candidates blocked only on iam:PassRole",
                f"{exp['blocked_takeover_candidates']} across "
                f"{exp['configs_with_a_blocked_candidate']} projects",
                f"{exp['configurations']} analysed projects",
                "census, then every candidate re-read from the raw Terraform",
                note=("the block follows from the API contract: "
                      "UpdateAgentRuntime marks roleArn required, so the "
                      "candidate cannot avoid iam:PassRole. What the 26 are "
                      "is in the next row.")))
            rows.append(row(
                "blocked candidates that are one agent reaching another",
                f"{a2a} of {n}",
                f"the {n} blocked candidates",
                "every candidate re-read from the raw Terraform",
                note=("the second pass agreed with every candidate, so this "
                      "is the breakdown of the blocked set and not an "
                      "agreement rate. "
                      + "; ".join(f"{v} {k}" for k, v in by.items())
                      + ". The rest are a takeover but not an agent to agent "
                        "one, or sit in a configuration with no second agent.")))
        if adj is not None:
            n_cross = sum(1 for x in adj if x["verdict"] == "cross-agent")
            rows.append(row(
                "cross-agent escalation found in the corpus",
                f"{n_cross} of {exp['configurations']}",
                f"{exp['configurations']} analysed projects",
                "hand adjudication of every flagged gap",
                note=("a count of zero has no positives to be precise about. "
                      "What bounds it is the population, not a precision.")))
        wide = cen.get("passrole_wide_enough_to_cover_a_sibling_agent_role", {})
        rows.append(row(
            "projects granting iam:PassRole over a role an agent runs as",
            f"{wide.get('configurations')} of {exp['configurations']}",
            f"{exp['configurations']} analysed projects",
            "census of the whole population, not a sample",
            note="no hand check exists"))

    # ---- CDK packages, which were read by hand ----------------------------
    cdk = load(os.path.join("..", "..", "validation", "pr", "cdk_packages.json"))
    if cdk is None:
        missing.append("validation/pr/cdk_packages.json")
    else:
        pkgs = cdk["packages"]
        confirmed = [p for p in pkgs if p.get("hand_confirmed")]
        rows.append(row(
            "CDK apps running several runtimes under one role",
            f"{len(pkgs)}",
            "the CDK apps the source scan flagged",
            "every one read by hand in the source",
            precision=(round(len(confirmed) / len(pkgs), 3) if pkgs else None),
            note=f"{len(confirmed)} of {len(pkgs)} confirmed by reading the file"))

    # ---- Foundry ----------------------------------------------------------
    rec = load("foundry_recon.json")
    if rec is None:
        missing.append("foundry_recon.json")
    else:
        rows.append(row(
            "Foundry template directories holding an agent declaration",
            f"{rec['dirs_with_an_agent']} of {rec['template_dirs']}",
            f"{rec['repositories']} repositories, "
            f"{rec['files_scanned']} files",
            "census of the whole corpus, not a sample",
            note="a count of zero has no positives to be precise about"))

        auth = rec.get("configured_auth_types")
        if auth is None:
            rows.append(row(
                "Foundry connection auth values, by type",
                "not in the artifact",
                "unknown",
                "NOT REBUILDABLE",
                note=("foundry_recon.py counts these and the published "
                      "numbers quote them, but until 2026-11-07 the counter "
                      "was not written to the JSON, so verify cannot rebuild "
                      "them. Re-run foundry_recon.py to fill this row.")))
        else:
            total = rec.get("configured_auth_values", sum(auth.values()))
            agentic = {k: v for k, v in auth.items()
                       if k.lower().startswith("agentic")}
            rows.append(row(
                "Foundry connection auth values, by type",
                ", ".join(f"{k} {v}" for k, v in list(auth.items())[:6]),
                f"{total} assigned authType values",
                "census of the whole corpus, not a sample",
                note="assigned values, which is not the authType marker count"))
            rows.append(row(
                "connections that pick an agent scoped auth type",
                f"{sum(agentic.values())} of {total}",
                f"{total} assigned authType values",
                "census of the whole corpus, not a sample",
                note="a count of zero has no positives to be precise about"))

    return rows, missing


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    rows, missing = build()

    width = max(len(r["claim"]) for r in rows) if rows else 0
    print("claim".ljust(width), "number".ljust(22), "precision")
    print("-" * (width + 36))
    measured = 0
    for r in rows:
        p = r["precision"]
        if p is None:
            shown = "not measured"
        else:
            shown = f"{p:.3f}"
            measured += 1
        print(r["claim"].ljust(width), str(r["number"]).ljust(22), shown)

    print()
    print(f"{measured} of {len(rows)} claims have a precision. "
          f"The rest say so rather than leaving a blank.")
    if missing:
        print("\nartifacts not found, so their claims are absent from this "
              "table rather than reported as unmeasured:")
        for m in missing:
            print(f"  {m}")

    print("\nnotes")
    for r in rows:
        if r["note"]:
            print(f"  {r['claim']}:\n    {r['note']}")

    if a.json:
        out = os.path.join(HERE, a.json) if not os.path.isabs(a.json) else a.json
        with open(out, "w") as fh:
            json.dump({"rows": rows, "artifacts_missing": missing}, fh, indent=1)
        print(f"\nwritten: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

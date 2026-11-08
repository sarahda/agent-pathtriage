#!/usr/bin/env python3
"""Re-derive every number the paper asserts, straight from the artifacts.

The paper defines each figure once, in numbers.tex, and every definition names
the artifact it came from. This reads those definitions back and recomputes
each one from the artifact, so a macro that drifted away from its evidence is
reported rather than trusted.

Run it from the repository root with numbers.tex given:

  python3 verify_numbers.py --numbers /path/to/numbers.tex \\
      --bench evaluation/benchmark

exit 0  every macro matches its artifact
exit 1  at least one disagrees, or an artifact is missing
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys


def load(bench, name):
    path = os.path.join(bench, name)
    if not os.path.isfile(path):
        return None
    with open(path) as fh:
        return json.load(fh)


def macros(path):
    """The macro name and literal value of every definition in numbers.tex."""
    out = {}
    text = open(path).read()
    for m in re.finditer(r'\\newcommand\{\\(\w+)\}\{([^}\\]*)\\xspace\}', text):
        out[m.group(1)] = m.group(2).strip()
    return out


def distinct_cdk_apps(bench):
    """Applications among the analysed CDK directories.

    Directories are grouped by the application path inside the repository.
    Several repositories carry the same sample at the same path, and those are
    one application. A repository whose application sits at its root has an
    empty path, which is not a shared path, so each of those counts on its own.
    """
    rows = []
    for f in glob.glob(os.path.join(bench, "cdk_synth_chain.jsonl")):
        with open(f) as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if r.get("ok"):
                    rows.append(r)
    groups, singles = {}, 0
    for r in rows:
        tail = "/".join(str(r.get("app_root", "")).split("/")[1:])
        if tail:
            groups.setdefault(tail, []).append(r)
        else:
            singles += 1
    biggest = max((len(v) for v in groups.values()), default=0)
    return len(groups) + singles, biggest, len(rows)


def row_for(rows, needle):
    """The claim row whose text contains needle. Case is ignored, because the
    artifact writes claims in sentence case and the paper does not."""
    low = needle.lower()
    for r in rows:
        if low in str(r.get("claim", "")).lower():
            return r
    return None


def claim(rows, needle, field=None):
    """A recall or precision value, as the claim artifact recorded it."""
    r = row_for(rows, needle)
    if r is None:
        return None
    if field == "precision":
        v = r.get("precision")
        return f"{v:.3f}" if isinstance(v, (int, float)) else None
    m = re.match(r"([0-9.]+)\s+recall", str(r.get("number", "")))
    return m.group(1) if m else None


def number(rows, needle, index=None):
    """The counts inside a claim's `number` field, such as "2 of 4"."""
    r = row_for(rows, needle)
    if r is None:
        return None
    nums = re.findall(r"\d+", str(r.get("number", "")))
    if index is None:
        return int(nums[0]) if nums else None
    return int(nums[index]) if len(nums) > index else None


def expected(bench):
    """macro name -> (value recomputed from the artifact, artifact it used)."""
    c = load(bench, "corpus_takeover_census.json") or {}
    e = c.get("expanded", {})
    b = load(bench, "blocked_takeover_source_check.json") or {}
    bv = b.get("by_verdict", {})
    s = load(bench, "shared_role_corrected.json") or {}
    ch = load(bench, "chain_cfn_corpus.json") or {}
    pop, cfn, cdkpop = ch.get("population", {}), ch.get("cloudformation", {}), ch.get("cdk", {})
    k = load(bench, "cdk_synth_chain.json") or {}
    kf = k.get("failures_by_stage", {})
    f = load(bench, "foundry_recon.json") or {}
    at = f.get("configured_auth_types", {})
    mk = f.get("markers", {})
    p = load(bench, "perf_tier2.json") or {}
    pt = p.get("per_template_seconds", {})
    ds = load(bench, "disclosure_sends.json") or {}
    ft = load(bench, "foundry_template_dup.json") or {}
    ck = load(bench, "checkov_summary.json") or {}
    cp = load(bench, "claim_precision.json") or {}
    rows = cp.get("rows", [])

    stored_keys = ("ApiKey", "CustomKeys", "AccessKey", "AccountKey", "PAT",
                   "SAS", "UsernamePassword", "None")
    stored = sum(v for key, v in at.items() if key in stored_keys)
    identity = sum(v for key, v in at.items() if key not in stored_keys)
    total = sum(at.values())
    singletons = sum(1 for v in at.values() if v == 1)

    apps, biggest, analysed = distinct_cdk_apps(bench)
    denom = pop.get("chain_denominator")
    ext = (denom + apps) if isinstance(denom, int) else None
    bound_ext = round(100 * (1 - 0.05 ** (1.0 / ext)), 1) if ext else None
    esc_single = sum(1 for r in e.get("escalating_configs", [])
                     if (r.get("n_agents") or 0) < 2)

    A = "corpus_takeover_census"
    return {
        "nProjects":            (c.get("configurations_measured"), A),
        "nProjectsFailed":      (c.get("configurations_failed"), A),
        "nEscalating":          (e.get("with_an_escalation"), A),
        "nEscalatingOwnResource": (e.get("with_an_escalation_gaining_a_resource_the_config_writes"), A),
        "nSurvivingTakeover":   (e.get("with_a_surviving_takeover_edge"), A),
        "nBlocked":             (e.get("blocked_takeover_candidates"), A),
        "nBlockedConfigs":      (e.get("configs_with_a_blocked_candidate"), A),
        "nPassRoleWide":        ((c.get("passrole_wide_enough_to_cover_a_sibling_agent_role") or {}).get("configurations"), A),
        "nEscalatingSingleAgent": (esc_single, A),

        "nBlockedAgentToAgent": (bv.get("agent to agent"), "blocked_takeover_source_check"),
        "nBlockedSingleAgent":  (bv.get("single-agent"), "blocked_takeover_source_check"),
        "nBlockedPrincipalNotAgent": (bv.get("principal is not an agent execution role"), "blocked_takeover_source_check"),
        "nBlockedTargetNotAgent": (bv.get("target is not an agent execution role"), "blocked_takeover_source_check"),

        "nMultiAgentBlocks":    (s.get("block_level", {}).get("multi_agent_templates"), "shared_role_corrected"),
        "nMultiAgentRuntimes":  (s.get("runtime_level", {}).get("multi_agent_templates"), "shared_role_corrected"),
        "nSharedRoleBlocks":    (s.get("block_level", {}).get("templates_sharing_one_execution_role"), "shared_role_corrected"),
        "nSharedRoleRuntimes":  (s.get("runtime_level", {}).get("templates_sharing_one_execution_role"), "shared_role_corrected"),

        "nChainTerraform":      (pop.get("terraform_projects"), "chain_cfn_corpus"),
        "nChainCfn":            (pop.get("cloudformation_templates_analysed"), "chain_cfn_corpus"),
        "nChainDenominator":    (denom, "chain_cfn_corpus"),
        "nChainNotCovered":     (pop.get("units_in_population_not_analysed_for_chains"), "chain_cfn_corpus"),
        "nChainsFound":         (pop.get("chains_found"), "chain_cfn_corpus"),
        "chainBound":           (pop.get("upper_bound_95_percent"), "chain_cfn_corpus"),
        "nCfnMultiRuntime":     (cfn.get("multi_runtime_templates"), "chain_cfn_corpus"),
        "nCfnAnalysed":         (cfn.get("analysed"), "chain_cfn_corpus"),
        "nCfnUndecidable":      (cfn.get("undecidable"), "chain_cfn_corpus"),
        "nCdkMultiRuntimeDirs": (cdkpop.get("multi_runtime_directories"), "chain_cfn_corpus"),

        "nCdkInScope":          (k.get("directories_in_scope"), "cdk_synth_chain"),
        "nCdkAnalysed":         (k.get("synthesised_and_analysed"), "cdk_synth_chain"),
        "nCdkRuntimes":         (k.get("agent_runtimes_recovered"), "cdk_synth_chain"),
        "nCdkEscalating":       (k.get("apps_with_an_escalating_principal"), "cdk_synth_chain"),
        "nCdkFailSynth":        (kf.get("synth"), "cdk_synth_chain"),
        "nCdkFailLanguage":     (kf.get("language"), "cdk_synth_chain"),
        "nCdkFailInstall":      (kf.get("install"), "cdk_synth_chain"),
        "nCdkFailLocate":       (kf.get("locate"), "cdk_synth_chain"),
        "nCdkDistinctApps":     (apps, "cdk_synth_chain.jsonl"),
        "nCdkSampleCopies":     (biggest, "cdk_synth_chain.jsonl"),
        "nChainDenominatorExt": (ext, "derived"),
        "chainBoundExt":        (bound_ext, "derived"),

        "nFoundryRepos":        (f.get("repositories"), "foundry_recon"),
        "nFoundryFiles":        (f.get("files_scanned"), "foundry_recon"),
        "nFoundryDirs":         (f.get("template_dirs"), "foundry_recon"),
        "nFoundryAuthValues":   (f.get("configured_auth_values"), "foundry_recon"),
        "nFoundryAuthDirs":     (f.get("configured_auth_directories"), "foundry_recon"),
        "nAuthAAD":             (at.get("AAD"), "foundry_recon"),
        "nAuthApiKey":          (at.get("ApiKey"), "foundry_recon"),
        "nAuthManagedIdentity": (at.get("ManagedIdentity"), "foundry_recon"),
        "nAuthCustomKeys":      (at.get("CustomKeys"), "foundry_recon"),
        "nAuthProjectManagedIdentity": (at.get("ProjectManagedIdentity"), "foundry_recon"),
        "nAuthAccessKey":       (at.get("AccessKey"), "foundry_recon"),
        "nAuthSingletons":      (singletons, "foundry_recon"),
        "nAuthStoredCredential": (stored, "foundry_recon"),
        "nAuthIdentity":        (identity, "foundry_recon"),
        "pctAuthStoredCredential": (round(100 * stored / total) if total else None, "foundry_recon"),

        "nTerraformFiles":      (p.get("terraform_files", {}).get("total"), "perf_tier2"),
        "corpusSeconds":        (p.get("whole_corpus_seconds"), "perf_tier2"),
        "medianSeconds":        (pt.get("median"), "perf_tier2"),
        "pNinetySeconds":       (pt.get("p90"), "perf_tier2"),
        "pNinetyNineSeconds":   (pt.get("p99"), "perf_tier2"),
        "maxSeconds":           (pt.get("max"), "perf_tier2"),
        "peakMemoryMB":         (p.get("peak_child_memory_mb"), "perf_tier2"),

        "nFoundryAgentDirs":    (f.get("dirs_with_an_agent"), "foundry_recon"),
        "nFoundryAgentAuthValues": (
            sum(v for k, v in (f.get("configured_auth_types") or {}).items()
                if k.lower().startswith("agentic")),
            "foundry_recon"),
        "nMarkerAuthType":      (mk.get("authType"), "foundry_recon"),
        "nMarkerProjects":      (mk.get("CognitiveServices/accounts/projects"), "foundry_recon"),
        "nMarkerMlsConnections": (mk.get("MachineLearningServices/workspaces/connections"), "foundry_recon"),
        "nMarkerFoundryResource": (mk.get("azurerm_ai_foundry"), "foundry_recon"),
        "nMarkerProjectManagedIdentity": (mk.get("ProjectManagedIdentity"), "foundry_recon"),
        "nMarkerUserEntraToken": (mk.get("UserEntraToken"), "foundry_recon"),
        "nMarkerAgenticIdentity": (mk.get("AgenticIdentity"), "foundry_recon"),
        "nMarkerAccountManagedIdentity": (mk.get("AccountManagedIdentity"), "foundry_recon"),

        "recallDelegation":     (claim(rows, "Delegation paths recovered"), "claim_precision"),
        "recallSingleIdentity": (claim(rows, "one identity at a time"), "claim_precision"),
        "precMultiAgent":       (claim(rows, "two or more agents", "precision"), "claim_precision"),
        "precSharedRole":       (claim(rows, "every agent under one execution role", "precision"), "claim_precision"),
        "precScopeGaps":        (claim(rows, "another agent in the same template", "precision"), "claim_precision"),
        "precBlockedAgentToAgent": (claim(rows, "one agent reaching another", "precision"), "claim_precision"),
        "precCdkSharedRole":    (claim(rows, "CDK apps running several runtimes", "precision"), "claim_precision"),
        "nScopeGapsFlagged":    (number(rows, "Resource-scope gaps"), "claim_precision"),
        "nScopeGapsCrossAgent": (number(rows, "another agent in the same template", 0), "claim_precision"),
        "nScopeGapsWithSecondAgent": (number(rows, "another agent in the same template", 1), "claim_precision"),
        "nCdkSharedRoleApps":   (number(rows, "CDK apps running several runtimes"), "claim_precision"),

        # --- disclosures ------------------------------------------------
        "nDisclosureReports": (ds.get("reports"), "disclosure_sends"),
        "nDisclosureRepos":   (ds.get("repositories_covered"),
                               "disclosure_sends"),
        "nDisclosureIssues":  ((ds.get("reports_by_channel") or {}).get("github-issue"),
                               "disclosure_sends"),
        "nDisclosureEmails":  ((ds.get("reports_by_channel") or {}).get("email"),
                               "disclosure_sends"),
        # --- the Foundry starter template -------------------------------
        "nFoundryTemplateCopies": (ft.get("identical_copies"),
                                   "foundry_template_dup"),
        "nFoundryTemplateRepos":  (ft.get("repositories_carrying_the_copy"),
                                   "foundry_template_dup"),
        "nFoundryTemplateApiKey": ((ft.get("call_sites_by_auth_type") or {}).get("ApiKey"),
                                   "foundry_template_dup"),
        "nFoundryTemplateShared": (ft.get("call_sites_setting_is_shared_to_all_true"),
                                   "foundry_template_dup"),
        # --- Checkov baseline -------------------------------------------
        "nCheckovFailed":         (ck.get("failed_checks"), "checkov_summary"),
        "nCheckovPassed":         (ck.get("passed_checks"), "checkov_summary"),
        "nCheckovRules":          (ck.get("distinct_failing_rules"),
                                   "checkov_summary"),
        "nCheckovOnAgentRuntime": (ck.get("checks_whose_subject_is_an_agent_runtime"),
                                   "checkov_summary"),
        "nCheckovGraphFailed":    (ck.get("failed_graph_checks"),
                                   "checkov_summary"),
        "nCheckovRelationRules":  (len(ck.get("rule_names_suggesting_a_relation") or [])
                                   or None, "checkov_summary"),
        "nClaims":              (len(rows) or None, "claim_precision"),
        "nClaimsWithPrecision": (sum(1 for r in rows if r.get("precision") is not None) or None, "claim_precision"),
    }


def same(written, derived):
    if derived is None:
        return False
    try:
        return abs(float(written) - float(derived)) < 1e-9
    except ValueError:
        return str(written) == str(derived)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--numbers", required=True)
    ap.add_argument("--bench", default="evaluation/benchmark")
    a = ap.parse_args()

    written = macros(a.numbers)
    exp = expected(a.bench)

    ok, bad, unchecked = [], [], []
    for name, value in sorted(written.items()):
        if name not in exp:
            unchecked.append(name)
            continue
        derived, source = exp[name]
        (ok if same(value, derived) else bad).append((name, value, derived, source))

    print(f"macros in numbers.tex : {len(written)}")
    print(f"  re-derived and equal: {len(ok)}")
    print(f"  disagree            : {len(bad)}")
    print(f"  no artifact mapping : {len(unchecked)}")
    if bad:
        print("\nDISAGREE")
        for n, w, d, s in bad:
            print(f"  \\{n:28} paper={w!s:>10}  artifact={d!s:>10}  [{s}]")
    if unchecked:
        print("\nNO MAPPING (add one, or confirm the macro is not a measurement)")
        for n in unchecked:
            print(f"  \\{n}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

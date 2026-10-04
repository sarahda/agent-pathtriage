#!/usr/bin/env python3
"""
AgentPathTriage - config-to-role gap (gap.py v0)

The PrivLess code-to-policy analogue for agents, at RESOURCE-SCOPE granularity
(feasibility-confirmed on vendor AgentCore Terraform 2026-10-03: agent_runtime
declares its bindings via env-var references like MEMORY_ID =
aws_bedrockagentcore_memory.memory.id, not a native field; actual read/write lives
in container code, so we measure resource scope, not exact action use).

Per template (a directory containing an aws_bedrockagentcore_agent_runtime):
  - wired(agent):   agentcore resources the runtime is tied to, resolved from
                    env-var references to aws_bedrockagentcore_*.{id,arn} and from
                    co-located agentcore resources.
  - granted(role):  bedrock-agentcore actions + resource scopes in the execution
                    role's inline policies (the role_arn the runtime references).
  - wired_recovered: could we statically resolve the wired set? (Gate-1 metric.)
  - resource_scope_gap: role grants bedrock-agentcore on a WILDCARD resource
                    (* or .../memory/* etc.) while the agent is wired to specific
                    resources -> over-grant. This is the exact shape of the lab's
                    RoleC (bedrock-agentcore:* on memory/*).
  - action_gap:     granted bedrock-agentcore actions beyond those the wired
                    resources require (per docs/role-mapping). Conservative.

Static text parsing (brace-matched blocks) is used instead of full HCL parsing
because role policies are jsonencode(...) strings that python-hcl2 leaves opaque.

Usage:
  python3 gap.py --corpus corpus_s1 --json gap_s1.json
"""
import argparse, json, os, re, glob, hashlib

# --- R4: exclusion + content-hash dedup ---
# Repos that are not real-world deployments: provider test fixtures and
# intentionally-vulnerable security labs. Excluded from prevalence.
EXCLUDE_SUBSTR = (
    "terraform-provider-aws", "terraform-provider-awscc",   # provider testdata
    "pathfinding-labs", "cloudgoat", "iam-vulnerable", "aigoat",
    "attack-path-lab", "klanker-maker",
    "building-and-automating-penetration-testing",
)

def is_excluded(path):
    p = path.replace(os.sep, "/").lower()
    if "/testdata/" in p:
        return True
    return any(s in p for s in EXCLUDE_SUBSTR)

def template_hash(template_dir):
    """sha256 of this dir's concatenated sorted *.tf contents (forks -> same hash)."""
    parts = []
    for f in sorted(glob.glob(os.path.join(template_dir, "*.tf"))):
        try:
            parts.append(open(f, encoding="utf-8", errors="ignore").read())
        except Exception:
            pass
    return hashlib.sha256("\n".join(parts).encode("utf-8", "ignore")).hexdigest()

AGENTCORE_RES = ("memory", "code_interpreter", "gateway", "gateway_target",
                 "browser", "runtime")
# minimal required actions per wired resource type (from docs/role-mapping.md)
REQUIRED = {
    "memory": {"GetMemoryRecord", "RetrieveMemoryRecords", "GetEvent",
               "ListMemoryRecords", "ListEvents", "CreateEvent",
               "BatchCreateMemoryRecords", "BatchUpdateMemoryRecords"},
    "code_interpreter": {"StartCodeInterpreterSession", "InvokeCodeInterpreter",
                         "StopCodeInterpreterSession", "GetCodeInterpreterSession",
                         "ListCodeInterpreterSessions"},
    "gateway": {"GetGatewayTarget", "ListGatewayTargets"},
    "gateway_target": {"GetGatewayTarget", "ListGatewayTargets"},
}
AC = "bedrock-agentcore"
# baseline actions EVERY agent runtime legitimately needs (workload-identity
# bootstrap). AgentCore mediates memory/tool access through these tokens, not
# through direct bedrock-agentcore:GetMemoryRecord grants in the execution role,
# so these must NOT be counted as over-grant (verified on vendor TF 2026-10-04).
BASELINE_AC = {"GetWorkloadAccessToken", "GetWorkloadAccessTokenForJWT",
               "GetWorkloadAccessTokenForUserId"}


def tf_text(dirpath):
    out = []
    for p in glob.glob(os.path.join(dirpath, "*.tf")):
        try:
            out.append(open(p, encoding="utf-8", errors="ignore").read())
        except Exception:
            pass
    return "\n".join(out)


def blocks(text, header_re):
    """Yield (match, body) for resource blocks matching header_re, brace-matched."""
    for m in re.finditer(header_re, text):
        i = text.find("{", m.end() - 1)
        if i < 0:
            continue
        depth = 0
        j = i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        yield m, text[i:j + 1]


def scan_template(dirpath):
    t = tf_text(dirpath)
    res = {
        "has_agent_runtime": False,
        "agentcore_resources": [],      # (type, localname)
        "wired": [],                    # resource types the runtime references
        "wired_recovered": False,
        "granted_ac_actions": set(),    # bedrock-agentcore actions granted
        "granted_ac_wildcard_resource": False,  # AC action on * or /type/*
        "granted_full_ac_star": False,  # bedrock-agentcore:* granted
        "resource_scope_gap": False,
        "action_gap": set(),
        "action_gap_pct": None,   # PrivLess-style: % of granted AC actions unnecessary for wired resources
    }

    # 1) agentcore resources declared in this template
    for m, _ in blocks(t, r'resource\s+"aws_bedrockagentcore_([a-z_]+)"\s+"([A-Za-z0-9_\-]+)"'):
        rtype, lname = m.group(1), m.group(2)
        res["agentcore_resources"].append((rtype, lname))

    # 2) agent_runtime block(s): wired set from env-var refs + role_arn
    role_local = None
    for m, body in blocks(t, r'resource\s+"aws_bedrockagentcore_agent_runtime"\s+"([A-Za-z0-9_\-]+)"'):
        res["has_agent_runtime"] = True
        # env-var / attribute references to agentcore resources
        for ref in re.finditer(r'aws_bedrockagentcore_([a-z_]+)\.([A-Za-z0-9_\-]+)\.(id|arn)', body):
            res["wired"].append(ref.group(1))
        # role_arn = aws_iam_role.<name>.arn
        rm = re.search(r'role_arn\s*=\s*aws_iam_role\.([A-Za-z0-9_\-]+)\.arn', body)
        if rm:
            role_local = rm.group(1)
    res["wired"] = sorted(set(res["wired"]))
    # recovery: we resolved at least one wired agentcore resource by reference,
    # OR the runtime is co-located with agentcore resources we can attribute.
    if res["wired"]:
        res["wired_recovered"] = True
    elif res["has_agent_runtime"] and res["agentcore_resources"]:
        # co-located but not referenced in the runtime block: weaker, mark as
        # recovered-by-colocation only if exactly the colocated set is unambiguous
        res["wired"] = sorted(set(rt for rt, _ in res["agentcore_resources"]
                                  if rt in ("memory", "code_interpreter", "gateway")))
        res["wired_recovered"] = bool(res["wired"])

    # 3) granted: execution role's inline policies
    #    find aws_iam_role_policy whose role references role_local (or any, fallback)
    policy_texts = []
    for m, body in blocks(t, r'resource\s+"aws_iam_role_policy"\s+"[A-Za-z0-9_\-]+"'):
        if role_local is None or re.search(r'role\s*=\s*aws_iam_role\.' + re.escape(role_local) + r'\.', body):
            policy_texts.append(body)
    if not policy_texts:
        # fallback: any inline role policy in the template
        for m, body in blocks(t, r'resource\s+"aws_iam_role_policy"\s+"[A-Za-z0-9_\-]+"'):
            policy_texts.append(body)
    blob = "\n".join(policy_texts)

    # bedrock-agentcore:* full grant
    if re.search(r'"' + re.escape(AC) + r':\*"', blob):
        res["granted_full_ac_star"] = True
        res["granted_ac_actions"].add("*")
    # specific bedrock-agentcore:Action tokens
    for a in re.findall(r'"' + re.escape(AC) + r':([A-Za-z]+)"', blob):
        res["granted_ac_actions"].add(a)
    # AC action on a wildcard resource? detect a statement where an AC action and
    # a wildcard resource co-occur (approx at policy-blob level)
    has_ac = res["granted_full_ac_star"] or any(a != "*" for a in res["granted_ac_actions"])
    wildcard_res = bool(re.search(r'"Resource"\s*[:=]\s*\[?\s*"\*"', blob) or
                        re.search(r':(memory|runtime|code-interpreter|gateway)/\*"', blob) or
                        re.search(r'"' + re.escape(AC) + r':\*"[\s\S]{0,400}?"\*"', blob))
    res["granted_ac_wildcard_resource"] = bool(has_ac and wildcard_res)

    # 4) gaps
    # resource-scope gap: AC granted on wildcard resource while wired is specific
    if res["granted_ac_wildcard_resource"] and res["wired_recovered"]:
        res["resource_scope_gap"] = True
    # action gap: granted AC actions beyond required(wired)
    required = set()
    for w in res["wired"]:
        required |= REQUIRED.get(w, set())
    UNIVERSE_AC = 223   # total bedrock-agentcore actions (service authorization reference)
    # granted AC actions excluding the always-needed workload-identity baseline
    granted_specific = set(a for a in res["granted_ac_actions"]
                           if a != "*" and a not in BASELINE_AC)
    # CANDIDATE over-grant actions: granted (non-baseline) AC actions not explained
    # by the wired resources. NOT a validated "unnecessary" set - some may be real
    # runtime needs (e.g. InvokeAgentRuntime for an orchestrator) visible only in
    # container code. Confirmation is R2 (code sampling). Reported as a candidate
    # count, not as a clean PrivLess % (AgentCore's token model breaks that).
    allowed = required | BASELINE_AC
    if res["granted_full_ac_star"]:
        res["action_gap"] = ["<all-beyond-required (bedrock-agentcore:*)>"]
        res["action_gap_pct"] = (round(100.0 * (UNIVERSE_AC - len(allowed)) / UNIVERSE_AC, 1)
                                 if res["wired_recovered"] else None)
    elif granted_specific and res["wired_recovered"]:
        cand = granted_specific - required
        res["action_gap"] = sorted(cand)
        # share of non-baseline granted actions not explained by wired resources
        res["action_gap_pct"] = round(100.0 * len(cand) / len(granted_specific), 1) if granted_specific else 0.0
    else:
        res["action_gap"] = sorted(granted_specific - required) if granted_specific else []
        res["action_gap_pct"] = 0.0 if (res["wired_recovered"] and not granted_specific) else None
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--json", default="gap.json")
    a = ap.parse_args()

    # templates = dirs that directly contain an agent_runtime
    cand = set()
    for p in glob.glob(os.path.join(a.corpus, "**", "*.tf"), recursive=True):
        if os.sep + ".terraform" + os.sep in p:
            continue
        cand.add(os.path.dirname(p))

    rows = []
    n_excluded = 0
    n_dup = 0
    seen_hashes = set()
    for d in sorted(cand):
        r = scan_template(d)
        if not r["has_agent_runtime"]:
            continue
        # R4: drop provider testdata / security labs
        if is_excluded(d):
            n_excluded += 1
            continue
        # R4: content-hash dedup (forks produce identical template content)
        h = template_hash(d)
        if h in seen_hashes:
            n_dup += 1
            continue
        seen_hashes.add(h)
        r["template"] = os.path.relpath(d, a.corpus)
        r["granted_ac_actions"] = sorted(r["granted_ac_actions"])
        r["action_gap"] = sorted(r["action_gap"])
        rows.append(r)
    print(f"R4 filter: excluded (testdata/labs) {n_excluded}, deduped (fork copies) {n_dup}  -> clean set below")

    import statistics
    n = len(rows)
    rec = sum(1 for r in rows if r["wired_recovered"])
    rsg = sum(1 for r in rows if r["resource_scope_gap"])
    star = sum(1 for r in rows if r["granted_full_ac_star"])
    pcts = [r["action_gap_pct"] for r in rows if r["action_gap_pct"] is not None]
    print(f"templates with agent_runtime: {n}")
    if n:
        print(f"  wired recovered:            {rec}/{n}  ({100.0*rec/n:.1f}%)   <- Gate-1 metric")
        print(f"  resource-scope gap:         {rsg}/{n}  ({100.0*rsg/n:.1f}%)")
        print(f"  granted bedrock-agentcore:*: {star}/{n}  ({100.0*star/n:.1f}%)")
    if pcts:
        over = sum(1 for p in pcts if p > 0)
        print(f"  CANDIDATE action over-grant % (non-baseline AC actions not explained by wired")
        print(f"     resources; needs R2 code confirmation, NOT validated unnecessary; n={len(pcts)}):")
        print(f"     mean {statistics.mean(pcts):.1f}%  median {statistics.median(pcts):.1f}%  "
              f"max {max(pcts):.1f}%  (templates with any candidate: {over}/{len(pcts)})")
    for r in rows:
        gp = r["action_gap_pct"]
        gp = f"{gp}%" if gp is not None else "n/a"
        print(f"  - {r['template']}: wired={r['wired']} recovered={r['wired_recovered']} "
              f"ac*={r['granted_full_ac_star']} rscope_gap={r['resource_scope_gap']} action_gap={gp}")
    json.dump({"n": n, "wired_recovered": rec, "resource_scope_gap": rsg,
               "full_ac_star": star, "rows": rows}, open(a.json, "w"), indent=2)
    print(f"written: {a.json}")


if __name__ == "__main__":
    main()

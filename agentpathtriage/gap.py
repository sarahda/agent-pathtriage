#!/usr/bin/env python3
"""
AgentPathTriage - config-to-role gap (gap.py v1)

v1 change (unit of analysis): scoring is now per AGENT RUNTIME, not per template.

  v0 scored one row per template directory. When a template declared more than
  one aws_bedrockagentcore_agent_runtime, v0 kept only the LAST role_arn it
  happened to read, so every other runtime in that template was never scored.
  Worse, the text was assembled with an unsorted glob, so "last" depended on
  filesystem order: the same template could score differently on two machines.
  v1 resolves each runtime's own execution role and scores each runtime
  separately, and all file reads are sorted, so a run is reproducible.

Per agent runtime:
  - wired(runtime):  agentcore resources this runtime is tied to, resolved from
                     env-var references to aws_bedrockagentcore_*.{id,arn} inside
                     that runtime's own block; if the block carries no reference,
                     fall back to agentcore resources co-located in the template
                     (recorded as wired_source="colocation", a weaker signal).
  - granted(role):   bedrock-agentcore actions + resource scopes in the inline
                     policies (aws_iam_role_policy) attached to the role this
                     runtime references via role_arn. If role_arn cannot be
                     resolved statically, fall back to every inline role policy
                     in the template and record role_resolved=False.
  - resource_scope_gap: the role grants bedrock-agentcore on a WILDCARD resource
                     (* or .../memory/* etc.) while the runtime is wired to
                     specific resources -> over-grant.
  - action_gap:      granted bedrock-agentcore actions beyond those the wired
                     resources require (per docs/role-mapping). Conservative.

Known coverage limit (measured, not assumed): permissions reaching a role through
aws_iam_policy + aws_iam_role_policy_attachment, through an inline_policy block
inside aws_iam_role, or through managed_policy_arns are NOT read. Each row carries
attachment_count / managed_policy_arn_count so the share of roles whose grants are
partly invisible to this pass is reportable rather than guessed.

Static text parsing (brace-matched blocks) is used instead of full HCL parsing
because role policies are jsonencode(...) strings that python-hcl2 leaves opaque.

Usage:
  python3 gap.py --corpus corpus_s1 --json gap_s1.json
"""
import argparse, json, os, re, sys, glob, hashlib

# --- R4: exclusion + content-hash dedup ---
# Repos that are not real-world deployments: provider test fixtures and
# intentionally-vulnerable security labs. Excluded from prevalence.
EXCLUDE_SUBSTR = (
    "terraform-provider-aws", "terraform-provider-awscc",   # provider testdata
    "pathfinding-labs", "cloudgoat", "iam-vulnerable", "aigoat",
    "attack-path-lab", "klanker-maker",
    "building-and-automating-penetration-testing",
    # self-contamination: this project's own repo was cloned into the corpus by
    # the tier2 collector (it matches the same GitHub code-search signals).
    "agent-pathtriage",
)

def is_excluded(path, root=None):
    """Is this template excluded, judged on its path INSIDE the corpus.

    `root` must be given whenever the caller has an absolute path. The
    substrings name repositories within the corpus, not places on disk, and
    matching them against the whole path makes the result depend on where the
    corpus happens to live. That is not hypothetical: one of the substrings is
    `agent-pathtriage`, which is this repository's own directory name, so
    running with an absolute path excluded every template in the corpus and
    reported zero findings with no warning. The default clone name is the one
    that triggers it.
    """
    if root:
        try:
            path = os.path.relpath(path, root)
        except ValueError:
            pass
    p = path.replace(os.sep, "/").lower()
    if "/testdata/" in p:
        return True
    return any(s in p for s in EXCLUDE_SUBSTR)

def tf_files(dirpath):
    """*.tf in this dir, sorted. Sorting is what makes a run reproducible."""
    return sorted(glob.glob(os.path.join(dirpath, "*.tf")))

def template_hash(template_dir):
    """sha256 of this dir's concatenated sorted *.tf contents (forks -> same hash)."""
    parts = []
    for f in tf_files(template_dir):
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
UNIVERSE_AC = 223   # total bedrock-agentcore actions (service authorization reference)
# co-location fallback only attributes resource types an execution role would
# plausibly be wired to; browser/runtime are excluded because their presence in a
# template does not imply this runtime consumes them.
COLOCATION_TYPES = ("memory", "code_interpreter", "gateway")


def tf_text(dirpath):
    out = []
    for p in tf_files(dirpath):
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


def index_role_policies(text):
    """role local name -> list of inline aws_iam_role_policy bodies.

    A role is referenced as aws_iam_role.<local>.id / .arn / .name. Policies whose
    role cannot be attributed to a local role are collected under None so the
    unresolved-role fallback can still see them.
    """
    by_role = {}
    for _, body in blocks(text, r'resource\s+"aws_iam_role_policy"\s+"[A-Za-z0-9_\-]+"'):
        m = re.search(r'\brole\s*=\s*aws_iam_role\.([A-Za-z0-9_\-]+)\.', body)
        by_role.setdefault(m.group(1) if m else None, []).append(body)
    return by_role


def index_role_attachments(text):
    """role local name -> count of policy attachments (coverage limit metric)."""
    counts = {}
    for _, body in blocks(text, r'resource\s+"aws_iam_role_policy_attachment"\s+"[A-Za-z0-9_\-]+"'):
        m = re.search(r'\brole\s*=\s*aws_iam_role\.([A-Za-z0-9_\-]+)\.', body)
        key = m.group(1) if m else None
        counts[key] = counts.get(key, 0) + 1
    return counts


def index_role_managed_arns(text):
    """role local name -> count of managed_policy_arns entries (coverage limit)."""
    counts = {}
    for m, body in blocks(text, r'resource\s+"aws_iam_role"\s+"([A-Za-z0-9_\-]+)"'):
        name = m.group(1)
        mp = re.search(r'managed_policy_arns\s*=\s*\[([\s\S]*?)\]', body)
        if mp:
            counts[name] = len([x for x in re.findall(r'"[^"]*"|[A-Za-z0-9_\.\-\[\]]+',
                                                      mp.group(1)) if x.strip()])
        if re.search(r'\binline_policy\s*{', body):
            # an inline_policy block is a grant source this pass does not read
            counts[name] = counts.get(name, 0)
    return counts


def analyse_policies(policy_bodies, wired):
    """Compute the granted/gap fields for one role's inline policy set."""
    blob = "\n".join(policy_bodies)
    granted = set()
    full_star = bool(re.search(r'"' + re.escape(AC) + r':\*"', blob))
    if full_star:
        granted.add("*")
    for a in re.findall(r'"' + re.escape(AC) + r':([A-Za-z]+)"', blob):
        granted.add(a)

    has_ac = full_star or any(a != "*" for a in granted)
    wildcard_res = bool(re.search(r'"Resource"\s*[:=]\s*\[?\s*"\*"', blob) or
                        re.search(r':(memory|runtime|code-interpreter|gateway)/\*"', blob) or
                        re.search(r'"' + re.escape(AC) + r':\*"[\s\S]{0,400}?"\*"', blob))
    wildcard_resource = bool(has_ac and wildcard_res)

    required = set()
    for w in wired:
        required |= REQUIRED.get(w, set())
    allowed = required | BASELINE_AC
    granted_specific = set(a for a in granted if a != "*" and a not in BASELINE_AC)
    recovered = bool(wired)

    if full_star:
        action_gap = ["<all-beyond-required (bedrock-agentcore:*)>"]
        action_gap_pct = (round(100.0 * (UNIVERSE_AC - len(allowed)) / UNIVERSE_AC, 1)
                          if recovered else None)
    elif granted_specific and recovered:
        cand = granted_specific - required
        action_gap = sorted(cand)
        action_gap_pct = round(100.0 * len(cand) / len(granted_specific), 1)
    else:
        action_gap = sorted(granted_specific - required) if granted_specific else []
        action_gap_pct = 0.0 if (recovered and not granted_specific) else None

    return {
        "granted_ac_actions": sorted(granted),
        "granted_full_ac_star": full_star,
        "granted_ac_wildcard_resource": wildcard_resource,
        "resource_scope_gap": bool(wildcard_resource and recovered),
        "action_gap": action_gap,
        "action_gap_pct": action_gap_pct,
    }


def scan_template(dirpath):
    """Return one record per aws_bedrockagentcore_agent_runtime in this template."""
    t = tf_text(dirpath)

    agentcore_resources = []
    for m, _ in blocks(t, r'resource\s+"aws_bedrockagentcore_([a-z_]+)"\s+"([A-Za-z0-9_\-]+)"'):
        agentcore_resources.append((m.group(1), m.group(2)))
    colocated = sorted(set(rt for rt, _ in agentcore_resources if rt in COLOCATION_TYPES))

    policies_by_role = index_role_policies(t)
    attachments_by_role = index_role_attachments(t)
    managed_by_role = index_role_managed_arns(t)
    all_inline_policies = [b for bodies in policies_by_role.values() for b in bodies]

    runtimes = []
    for m, body in blocks(t, r'resource\s+"aws_bedrockagentcore_agent_runtime"\s+"([A-Za-z0-9_\-]+)"'):
        rt_name = m.group(1)
        wired = sorted(set(ref.group(1) for ref in re.finditer(
            r'aws_bedrockagentcore_([a-z_]+)\.([A-Za-z0-9_\-]+)\.(id|arn)', body)))
        wired_source = "reference" if wired else None
        if not wired and colocated:
            wired = list(colocated)
            wired_source = "colocation"

        rm = re.search(r'role_arn\s*=\s*aws_iam_role\.([A-Za-z0-9_\-]+)\.arn', body)
        role_local = rm.group(1) if rm else None
        role_resolved = role_local is not None
        if role_resolved:
            bodies = policies_by_role.get(role_local, [])
        else:
            # cannot attribute a role statically: fall back to every inline role
            # policy in the template, as v0 did, and mark the row.
            bodies = all_inline_policies

        rec = {
            "runtime": rt_name,
            "role_local": role_local,
            "role_resolved": role_resolved,
            "inline_policy_count": len(bodies),
            "attachment_count": attachments_by_role.get(role_local, 0),
            "managed_policy_arn_count": managed_by_role.get(role_local, 0),
            "wired": wired,
            "wired_source": wired_source,
            "wired_recovered": bool(wired),
            "agentcore_resources": agentcore_resources,
        }
        rec.update(analyse_policies(bodies, wired))
        runtimes.append(rec)
    return runtimes


def collect(corpus, cache, budget):
    """Fill the cache one repository at a time. Returns True when the corpus is done.

    Sliced by repository rather than scanned in one pass, because a single
    recursive walk of the corpus costs minutes on a network or FUSE mount and a
    measurement that cannot be re-run is a measurement that cannot be checked.
    Each repository's rows are appended as they are produced, so an interrupted
    run resumes instead of restarting. Delete the cache to force a clean
    re-measurement, which is required after any change to the extractor.
    """
    import time
    deadline = time.time() + budget if budget else None

    done_repos = set()
    if os.path.exists(cache):
        for ln in open(cache):
            try:
                row = json.loads(ln)
            except Exception:
                continue
            if row.get("_repo_done"):
                done_repos.add(row["_repo_done"])

    repos = sorted(x for x in os.listdir(corpus)
                   if os.path.isdir(os.path.join(corpus, x)))
    todo = [r for r in repos if r not in done_repos]
    if not todo:
        return True

    out = open(cache, "a")
    for repo in todo:
        if deadline and time.time() > deadline:
            out.close()
            print(f"budget reached: {len(done_repos)}/{len(repos)} repositories cached, "
                  f"run again to continue", file=sys.stderr)
            return False
        root = os.path.join(corpus, repo)
        cand = sorted({os.path.dirname(p)
                       for p in glob.glob(os.path.join(root, "**", "*.tf"), recursive=True)
                       if os.sep + ".terraform" + os.sep not in p})
        for d in cand:
            runtimes = scan_template(d)
            if not runtimes:
                continue
            out.write(json.dumps({"d": os.path.relpath(d, corpus),
                                  "excluded": bool(is_excluded(d, corpus)),
                                  "h": template_hash(d),
                                  "runtimes": runtimes}) + "\n")
        out.write(json.dumps({"_repo_done": repo}) + "\n")
        out.flush()
        done_repos.add(repo)
    out.close()
    return True


def load_rows(cache):
    """Cache to rows, applying the exclusion filter and fork de-duplication.

    Both filters run here rather than during collection so the cache stays a raw
    record of what was scanned: changing a filter re-derives the numbers without
    re-walking the corpus, and the counts it reports stay honest.
    """
    rows, n_templates, n_excluded, n_dup = [], 0, 0, 0
    seen = set()
    entries = []
    for ln in open(cache):
        try:
            row = json.loads(ln)
        except Exception:
            continue
        if not row.get("_repo_done"):
            entries.append(row)
    for e in sorted(entries, key=lambda r: r["d"]):
        if e["excluded"]:
            n_excluded += 1
            continue
        if e["h"] in seen:
            n_dup += 1
            continue
        seen.add(e["h"])
        n_templates += 1
        for r in e["runtimes"]:
            r["template"] = e["d"]
            rows.append(r)
    return rows, n_templates, n_excluded, n_dup


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--json", default="gap.json")
    ap.add_argument("--cache", help="resumable per-repository cache "
                                    "(default: <json>.cache.jsonl)")
    ap.add_argument("--budget", type=float, default=0,
                    help="stop after this many seconds and exit for resumption; "
                         "0 runs to completion")
    a = ap.parse_args()
    cache = a.cache or a.json + ".cache.jsonl"

    if not collect(a.corpus, cache, a.budget):
        print("INCOMPLETE")
        return 1
    rows, n_templates, n_excluded, n_dup = load_rows(cache)

    print(f"R4 filter: excluded (testdata/labs) {n_excluded}, deduped (fork copies) {n_dup}  -> clean set below")
    if n_excluded and not rows:
        print("\nERROR: every template was excluded, which is never a real "
              "result. The exclusion substrings name repositories inside the "
              "corpus; if one of them also appears in the path TO the corpus, "
              "everything matches. Check the corpus path.", file=sys.stderr)
        return 1

    import statistics
    n = len(rows)
    rec = sum(1 for r in rows if r["wired_recovered"])
    byref = sum(1 for r in rows if r["wired_source"] == "reference")
    rsg = sum(1 for r in rows if r["resource_scope_gap"])
    star = sum(1 for r in rows if r["granted_full_ac_star"])
    unres = sum(1 for r in rows if not r["role_resolved"])
    att = sum(1 for r in rows if r["attachment_count"] > 0)
    multi = n - n_templates
    pcts = [r["action_gap_pct"] for r in rows if r["action_gap_pct"] is not None]

    print(f"templates with >=1 agent_runtime: {n_templates}")
    print(f"agent runtimes (unit of analysis): {n}   (+{multi} from multi-runtime templates)")
    if n:
        print(f"  wired recovered:            {rec}/{n}  ({100.0*rec/n:.1f}%)   <- Gate-1 metric")
        print(f"     of which by reference:   {byref}/{n}  ({100.0*byref/n:.1f}%)  (rest: co-location)")
        print(f"  resource-scope gap:         {rsg}/{n}  ({100.0*rsg/n:.1f}%)")
        print(f"  granted bedrock-agentcore:*: {star}/{n}  ({100.0*star/n:.1f}%)")
        print(f"  role_arn unresolved (fallback to all template policies): {unres}/{n}")
        print(f"  roles with >=1 policy attachment NOT read by this pass:  {att}/{n}  <- coverage limit")
    if pcts:
        over = sum(1 for p in pcts if p > 0)
        print(f"  CANDIDATE action over-grant % (non-baseline AC actions not explained by wired")
        print(f"     resources; needs R2 code confirmation, NOT validated unnecessary; n={len(pcts)}):")
        print(f"     mean {statistics.mean(pcts):.1f}%  median {statistics.median(pcts):.1f}%  "
              f"max {max(pcts):.1f}%  (runtimes with any candidate: {over}/{len(pcts)})")
    for r in rows:
        gp = r["action_gap_pct"]
        gp = f"{gp}%" if gp is not None else "n/a"
        print(f"  - {r['template']}::{r['runtime']}: wired={r['wired']} src={r['wired_source']} "
              f"role={r['role_local']} ac*={r['granted_full_ac_star']} "
              f"rscope_gap={r['resource_scope_gap']} action_gap={gp}")
    json.dump({"unit": "agent_runtime", "n_runtimes": n, "n_templates": n_templates,
               "wired_recovered": rec, "wired_by_reference": byref,
               "resource_scope_gap": rsg, "full_ac_star": star,
               "role_unresolved": unres, "roles_with_unread_attachments": att,
               "rows": rows}, open(a.json, "w"), indent=2)
    print(f"written: {a.json}")
    print("COMPLETE")
    return 0


if __name__ == "__main__":
    sys.exit(main())

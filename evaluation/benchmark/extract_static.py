#!/usr/bin/env python3
"""
AgentPathTriage - static corpus scanner (extract_static, v3)

For the prevalence study (E2) we analyse published IaC templates WITHOUT deploying
them. `extract` reads deployed Terraform state; this reads RAW .tf source
statically with python-hcl2, so it runs over a cloned corpus at zero cost.

What it detects, per template (a directory of .tf):
  - delegation primitive on the IDENTITY side: iam:PassRole or sts:AssumeRole in
    an identity policy. NOT a role's trust policy (assume_role_policy / an
    aws_iam_policy_document that has `principals` and no `resources`), which is the
    resource side and legitimate on its own.
  - over-privilege: an identity statement whose ACTION is admin-grade ("*", "*:*",
    "iam:*", "sts:*") AND whose Resource is a wildcard, or an attached admin-grade
    managed policy (AdministratorAccess / IAMFullAccess / PowerUserAccess).
  - wildcard PassRole: iam:PassRole whose Resource is "*".

A template is `chainable` when it has BOTH a delegation primitive AND an
over-privileged target. Prevalence signal, deliberately scoped: presence of the
enabling pattern, not a claim any specific deployment is exploitable.

Precision notes (v3): admin-grade "*" is matched only in ACTION position, never a
Resource "*"; service-wildcards iam:*/sts:*/*:* are matched anywhere (they are
never Resources). aws_iam_policy_document data sources are judged per-statement
from parsed structure (actions / resources / principals), so a trust policy is not
miscounted as an identity-side delegation. Inline jsonencode / heredoc policies are
still matched by text (not structurally parseable), with the same action-position
rule. A file that fails to parse is recorded as parse_error (fail closed).

Usage:
    python3 extract_static.py --corpus ./corpus --json prevalence_raw.json
"""
import argparse, json, os, re, glob
import hcl2

ADMIN_MANAGED = ("AdministratorAccess", "IAMFullAccess", "PowerUserAccess")

# Agentic services whose service-wildcard (`svc:*`) on a broad resource is the
# over-privilege this project targets (the lab's RoleC = bedrock-agentcore:* on
# memory/*). Narrowly scoped to the agent substrate, NOT every AWS service.
AGENTIC_SERVICES = ("bedrock-agentcore", "bedrock", "sagemaker", "bedrock-agent", "qbusiness")

# --- text patterns for INLINE (jsonencode/heredoc) policy strings ---
# admin "*" only when it is the Action field value (not a Resource "*")
ACTION_STAR = re.compile(r'"?Action"?\s*[:=]\s*\[?\s*"\*"', re.I)
# service-wildcards that are unambiguously ACTIONS (never a Resource ARN)
ADMIN_SVC_WILDCARD = re.compile(r'"(iam:\*|sts:\*|\*:\*)"', re.I)
# any service-wildcard action token, capturing the service prefix
SVC_WILDCARD = re.compile(r'"([a-z0-9-]+):\*"', re.I)
PASSROLE = re.compile(r'iam:PassRole', re.I)
ASSUMEROLE = re.compile(r'sts:AssumeRole', re.I)
WILDCARD_RES = re.compile(r'"?Resource"?\s*[:=]\s*\[?\s*"\*"', re.I)


def text_has_admin_action(t):
    return bool(ACTION_STAR.search(t) or ADMIN_SVC_WILDCARD.search(t))


def text_agentic_services(t):
    """Agentic service-wildcard services (svc:*) present in the policy text."""
    return {m.lower() for m in SVC_WILDCARD.findall(t) if m.lower() in AGENTIC_SERVICES}


def iter_tf_files(template_dir, recursive=True):
    pat = os.path.join(template_dir, "**", "*.tf") if recursive else os.path.join(template_dir, "*.tf")
    for p in glob.glob(pat, recursive=recursive):
        if os.sep + ".terraform" + os.sep in p:
            continue
        yield p


def load_blocks(path):
    """Return (resources, data_blocks, parse_ok)."""
    try:
        with open(path) as fh:
            d = hcl2.load(fh)
    except Exception:
        return [], [], False
    res, data = [], []
    for r in d.get("resource", []):
        for rtype, body in r.items():
            for name, vals in body.items():
                res.append((rtype.strip('"'), vals))
    for r in d.get("data", []):
        for dtype, body in r.items():
            for name, vals in body.items():
                data.append((dtype.strip('"'), vals))
    return res, data, True


def _strings(v):
    """Flatten any nested list/dict value into the string leaves it contains."""
    out = []
    if isinstance(v, str):
        out.append(v)
    elif isinstance(v, list):
        for x in v:
            out.extend(_strings(x))
    elif isinstance(v, dict):
        for x in v.values():
            out.extend(_strings(x))
    return out


def _actions_admin(actions):
    low = [a.lower() for a in actions]
    return any(a in ("*", "*:*", "iam:*", "sts:*") for a in low)


def _actions_agentic_svcwild(actions):
    """Agentic services whose `svc:*` wildcard appears in this action list."""
    out = set()
    for a in actions:
        a = a.lower()
        if a.endswith(":*"):
            svc = a[:-2]
            if svc in AGENTIC_SERVICES:
                out.add(svc)
    return out


def _has(actions, name):
    name = name.lower()
    return any(a.lower() == name for a in actions)


def scan_policy_document(vals, flags):
    """Structural per-statement scan of an aws_iam_policy_document data source.
    Skips trust-side statements (principals present, no resources)."""
    stmts = vals.get("statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        return
    for st in stmts:
        if not isinstance(st, dict):
            continue
        actions = _strings(st.get("actions", st.get("action", [])))
        resources = _strings(st.get("resources", st.get("resource", [])))
        has_principals = bool(st.get("principals") or st.get("principal"))
        # trust / resource side: a statement that names principals and no
        # resources is an assume-role trust policy, not an identity grant.
        if has_principals and not resources:
            continue
        res_wild = any(r == "*" for r in resources)
        if _has(actions, "iam:PassRole"):
            flags["has_passrole_identity"] = True
            if res_wild:
                flags["has_wildcard_passrole"] = True
        if _has(actions, "sts:AssumeRole"):
            flags["has_assumerole_identity"] = True
        # precise, same-statement: admin / agentic over-privilege require the
        # wildcard resource to be IN THE SAME statement as the broad action.
        if _actions_admin(actions) and res_wild:
            flags["has_overpriv_classic"] = True
        if res_wild and _actions_agentic_svcwild(actions):
            flags["has_overpriv_agentic"] = True


def scan_inline_policy(pol, flags):
    """Text scan of an inline jsonencode/heredoc identity policy string."""
    if PASSROLE.search(pol):
        flags["has_passrole_identity"] = True
        if WILDCARD_RES.search(pol):
            flags["has_wildcard_passrole"] = True
    if ASSUMEROLE.search(pol):
        flags["has_assumerole_identity"] = True
    # inline strings can't be tied statement-by-statement; template-level coupling.
    if WILDCARD_RES.search(pol):
        if text_has_admin_action(pol):
            flags["has_overpriv_classic"] = True
        if text_agentic_services(pol):
            flags["has_overpriv_agentic"] = True


def scan_template(template_dir, recursive=True):
    flags = {
        "has_passrole_identity": False,
        "has_assumerole_identity": False,
        "has_wildcard_passrole": False,
        "has_overpriv_classic": False,     # *, iam:*, sts:*, *:*  on wildcard resource
        "has_overpriv_agentic": False,     # bedrock-agentcore:* / bedrock:* / sagemaker:* on wildcard resource
        "has_admin_managed": False,
        "files": 0, "parse_errors": 0,
    }
    for path in iter_tf_files(template_dir, recursive=recursive):
        flags["files"] += 1
        res, data, ok = load_blocks(path)
        if not ok:
            flags["parse_errors"] += 1
            continue
        for rtype, vals in res:
            if rtype in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy",
                         "aws_iam_group_policy"):
                scan_inline_policy(str(vals.get("policy", "")), flags)
            if rtype in ("aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
                         "aws_iam_policy_attachment"):
                if any(a in str(vals.get("policy_arn", "")) for a in ADMIN_MANAGED):
                    flags["has_admin_managed"] = True
            if rtype in ("aws_iam_role", "aws_iam_user"):
                if any(a in str(vals.get("managed_policy_arns", "")) for a in ADMIN_MANAGED):
                    flags["has_admin_managed"] = True
        for dtype, vals in data:
            if dtype == "aws_iam_policy_document":
                scan_policy_document(vals, flags)

    delegation = flags["has_passrole_identity"] or flags["has_assumerole_identity"]
    overpriv_classic = flags["has_overpriv_classic"] or flags["has_admin_managed"]
    overpriv_agentic = flags["has_overpriv_agentic"]
    flags["delegation"] = delegation
    flags["overprivilege_classic"] = overpriv_classic
    flags["overprivilege_agentic"] = overpriv_agentic
    flags["overprivilege"] = overpriv_classic or overpriv_agentic
    # chainable at each tier: the paper's headline is the AGENTIC tier (matches the
    # lab's RoleA->RoleC bedrock-agentcore:* escalation); classic is the IAM-only tier.
    flags["chainable_classic"] = bool(delegation and overpriv_classic)
    flags["chainable_agentic"] = bool(delegation and overpriv_agentic)
    flags["chainable"] = bool(delegation and (overpriv_classic or overpriv_agentic))
    return flags


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, help="dir with one subdir per template")
    ap.add_argument("--json", default="prevalence_raw.json")
    a = ap.parse_args()

    templates = sorted(d for d in glob.glob(os.path.join(a.corpus, "*")) if os.path.isdir(d))
    rows = []
    for t in templates:
        f = scan_template(t)
        f["template"] = os.path.basename(t)
        rows.append(f)

    n = len(rows)
    def pct(key):
        c = sum(1 for r in rows if r[key])
        return c, (100.0 * c / n if n else 0.0)

    print(f"templates scanned: {n}")
    for key in ("delegation", "overprivilege_classic", "overprivilege_agentic",
                "chainable_classic", "chainable_agentic", "chainable", "has_wildcard_passrole"):
        c, p = pct(key)
        print(f"  {key:24s}: {c}/{n}  ({p:.1f}%)")
    pe = sum(r["parse_errors"] for r in rows)
    print(f"  files with parse errors (fail-closed): {pe}")

    json.dump({"n": n, "rows": rows}, open(a.json, "w"), indent=2)
    print(f"written: {a.json}")


if __name__ == "__main__":
    main()

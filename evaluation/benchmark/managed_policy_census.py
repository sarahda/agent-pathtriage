#!/usr/bin/env python3
"""Which AWS managed policies the corpus attaches, and to which roles.

The live experiment of the case study hands the attacker one managed policy
and nothing else. Whether that is a position published deployments put a
principal in is a question about the corpus, not about the account, so this
pass answers it from the source text.

It reads every `aws_iam_role_policy_attachment` block in a template directory,
takes the `policy_arn` and the `role` expressions out of the block, and groups
the result by policy. A configuration counts once however many times it
attaches the same policy, and the runtimes it covers come from the topology
rather than from this scan, so the two files disagree loudly if the corpus and
the topology have drifted apart.

What this does not do is resolve the role name. The condition on the target
policy's iam:PassRole statement is a glob over the name of the role being
passed, and a deployment is free to build that name from a variable. This scan
reports the expression as written. Deciding the glob needs a bound value, and
the limitations section says so.

  python3 evaluation/benchmark/managed_policy_census.py \
      --corpus corpus_tier2 \
      --topology evaluation/benchmark/topology_tier2.json \
      --policy BedrockAgentCoreFullAccess \
      --json evaluation/benchmark/managed_policy_census.json
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys

ATTACHMENT = re.compile(
    r'resource\s+"aws_iam_role_policy_attachment"\s+"([^"]+)"\s*\{', re.M)
POLICY_ARN = re.compile(r'^\s*policy_arn\s*=\s*(.+?)\s*$', re.M)
ROLE = re.compile(r'^\s*role\s*=\s*(.+?)\s*$', re.M)


def block_of(text, start):
    """The text of one braced block, from the brace that `start` points past."""
    depth, i = 0, text.index("{", start - 1)
    begin = i
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[begin:i + 1]
        i += 1
    return text[begin:]


# An AWS managed policy lives under the aws account in the iam namespace. A
# policy the deployment defines itself is a different object with a different
# owner, and counting the two together would make the census unreadable.
# The partition is often written as an interpolation, so the anchor is the
# iam::aws:policy path rather than the literal arn:aws prefix.
AWS_MANAGED = re.compile(r':iam::aws:policy/(\S+?)"?\s*$')


def policy_name(expr):
    """The AWS managed policy's name, or None for anything else.

    Terraform writes these as a literal ARN or as an interpolation over the
    partition, and both carry the `iam::aws:policy/` path. A customer managed
    policy, a reference to a policy resource, and an expression that does not
    resolve to a literal are all excluded: the first is not an AWS policy, and
    the other two name no policy this pass can read. The service-role/ prefix
    is part of the name and is kept.
    """
    if expr is None:
        return None
    cleaned = expr.strip().rstrip(",")
    m = AWS_MANAGED.search(cleaned)
    if not m:
        return None
    name = m.group(1).strip().strip('"')
    # An interpolation anywhere in the name leaves it undecided.
    if "${" in name or not name:
        return None
    return name


def scan_template(template_dir):
    """Every managed policy attachment in one template directory."""
    found = []
    for root, _dirs, files in os.walk(template_dir):
        for fn in sorted(files):
            if not fn.endswith(".tf"):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            for m in ATTACHMENT.finditer(text):
                body = block_of(text, m.end())
                arn = POLICY_ARN.search(body)
                role = ROLE.search(body)
                found.append({
                    "block": m.group(1),
                    "file": os.path.relpath(path, template_dir),
                    "policy_arn_expression": arn.group(1) if arn else None,
                    "policy": policy_name(arn.group(1) if arn else None),
                    "role_expression": role.group(1).strip() if role else None,
                })
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus_tier2")
    ap.add_argument("--topology", default=None,
                    help="topology_tier2.json, the published population")
    ap.add_argument("--policy", default="BedrockAgentCoreFullAccess",
                    help="the managed policy the case study uses")
    ap.add_argument("--grant-note", default=None,
                    help="what the target policy grants, and when it was read; "
                         "recorded with the result so the count carries the "
                         "version it was taken against")
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    topology_path = a.topology or os.path.join(here, "topology_tier2.json")
    with open(topology_path) as fh:
        topology = json.load(fh)

    by_policy = collections.defaultdict(
        lambda: {"configurations": 0, "runtimes": 0})
    hits, missing = [], []
    runtimes_total = 0

    for entry in topology:
        template = entry["t"]
        n_agents = entry.get("n_agents", 0)
        runtimes_total += n_agents
        path = os.path.join(a.corpus, template)
        if not os.path.isdir(path):
            missing.append(template)
            continue

        found = scan_template(path)
        seen = set()
        for f in found:
            if not f["policy"] or f["policy"] in seen:
                continue
            seen.add(f["policy"])
            by_policy[f["policy"]]["configurations"] += 1
            by_policy[f["policy"]]["runtimes"] += n_agents

        naming_it = [f for f in found if f["policy"] == a.policy]
        if naming_it:
            roles = sorted({f["role_expression"] for f in naming_it
                            if f["role_expression"]})
            hits.append({
                "config": template,
                "runtimes": n_agents,
                "n_agents": n_agents,
                "attachment_blocks_naming_it": len(naming_it),
                "roles_it_is_attached_to": roles,
            })

    confirmed = [h for h in hits if h["roles_it_is_attached_to"]]
    multi = [h for h in confirmed if h["n_agents"] > 1]
    per_agent = [h for h in multi
                 if h["attachment_blocks_naming_it"] > 1
                 and len(h["roles_it_is_attached_to"]) > 1]

    out = {
        "population": f"{os.path.basename(topology_path)}, "
                      f"the published {len(topology)} configurations, "
                      "deduplicated by content hash. Every count in this file, "
                      "by_policy included, is scoped to those configurations "
                      "and not to the wider collection the corpus directory "
                      "holds.",
        "configurations": len(topology),
        "runtimes_summed_from_n_agents": runtimes_total,
        "configurations_not_on_disk": len(missing),
        "target_policy": a.policy,
        "configurations_referencing_it": len(hits),
        "runtimes_in_them": sum(h["runtimes"] for h in hits),
        "role_attachment_confirmed": len(confirmed),
        "runtimes_in_role_confirmed": sum(h["runtimes"] for h in confirmed),
        "role_confirmed_and_multi_agent": len(multi),
        "runtimes_in_role_confirmed_multi_agent": sum(h["runtimes"]
                                                      for h in multi),
        "attached_once_per_agent": len(per_agent),
        "by_policy": {k: v for k, v in sorted(
            by_policy.items(),
            key=lambda kv: (-kv[1]["configurations"], kv[0]))},
        "hits": hits,
    }
    if a.grant_note:
        out["policy_document_grant"] = a.grant_note
    if missing:
        out["not_on_disk"] = missing

    print(f"population {len(topology)} configurations, "
          f"{runtimes_total} runtimes")
    if missing:
        print(f"NOT ON DISK  {len(missing)} configuration(s); "
              f"the corpus and the topology have drifted apart")
    print(f"{a.policy}")
    print(f"  referenced in            {len(hits)} configuration(s)")
    print(f"  role attachment read in  {len(confirmed)}, "
          f"covering {sum(h['runtimes'] for h in confirmed)} runtime(s)")
    print(f"  of those, multi-agent    {len(multi)}, "
          f"covering {sum(h['runtimes'] for h in multi)} runtime(s)")
    print(f"  attached once per agent  {len(per_agent)}")

    if a.json:
        with open(a.json, "w") as fh:
            json.dump(out, fh, indent=1)
        print(f"\nwrote {a.json}")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())

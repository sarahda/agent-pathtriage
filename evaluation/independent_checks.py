#!/usr/bin/env python3
"""Second checks for the claims that had none.

Appendix A reports a precision wherever a separate pass re-derived a number
from the raw source. Nine claims had no such pass. This adds one for the four
that can be counted a different way, and says why the rest cannot.

Each check here re-derives its number from the Terraform text with its own
patterns, not by reading the analysis output. Agreement means two routes to
the same number; disagreement names the configurations that differ.

  python3 evaluation/independent_checks.py \\
      --corpus corpus_tier2 --bench evaluation/benchmark \\
      --json independent_checks.json

exit 0  every check agrees with the published figure
exit 1  at least one disagrees
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

# A runtime block, and the role argument inside it. Deliberately different
# expressions from the ones extract_graph uses, so a shared bug in one regex
# does not survive into both counts.
RUNTIME_BLOCK = re.compile(
    r'resource\s+"aws_bedrockagentcore_agent_runtime"\s+"([^"]+)"', re.M)
PASSROLE = re.compile(r'"iam:PassRole"', re.I)
ROLE_RESOURCE = re.compile(r'resource\s+"aws_iam_role"\s+"([^"]+)"', re.M)
AGENT_SERVICE = re.compile(r'bedrock-agentcore\.amazonaws\.com')
# A Foundry agent as a deployed resource, by any of the spellings a template
# could use. The published claim is that none of these appear.
# Microsoft.App/agents is Container Apps and not an AI Foundry agent, so the
# provider has to be named rather than any resource type ending in /agents.
FOUNDRY_AGENT = re.compile(
    r'(Microsoft\.CognitiveServices/accounts/projects/agents'
    r'|azurerm_ai_foundry_agent'
    r'|"type"\s*:\s*"Microsoft\.CognitiveServices/[^"]*/agents"'
    r'|resource\s+"azapi_resource"[^}]{0,400}?'
    r'Microsoft\.CognitiveServices/[^"]*/agents)', re.I | re.S)


def tf_text(directory):
    """Every .tf file's text in one string, with its path kept per file."""
    out = {}
    for dp, dn, fn in os.walk(directory):
        dn[:] = [d for d in dn if d not in (".git", ".terraform", "node_modules")]
        for f in fn:
            if not f.endswith(".tf"):
                continue
            p = os.path.join(dp, f)
            try:
                with open(p, encoding="utf-8", errors="ignore") as fh:
                    out[p] = fh.read()
            except Exception:
                pass
    return out



def published_value(artifact, *keys, bench="evaluation/benchmark"):
    """The figure the paper publishes, read from its artifact.

    A check with no published counterpart cannot disagree with anything, so
    every check that has one reads it here rather than printing a bare count.
    """
    path = os.path.join(bench, artifact)
    try:
        with open(path) as fh:
            node = json.load(fh)
    except Exception:
        return None
    for k in keys:
        if not isinstance(node, dict) or k not in node:
            return None
        node = node[k]
    return node


def check_multi_agent(corpus, topo):
    """Configurations declaring two or more runtime blocks, counted again."""
    mine, theirs = set(), {e["t"] for e in topo if e.get("n_agents", 0) >= 2}
    for e in topo:
        d = os.path.join(corpus, e["t"])
        if not os.path.isdir(d):
            continue
        n = sum(len(RUNTIME_BLOCK.findall(t)) for t in tf_text(d).values())
        if n >= 2:
            mine.add(e["t"])
    return {
        "claim": "configurations declaring two or more agents",
        "published": len(theirs),
        "re_derived": len(mine),
        "agree": mine == theirs,
        "only_in_published": sorted(theirs - mine),
        "only_in_re_derived": sorted(mine - theirs),
    }


def enclosing_statement(text, pos):
    """The policy statement object that contains the character at pos.

    A character window is not enough: a long policy document puts many
    statements within a few hundred characters of each other, and a wildcard
    resource in a neighbouring statement is not this statement's resource.
    This walks out to the braces that enclose pos.
    """
    depth, start = 0, None
    for i in range(pos, -1, -1):
        if text[i] == "}":
            depth += 1
        elif text[i] == "{":
            if depth == 0:
                start = i
                break
            depth -= 1
    if start is None:
        return None
    depth, end = 0, None
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    return text[start:end] if end else None


def strip_comments(block):
    """Terraform comment lines, removed. A commented out resource is not a
    grant, and the corpus contains statements whose entries are all
    commented out."""
    out = []
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        out.append(re.sub(r'\s+#.*$', '', line))
    return "\n".join(out)


def check_passrole_over_agent_role(corpus, topo):
    """Configurations granting iam:PassRole where an agent role is in range.

    Counted without the analysis: a configuration qualifies when it declares a
    runtime, a role whose trust policy admits the agent service, and a policy
    statement that both grants iam:PassRole and carries a wildcard resource in
    that same statement.
    """
    hits = []
    for e in topo:
        d = os.path.join(corpus, e["t"])
        if not os.path.isdir(d):
            continue
        files = tf_text(d)
        blob = "\n".join(files.values())
        if not RUNTIME_BLOCK.search(blob) or not AGENT_SERVICE.search(blob):
            continue
        for path, text in files.items():
            found = False
            for m in PASSROLE.finditer(text):
                stmt = enclosing_statement(text, m.start())
                if not stmt:
                    continue
                stmt = strip_comments(stmt)
                if re.search(r'Resource\s*=\s*"\*"', stmt) or \
                   re.search(r'Resource\s*=\s*\[[^\]]*"\*"', stmt, re.S):
                    hits.append({"config": e["t"],
                                 "file": os.path.relpath(path, d)})
                    found = True
                    break
            if found:
                break
    pub = published_value("corpus_takeover_census.json",
                          "passrole_wide_enough_to_cover_a_sibling_agent_role",
                          "configurations")
    out = {
        "claim": "configurations granting iam:PassRole broadly enough to "
                 "cover a role an agent runs as",
        "re_derived": len(hits),
        "detail": hits,
        "method": "the wildcard must sit in the same policy statement as the "
                  "iam:PassRole action, with commented out lines removed",
    }
    if pub is not None:
        out["published"] = pub
        out["agree"] = (pub == len(hits))
    return out


def check_foundry_agents(foundry_corpus):
    """Foundry template directories declaring an agent as a deployed resource."""
    if not foundry_corpus or not os.path.isdir(foundry_corpus):
        return {"claim": "Foundry directories declaring an agent",
                "skipped": "corpus not present"}
    dirs, hits = 0, []
    for dp, dn, fn in os.walk(foundry_corpus):
        dn[:] = [d for d in dn if d not in (".git", "node_modules")]
        names = [f for f in fn
                 if f.endswith((".json", ".bicep", ".tf", ".yaml", ".yml"))]
        if not names:
            continue
        dirs += 1
        for f in names:
            try:
                with open(os.path.join(dp, f), encoding="utf-8",
                          errors="ignore") as fh:
                    if FOUNDRY_AGENT.search(fh.read()):
                        hits.append(os.path.relpath(os.path.join(dp, f),
                                                    foundry_corpus))
                        break
            except Exception:
                pass
    pub = published_value("foundry_recon.json", "dirs_with_an_agent")
    out = {
        "claim": "Foundry template directories declaring an agent resource",
        "directories_seen": dirs,
        "re_derived": len(hits),
        "detail": hits[:20],
    }
    if pub is not None:
        out["published"] = pub
        out["agree"] = (pub == len(hits))
    return out


def check_no_cross_agent_chain(corpus, topo):
    """The zero, approached from the other side.

    A cross-agent chain needs a configuration with two agents whose roles
    differ, and a principal in it holding both the update action and a pass
    over the second role. This counts the configurations that clear the first
    two conditions, which is the set a chain could possibly live in.
    """
    candidates = []
    for e in topo:
        if e.get("n_agents", 0) < 2:
            continue
        d = os.path.join(corpus, e["t"])
        if not os.path.isdir(d):
            continue
        blob = "\n".join(tf_text(d).values())
        roles = set(re.findall(r'role_arn\s*=\s*([^\n]+)', blob))
        update = re.search(r'bedrock-agentcore:(\*|UpdateAgentRuntime)', blob)
        if len(roles) >= 2 and update:
            candidates.append({"config": e["t"],
                               "distinct_role_expressions": len(roles)})
    return {
        "claim": "configurations where a cross-agent chain could exist at all",
        "re_derived": len(candidates),
        "detail": candidates,
        "note": "a chain needs more than this; the published result is that "
                "none of these completes",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus_tier2")
    ap.add_argument("--foundry-corpus", default="corpus_foundry")
    ap.add_argument("--bench", default="evaluation/benchmark")
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    with open(os.path.join(a.bench, "topology_tier2.json")) as fh:
        topo = json.load(fh)

    checks = [
        check_multi_agent(a.corpus, topo),
        check_passrole_over_agent_role(a.corpus, topo),
        check_no_cross_agent_chain(a.corpus, topo),
        check_foundry_agents(a.foundry_corpus),
    ]

    bad = 0
    uncompared = 0
    for c in checks:
        if c.get("skipped"):
            print(f"SKIP  {c['claim']}: {c['skipped']}")
            continue
        line = f"  {c['claim']}"
        if "published" in c:
            ok = c.get("agree")
            bad += 0 if ok else 1
            print(f"{'OK  ' if ok else 'DIFF'}{line}")
            print(f"        published {c['published']}  "
                  f"re-derived {c['re_derived']}")
            for k in ("only_in_published", "only_in_re_derived"):
                if c.get(k):
                    print(f"        {k}: {', '.join(c[k][:6])}")
        else:
            uncompared += 1
            print(f"NOCMP{line}")
            print(f"        re-derived {c['re_derived']}  "
                  f"(no published figure to compare against)")
    print(f"\nchecks: {len(checks)}, compared: {len(checks) - uncompared}, "
          f"disagreeing: {bad}, not compared: {uncompared}")

    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"checks": checks}, fh, indent=1)
        print(f"written: {a.json}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

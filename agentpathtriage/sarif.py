#!/usr/bin/env python3
"""Findings as SARIF 2.1.0, for a code scanning tab.

Why this exists and what it is not. It is not a claim in the paper: nothing in
the evaluation depends on a SARIF file. It is there because an artifact that
can only be read by running it and reading its stdout is an artifact nobody
runs twice, and because a repository owner who gets a disclosure is far more
likely to act on a finding that appears in the interface they already use than
on a markdown file in an email.

Two details carry weight.

Suppressed findings are written out, marked suppressed, rather than dropped.
A baseline is a statement that somebody looked at a finding and decided to
live with it, which is a different thing from the finding not existing. SARIF
has a place to say exactly that, and GitHub reads it as a dismissal, so the
finding stays visible and stays closed. Dropping them instead would make the
artifact disagree with itself: the tool would be reporting a clean scan of a
template it had just found four escalations in.

Locations are relative to a base directory, defaulting to the working
directory. GitHub resolves a result's path against the repository root and
silently discards anything it cannot place, so a path that escapes the base is
rewritten relative to the scanned directory rather than left absolute. A
finding whose line could not be determined is still emitted, against the first
file in the directory, and carries `located: false` in its properties so the
line is not mistaken for evidence.
"""
import json
import os
import re

from findings import RULES

SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
          "Schemata/sarif-schema-2.1.0.json")
INFORMATION_URI = "https://github.com/sarahda/agent-pathtriage"
FINGERPRINT_KEY = "agentPathTriage/finding/v1"

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def version():
    """The package version, read from pyproject so it cannot drift from it."""
    p = os.path.join(_ROOT, "pyproject.toml")
    try:
        m = re.search(r'^version\s*=\s*"([^"]+)"', open(p).read(), re.M)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "0.0.0"


def _pascal(name):
    return "".join(w.capitalize() for w in name.split("-"))


def _uri(path, base, tfdir):
    """A relative path GitHub can resolve, or the best available substitute."""
    if not path:
        return None
    for root in (base, tfdir):
        if not root:
            continue
        try:
            rel = os.path.relpath(path, root)
        except ValueError:
            continue
        if not rel.startswith(".."):
            return rel.replace(os.sep, "/")
    return os.path.basename(path)


def _rules_block():
    out = []
    for rid in sorted(RULES):
        r = RULES[rid]
        out.append({
            "id": rid,
            "name": _pascal(r["name"]),
            "shortDescription": {"text": r["short"]},
            "fullDescription": {"text": r["help"]},
            "help": {"text": r["help"],
                     "markdown": f"**{r['short']}**\n\n{r['help']}"},
            "defaultConfiguration": {"level": r["level"]},
            "properties": {
                "tags": ["security", "iam", "agentic", r["name"]],
                "problem.severity": ("error" if r["level"] == "error"
                                     else "recommendation"),
            },
        })
    return out


def _result(f, rule_ids, base, tfdir, suppressed):
    idx = rule_ids.index(f["rule"])
    res = {
        "ruleId": f["rule"],
        "ruleIndex": idx,
        "level": f["level"],
        "message": {"text": f["message"]},
        "partialFingerprints": {FINGERPRINT_KEY: f["fingerprint"]},
        "properties": {k: v for k, v in f.items()
                       if k in ("principal", "reaches", "action", "via_role",
                                "hops", "conditional", "role", "agents",
                                "roles", "service", "policies", "scope",
                                "reaches_type", "actions", "located",
                                "fails_run")},
    }
    uri = _uri(f.get("file"), base, tfdir)
    if uri:
        res["locations"] = [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, int(f.get("line") or 1))},
            }
        }]
    if suppressed:
        res["suppressions"] = [{
            "kind": "external",
            "justification": "present in the baseline supplied to this run",
        }]
    return res


def build(new, suppressed=(), base=None, tfdir=None):
    """A SARIF log for one scan.

    `new` and `suppressed` are both written. Separating them is the baseline's
    job; hiding one of them is not.
    """
    base = os.path.abspath(base or os.getcwd())
    tfdir = os.path.abspath(tfdir) if tfdir else None
    rule_ids = sorted(RULES)
    results = ([_result(f, rule_ids, base, tfdir, False) for f in new]
               + [_result(f, rule_ids, base, tfdir, True) for f in suppressed])
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "AgentPathTriage",
                "semanticVersion": version(),
                "version": version(),
                "informationUri": INFORMATION_URI,
                "rules": [_rules_block()[rule_ids.index(r)]
                          for r in rule_ids],
            }},
            "automationDetails": {"id": "agentpathtriage/scan"},
            "columnKind": "utf16CodeUnits",
            "results": results,
        }],
    }


def write(path, new, suppressed=(), base=None, tfdir=None):
    doc = build(new, suppressed, base, tfdir)
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    return doc

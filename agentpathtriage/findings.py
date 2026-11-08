#!/usr/bin/env python3
"""One list of findings, with a stable name for each.

Two features need the same thing and had better agree on it: suppressing
findings a reviewer has already triaged, and writing findings out as SARIF for
a code scanning tab. Both need every finding to be a separate item carrying a
name that survives a re-run. The per-principal result rows are not that: one
row can hold a delegation escalation, a self escalation and a linter-visible
wildcard grant at once, and the row says nothing about where in the source any
of it is written.

So this flattens report.build into one record per finding, names each one by a
fingerprint over the facts that make it that finding, and locates it in the
Terraform that declares it.

What goes into a fingerprint decides what suppression hides, which makes it a
security decision rather than a formatting one. The rule here is that a
fingerprint carries the finding and not the explanation. For a delegation
escalation that is the principal, the resource reached and the action, and not
the chain that got there. A different chain to the same resource with the same
action is the same fact about who can reach what, so it stays suppressed. A
new resource, a new action or a new principal is a new fact, so it surfaces.
Leaving the chain out is deliberate in both directions: putting it in would
make every old finding reappear whenever an unrelated hand-off was added
somewhere else in the template, and a baseline that cries wolf gets deleted.

The six rules, and which of them a CI run fails on:

  APT001  delegation-escalation     fail   the contribution: reach that exists
                                           only because of a hand-off
  APT002  self-escalation           fail   the principal can rewrite its own
                                           permissions
  APT003  shared-execution-role     fail   two agents run as one role, so each
                                           already holds the other's permissions
  APT004  unquantified-escalation   fail   a real gain whose extent cannot be
                                           read from the configuration
  APT005  interchangeable-roles     warn   a service is trusted by more than
                                           one role with nothing narrowing it
  APT006  own-policy-risk           note   a wildcard grant the principal holds
                                           under its own identity. A policy
                                           linter finds these. Reported for
                                           completeness and attributed as such

APT005 and APT006 do not fail a run. Neither is this project's claim, and
neither is on its own a defect.
"""
import glob
import hashlib
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_ROOT, "evaluation", "benchmark")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

RULES = {
    "APT001": {
        "name": "delegation-escalation",
        "short": "Reach gained only through a hand-off",
        "level": "error",
        "help": "This principal reaches a resource that nothing in its own "
                "policies grants. The reach exists because it can acquire a "
                "second identity. Narrow the hand-off, or narrow what the "
                "second identity holds.",
    },
    "APT002": {
        "name": "self-escalation",
        "short": "The principal can rewrite its own permissions",
        "level": "error",
        "help": "The principal holds an action that lets it grant itself more. "
                "Its effective reach is therefore everything, whatever its "
                "current policies say.",
    },
    "APT003": {
        "name": "shared-execution-role",
        "short": "Two or more agents run as one execution role",
        "level": "error",
        "help": "Each agent already holds every permission the others hold, so "
                "anything that reaches the weaker agent acts with the stronger "
                "agent's authority. A policy linter cannot report this: the "
                "role and its policy are unremarkable, and the defect is in "
                "binding two agents to it. Give each agent its own role.",
    },
    "APT004": {
        "name": "unquantified-escalation",
        "short": "Escalation whose extent cannot be read from configuration",
        "level": "error",
        "help": "The principal reaches a role carrying an AWS managed policy "
                "whose document lives at AWS rather than in this repository. "
                "The gain is real; its size cannot be measured from source.",
    },
    "APT005": {
        "name": "interchangeable-roles",
        "short": "One service is trusted by several roles, unconditionally",
        "level": "warning",
        "help": "Nothing narrows which of these roles the service may use, so "
                "anything able to make that service act can choose among them. "
                "Add a condition, usually aws:SourceArn or aws:SourceAccount, "
                "to each trust policy.",
    },
    "APT006": {
        "name": "own-policy-risk",
        "short": "Wildcard-scoped grant held under the principal's own identity",
        "level": "note",
        "help": "Visible without any delegation. A policy linter reports these "
                "too; it is included so the delegation findings above can be "
                "read as the part that needed this tool.",
    },
}

# The rules a CI run fails on. APT005 and APT006 are reported and do not fail,
# which is what keeps the exit code meaning what it meant before these existed.
FAILING = ("APT001", "APT002", "APT003", "APT004")

BASELINE_FORMAT = "agentpathtriage/baseline/1"


# ---------------------------------------------------------------- fingerprints

def fingerprint(*parts):
    """A short stable name for a finding.

    Joined on a unit separator rather than concatenated, so that two different
    tuples cannot spell the same string: ("a", "bc") and ("ab", "c") are
    distinct findings and must stay distinct names.
    """
    h = hashlib.sha256("\x1f".join(str(p) for p in parts).encode())
    return h.hexdigest()[:16]


def analyser_stamp():
    """A hash of the code that decides what a finding is.

    A baseline records fingerprints, and a fingerprint only means what it meant
    when it was written if the analyser is the same analyser. This is the same
    lesson as the corpus cache, which once outlived the code that wrote it and
    reported 84 templates where there were 220: a stored judgement has to carry
    the identity of whatever made it.
    """
    h = hashlib.sha256()
    for f in ("reach.py", "extract_graph.py", "iam_eval.py", "report.py",
              "findings.py"):
        p = os.path.join(_HERE, f)
        if not os.path.exists(p):
            h.update(f"missing:{f}".encode())
            continue
        with open(p, "rb") as fh:
            h.update(f.encode())
            h.update(fh.read())
    return h.hexdigest()[:16]


# -------------------------------------------------------------------- locating

RESOURCE_HEADER = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')


def resource_lines(tfdir):
    """(type, name) -> (absolute path, 1-based line) for every resource block.

    Comments are blanked out first, by the same function the parser uses, which
    preserves offsets. That matters twice over: a resource header inside a
    comment must not be found, and the line number has to be the line in the
    real file rather than in some rewritten copy of it.

    A duplicate (type, name) is a Terraform error, so the first one wins and
    the collision is not worth reporting here.
    """
    import tf_to_state as T
    out = {}
    files = sorted(p for p in glob.glob(os.path.join(tfdir, "**", "*.tf"),
                                        recursive=True)
                   if os.sep + ".terraform" + os.sep not in p)
    for p in files:
        try:
            raw = open(p, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        blanked = T.strip_comments(raw)
        for m in RESOURCE_HEADER.finditer(blanked):
            key = (m.group(1), m.group(2))
            if key in out:
                continue
            out[key] = (os.path.abspath(p), raw.count("\n", 0, m.start()) + 1)
    return out


def arn_index(state):
    """ARN -> (type, name), so a finding about an ARN can be put on a line."""
    out = {}
    for r in state.get("values", {}).get("root_module", {}).get("resources", []):
        arn = (r.get("values") or {}).get("arn")
        if isinstance(arn, str) and arn not in out:
            out[arn] = (r.get("type"), r.get("name"))
    return out


class Locator:
    """Turns an ARN into a file and a line, or says it could not.

    Where it cannot, a finding still has to land somewhere for a code scanning
    tab to show it at all, so it falls back to the first Terraform file in the
    directory. The fallback is recorded on the finding as `located: False` so
    that nobody reads a line number as evidence of anything.
    """

    def __init__(self, tfdir):
        self.tfdir = os.path.abspath(tfdir) if tfdir else None
        self.lines = resource_lines(self.tfdir) if self.tfdir else {}
        self.fallback = None
        if self.tfdir:
            first = sorted(glob.glob(os.path.join(self.tfdir, "**", "*.tf"),
                                     recursive=True))
            if first:
                self.fallback = (os.path.abspath(first[0]), 1)

    def of_resource(self, rtype, rname):
        hit = self.lines.get((rtype, rname))
        if hit:
            return {"file": hit[0], "line": hit[1], "located": True}
        return self.unknown()

    def of_arn(self, arn, index):
        key = index.get(arn)
        if key:
            return self.of_resource(*key)
        return self.unknown()

    def unknown(self):
        if self.fallback:
            return {"file": self.fallback[0], "line": self.fallback[1],
                    "located": False}
        return {"file": None, "line": None, "located": False}


# -------------------------------------------------------------------- collect

def _shared_execution_roles(ix):
    """role ARN -> the agents that all run as it, where there is more than one.

    The same condition shared_role.py measures over the corpus, asked of one
    template. An agent whose role_arn did not resolve is left out rather than
    grouped under a None key, because an unresolved value could be hiding
    either answer and guessing would invent a finding.
    """
    by_role = {}
    for name, meta in getattr(ix, "agents", {}).items():
        role = (meta or {}).get("role_arn")
        if role is None or str(role) == "None":
            continue
        by_role.setdefault(str(role), []).append(name)
    return {r: sorted(a) for r, a in by_role.items() if len(a) > 1}


def collect(state, tfdir=None):
    """Every finding in this state, flattened, named and located."""
    import report as RP

    rows, shared_trust, ix = RP.build(state)
    loc = Locator(tfdir)
    index = arn_index(state)
    out = []

    def add(rule, fp, message, where, **extra):
        rec = {"rule": rule, "rule_name": RULES[rule]["name"],
               "level": RULES[rule]["level"], "fingerprint": fp,
               "message": message, "fails_run": rule in FAILING}
        rec.update(where)
        rec.update(extra)
        out.append(rec)

    for row in rows:
        p = row["principal"]
        where = loc.of_arn(p, index)

        for w in row.get("delegation_only_risk", []):
            add("APT001",
                fingerprint("APT001", p, w["reaches"], w["action"]),
                f"{_short(p)} reaches {_short(w['reaches'])} with "
                f"{w['action']}, which none of its own policies grant. The "
                f"reach comes from assuming {_short(w['via_role'])} "
                f"({w['hops']} hop(s))"
                + (", under a condition." if w["conditional"] else "."),
                where,
                principal=p, reaches=w["reaches"], action=w["action"],
                via_role=w["via_role"], hops=w["hops"],
                conditional=w["conditional"])

        for act in row.get("self_escalation_via", []):
            add("APT002",
                fingerprint("APT002", p, act),
                f"{_short(p)} holds {act}, which lets it grant itself further "
                f"permissions under its own identity.",
                where, principal=p, action=act)

        for role, policies in (row.get("unreadable_managed_gained") or {}).items():
            if not row.get("unquantified"):
                continue
            add("APT004",
                fingerprint("APT004", p, role, *sorted(policies)),
                f"{_short(p)} reaches {_short(role)}, which carries "
                f"{', '.join(sorted(policies))}. That policy's document is "
                f"held by AWS and is not in this repository, so the reach "
                f"gained is real but cannot be measured from source.",
                where, principal=p, via_role=role,
                policies=sorted(policies))

        for own in row.get("own_policy_risk", []):
            actions = sorted(a for a in (own.get("actions") or []) if a)
            add("APT006",
                fingerprint("APT006", p, own["reaches_type"], *actions),
                f"{_short(p)} holds {', '.join(actions) or 'an action'} on "
                f"{own['reaches_type']} with scope {own.get('scope')}, under "
                f"its own identity and with no delegation involved.",
                where, principal=p, reaches_type=own["reaches_type"],
                actions=actions, scope=own.get("scope"))

    for role, agents in sorted(_shared_execution_roles(ix).items()):
        add("APT003",
            fingerprint("APT003", role, *agents),
            f"{len(agents)} agents run as {_short(role)}: "
            f"{', '.join(agents)}. Each already holds every permission the "
            f"others hold, so reaching any one of them acts with the "
            f"authority of all.",
            loc.of_arn(role, index),
            role=role, agents=agents)

    for service, roles in sorted(shared_trust.items()):
        roles = sorted(roles)
        add("APT005",
            fingerprint("APT005", service, *roles),
            f"{service} is trusted by {len(roles)} roles with nothing "
            f"narrowing the grant: {', '.join(_short(r) for r in roles)}. "
            f"Anything able to make that service act can choose among them.",
            loc.of_arn(roles[0], index),
            service=service, roles=roles)

    out.sort(key=lambda f: (f["rule"], f["fingerprint"]))
    return out


def _short(arn):
    """The tail of an ARN, for a message a person reads in a narrow column."""
    s = str(arn)
    return s.rsplit("/", 1)[-1] if s.startswith("arn:") else s


def failing(findings):
    return [f for f in findings if f["fails_run"]]


# ------------------------------------------------------------------- baseline

def write_baseline(findings, path):
    """Record what is known now, so a later run can say what is new.

    Only the failing rules are recorded. Baselining a note would be recording
    that a policy linter has an opinion, which nobody needs to triage.
    """
    doc = {
        "format": BASELINE_FORMAT,
        "analyser": analyser_stamp(),
        "fingerprints": {
            f["fingerprint"]: {"rule": f["rule"], "rule_name": f["rule_name"],
                               "message": f["message"]}
            for f in findings if f["fails_run"]
        },
    }
    with open(path, "w") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return doc


def read_baseline(path):
    doc = json.load(open(path))
    if doc.get("format") != BASELINE_FORMAT:
        raise ValueError(f"{path} is not an agentpathtriage baseline "
                         f"(format: {doc.get('format')!r})")
    return doc


def apply_baseline(findings, baseline):
    """Split into what is new and what the baseline already accounts for.

    Returns (new, suppressed, stale). `stale` is the part of the baseline that
    matched nothing, which is worth saying out loud: it is either a finding
    that got fixed, or a sign that the fingerprints have moved under the
    baseline and the suppression is no longer doing what its author meant.
    """
    known = set(baseline.get("fingerprints", {}))
    new, suppressed = [], []
    for f in findings:
        (suppressed if f["fingerprint"] in known else new).append(f)
    seen = {f["fingerprint"] for f in findings}
    stale = sorted(known - seen)
    return new, suppressed, stale


def baseline_warning(baseline):
    """The one case where suppression is dangerous enough to say so."""
    if baseline.get("analyser") != analyser_stamp():
        return ("this baseline was written by a different build of the "
                "analyser, so a fingerprint in it may no longer mean what it "
                "meant when it was written. Re-write the baseline after "
                "reviewing the findings.")
    return None

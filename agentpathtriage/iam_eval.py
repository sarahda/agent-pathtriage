#!/usr/bin/env python3
"""
AgentPathTriage - IAM policy evaluation core (iam_eval)

One place where "does this policy allow this" is decided, so the agentic extractor
and the generic IAM extractor cannot drift apart. Before this module there were two
implementations with different wildcard rules, different handling of users, and
neither of them read Deny at all, while model/act-scope.md stated that an explicit
Deny always wins.

What this module decides:
  - action matching with IAM glob semantics (`*` and `?`), case-insensitive, so
    `bedrock-agentcore:*CodeInterpreter*` matches `InvokeCodeInterpreter`
  - resource matching with the same glob semantics over ARNs, so a PassRole target of
    `arn:aws:iam::123456789012:role/agentcore_*` matches both agentcore roles
  - explicit Deny beats Allow, evaluated per request rather than per statement, which
    is what the provider does and what act-scope.md already promised
  - NotAction and NotResource, because IAM-Vulnerable ships an exploitable NotAction
    case and ignoring the form silently turns it into a miss
  - conditions are recorded, not evaluated. A statement carrying conditions still
    grants, and the grant is tagged conditional so a caller can report it separately
    instead of pretending the condition was checked.

Scope limits, stated rather than implied:
  - permission boundaries, SCPs and session policies are not read
  - condition keys are not evaluated, so a conditional allow is reported as an allow
    with `conditional=True`
  - resource-based policies are handled only where the caller passes them in
"""
import fnmatch
import re

WILDCARD_CHARS = re.compile(r"[*?]")


def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def glob_match(pattern, value):
    """IAM glob match: `*` is any run, `?` is one character, comparison is case
    insensitive. fnmatch is reused but `[` must not become a character class,
    because ARNs contain no character classes and a literal `[` is possible."""
    if pattern is None or value is None:
        return False
    p = str(pattern).lower().replace("[", "[[]")
    return fnmatch.fnmatchcase(str(value).lower(), p)


def has_wildcard(pattern):
    return bool(WILDCARD_CHARS.search(str(pattern)))


def action_matches(pattern, action):
    """`*` alone matches everything. `svc:*` matches that service only."""
    if pattern == "*":
        return True
    return glob_match(pattern, action)


def resource_matches(pattern, resource):
    if pattern == "*":
        return True
    return glob_match(pattern, resource)


class Statement:
    """One policy statement, normalised."""

    __slots__ = ("effect", "actions", "not_actions", "resources", "not_resources",
                 "conditions", "sid", "source")

    def __init__(self, raw, source=None):
        self.effect = str(raw.get("Effect", "Allow"))
        self.actions = [str(a) for a in _as_list(raw.get("Action"))]
        self.not_actions = [str(a) for a in _as_list(raw.get("NotAction"))]
        self.resources = [str(r) for r in _as_list(raw.get("Resource"))]
        self.not_resources = [str(r) for r in _as_list(raw.get("NotResource"))]
        self.conditions = raw.get("Condition") or {}
        self.sid = raw.get("Sid")
        self.source = source

    @property
    def is_allow(self):
        return self.effect.lower() == "allow"

    @property
    def is_deny(self):
        return self.effect.lower() == "deny"

    def covers_action(self, action):
        if self.not_actions:
            return not any(action_matches(p, action) for p in self.not_actions)
        return any(action_matches(p, action) for p in self.actions)

    def covers_resource(self, resource):
        if self.not_resources:
            return not any(resource_matches(p, resource) for p in self.not_resources)
        if not self.resources:
            return False
        return any(resource_matches(p, resource) for p in self.resources)

    def resource_is_wildcard(self):
        if self.not_resources:
            return True          # NotResource grants everything except a list
        return any(r == "*" or has_wildcard(r) for r in self.resources)

    def resource_spans_many(self):
        """Does the resource pattern reach more than one named resource.

        `resource_is_wildcard` answers whether a `*` appears anywhere, which is
        too coarse for blast radius: it puts `runtime/*`, which is every
        runtime in the account, in the same class as
        `runtime/mcp/runtime-endpoint/*`, which is one named runtime's
        endpoints. Reporting the second as "permitted to call any agent" is
        wrong, and it also made a validated repair look like it had failed,
        because narrowing to the declared target still left a wildcard in the
        string.

        The rule is positional. In an ARN the resource id is the segment after
        the resource type; if that id is present and carries no wildcard, the
        pattern names one resource however many wildcards follow it.
        """
        if self.not_resources:
            return True
        return any(resource_spans_many(r) for r in self.resources)


def resource_spans_many(pattern):
    """True when the pattern can match more than one named resource."""
    p = str(pattern)
    if p == "*":
        return True
    if not has_wildcard(p):
        return False
    parts = p.split(":", 5)
    if len(parts) < 6:
        # not an ARN shape, so fall back to the coarse answer
        return True
    tail = parts[5]
    segs = tail.split("/")
    if len(segs) >= 2 and segs[0] and not has_wildcard(segs[0]):
        # a resource type followed by an id: the id decides
        return has_wildcard(segs[1]) or not segs[1]
    # `type:id` form, or a bare wildcard tail
    if ":" in tail:
        a, _, b = tail.partition(":")
        if a and not has_wildcard(a):
            return has_wildcard(b) or not b
    return True


def parse_statements(policy, source=None):
    """Accept a policy as a dict, a JSON string, or a list of statements."""
    import json
    if policy is None:
        return []
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except Exception:
            return []
    if isinstance(policy, list):
        raw = policy
    elif isinstance(policy, dict):
        raw = _as_list(policy.get("Statement", []))
    else:
        return []
    return [Statement(s, source) for s in raw if isinstance(s, dict)]


# --- partial condition evaluation ---------------------------------------------
#
# Conditions are not fully evaluated, because most keys depend on a request that
# does not exist at analysis time. What is decided here is narrower and sound in
# one direction: can an attacker ever satisfy this condition at all. A condition
# that can never hold makes its statement dead, and treating a dead statement as a
# grant is a false positive. Anything undecidable is treated as satisfiable, which
# keeps the pass over-approximating in the direction model/act-scope.md commits to.
#
# The benchmark pins both directions with one pair: IAM-Vulnerable's fn3 grants on
# DateGreaterThan aws:TokenIssueTime 2020-01-01, which always holds now and is
# exploitable, and fp5 grants on DateLessThan the same date, which can never hold
# and is the author's designed false positive.
import datetime as _dt

DATE_TESTS = ("datelessthan", "datelessthanequals",
              "dategreaterthan", "dategreaterthanequals")
IDENTITY_KEYS = ("aws:principalarn", "aws:userid", "aws:username")

SATISFIABLE, UNSATISFIABLE, UNKNOWN = True, False, None


def _parse_date(text):
    s = str(text).strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            return _dt.datetime.fromisoformat(s) if fmt is None \
                else _dt.datetime.strptime(str(text).strip(), fmt).replace(
                    tzinfo=_dt.timezone.utc)
        except Exception:
            continue
    return None


def condition_satisfiable(conditions, principal_arn=None, now=None):
    """UNSATISFIABLE only when a condition provably cannot hold. Else SATISFIABLE
    or UNKNOWN, and UNKNOWN is treated as satisfiable by the caller."""
    if not conditions:
        return SATISFIABLE
    now = now or _dt.datetime.now(_dt.timezone.utc)
    verdict = SATISFIABLE
    for test, block in conditions.items():
        if not isinstance(block, dict):
            continue
        t = str(test).lower().replace("ifexists", "")
        for key, values in block.items():
            vals = _as_list(values)
            k = str(key).lower()
            if t in DATE_TESTS:
                for v in vals:
                    when = _parse_date(v)
                    if when is None:
                        verdict = UNKNOWN if verdict is SATISFIABLE else verdict
                        continue
                    # the request happens now, so a window that closed in the past
                    # or opens in the future cannot be met
                    if t.startswith("dateless") and now >= when:
                        return UNSATISFIABLE
                    if t.startswith("dategreater") and now <= when:
                        return UNSATISFIABLE
            elif k in IDENTITY_KEYS and t.startswith("stringequals") and principal_arn:
                if not any(glob_match(v, principal_arn) or str(v) == str(principal_arn)
                           for v in vals):
                    return UNSATISFIABLE
            else:
                verdict = UNKNOWN if verdict is SATISFIABLE else verdict
    return verdict


class Decision:
    __slots__ = ("allowed", "conditional", "allow_statements", "deny_statements")

    def __init__(self, allowed, conditional, allow_statements, deny_statements):
        self.allowed = allowed
        self.conditional = conditional
        self.allow_statements = allow_statements
        self.deny_statements = deny_statements

    def __bool__(self):
        return self.allowed

    def __repr__(self):
        return (f"Decision(allowed={self.allowed}, conditional={self.conditional}, "
                f"allows={len(self.allow_statements)}, denies={len(self.deny_statements)})")


def evaluate(statements, action, resource, principal_arn=None, now=None):
    """Provider order: an explicit Deny that matches wins over any Allow.

    Returns a Decision rather than a bool so the caller can tell a clean allow from
    an allow that only holds because a condition was not evaluated. A statement
    whose condition can never be satisfied is dropped, because a dead statement is
    not a grant.
    """
    def live(s):
        return condition_satisfiable(s.conditions, principal_arn, now) is not UNSATISFIABLE

    denies = [s for s in statements
              if s.is_deny and s.covers_action(action) and s.covers_resource(resource)
              and live(s)]
    # an unconditional deny is final; a conditional deny might not fire at runtime,
    # so it is reported but does not erase the allow
    if any(not s.conditions for s in denies):
        return Decision(False, False, [], denies)
    allows = [s for s in statements
              if s.is_allow and s.covers_action(action) and s.covers_resource(resource)
              and live(s)]
    if not allows:
        return Decision(False, False, [], denies)
    conditional = all(
        condition_satisfiable(s.conditions, principal_arn, now) is UNKNOWN
        for s in allows) or bool(denies)
    return Decision(True, conditional, allows, denies)


def allowed_actions_on(statements, resource, action_universe):
    """Every action from `action_universe` this statement set allows on `resource`."""
    return {a for a in action_universe if evaluate(statements, a, resource).allowed}


def delegation_targets(statements, action, candidate_arns):
    """ARNs from `candidate_arns` that `action` (iam:PassRole, sts:AssumeRole) is
    allowed on, each with the scope of the pattern that matched.

    Scope is what makes blast radius reportable: `exact` names one role, `pattern`
    names a family such as role/agentcore_*, `any` is a bare `*`.
    """
    out = {}
    for arn in candidate_arns:
        d = evaluate(statements, action, arn)
        if not d.allowed:
            continue
        scope = "exact"
        for s in d.allow_statements:
            for r in s.resources:
                if not resource_matches(r, arn):
                    continue
                if r == "*":
                    scope = "any"
                elif has_wildcard(r):
                    scope = "pattern" if scope != "any" else scope
        out[arn] = {"scope": scope, "conditional": d.conditional}
    return out


# --- trust policies ------------------------------------------------------------

UNSCOPED_TRUST_KEYS = ("aws:sourcearn", "aws:sourceaccount", "sts:externalid",
                       "aws:principalarn", "aws:principalorgid")


def trust_entries_from_policy(assume_role_policy):
    """Who may assume this role, and whether the grant is narrowed by a condition.

    A service principal with no scoping condition is the mechanism behind the
    published AgentCore cross-agent escalations: two roles trusting the same service
    with nothing narrowing it are interchangeable to anything that can make that
    service act.

    Returns one dict per allowed trust principal:
      {kind, value, scoped, condition_keys}
    where `scoped` is True when the statement carries a condition key that actually
    narrows who may assume (source ARN, source account, external id, principal ARN,
    principal org). Any other condition key leaves `scoped` False, because it does
    not restrict the caller.
    """
    import json
    pol = assume_role_policy
    if isinstance(pol, str):
        try:
            pol = json.loads(pol)
        except Exception:
            return []
    if not isinstance(pol, dict):
        return []
    out = []
    for st in _as_list(pol.get("Statement", [])):
        if not isinstance(st, dict) or str(st.get("Effect", "Allow")).lower() != "allow":
            continue
        cond = st.get("Condition") or {}
        keys = sorted({k.lower() for block in cond.values() if isinstance(block, dict)
                       for k in block})
        scoped = any(k in UNSCOPED_TRUST_KEYS for k in keys)
        pr = st.get("Principal", {})
        if isinstance(pr, str):
            pr = {"AWS": pr}
        if not isinstance(pr, dict):
            continue
        for kind, vals in pr.items():
            for v in _as_list(vals):
                out.append({"kind": str(kind), "value": str(v),
                            "scoped": scoped, "condition_keys": keys})
    return out

"""AWS managed policy documents, read from a dated snapshot.

Why a snapshot and not the API. The predicate reads policies out of the
configuration, and an AWS managed policy is not in the configuration: the
configuration only names it. Expanding one therefore needs its document from
AWS. Fetching it at analysis time would make a published figure depend on what
AWS served that day, and AWS revises these documents, so the figure could not
be reproduced or cited. The snapshot records the document together with its
version and update date, so a number computed from it can be stated against a
known version.

What a missing policy means. A policy the snapshot does not carry stays
unexpanded, which is the behaviour the project already had: `unreadable_managed`
reports it and the extent of any escalation into it is recorded as not
measurable from configuration. Expansion narrows that set, it does not make it
disappear, and a policy listed under `unavailable` in the snapshot is one the
corpus names that does not exist at AWS at all.

The snapshot path is a parameter. Nothing here names a policy, so the set
expanded is whatever the snapshot holds and widening it is a data change rather
than a code change.
"""

from __future__ import annotations

import json
import os
import pathlib

import iam_eval as E

DEFAULT_PATH = (pathlib.Path(__file__).resolve().parent
                / "data" / "aws_managed_policies.json")

# Set this to a snapshot path to expand managed policies without passing one
# through every call site. Left unset, nothing is expanded.
ENV_VAR = "AGENTPATHTRIAGE_MANAGED_POLICIES"


class Snapshot:
    """Parsed managed policy documents, keyed by policy arn."""

    def __init__(self, raw: dict, path: pathlib.Path | None = None):
        self.path = path
        self.fetched = raw.get("fetched_utc")
        self.source = raw.get("source")
        self.statements: dict[str, list] = {}
        self.versions: dict[str, str] = {}
        self.updated: dict[str, str] = {}
        for arn, rec in (raw.get("policies") or {}).items():
            doc = rec.get("document")
            if not doc:
                continue
            ver = rec.get("version") or "unknown"
            # The source string travels with every statement, so a finding can
            # say which policy and which version of it allowed the action.
            self.statements[arn] = E.parse_statements(
                doc, source=f"aws-managed {arn} {ver}")
            self.versions[arn] = ver
            self.updated[arn] = rec.get("update_date")
        self.unavailable = dict(raw.get("unavailable") or {})

    def __len__(self) -> int:
        return len(self.statements)

    def __bool__(self) -> bool:
        return bool(self.statements)

    def describe(self) -> str:
        n = len(self.statements)
        when = (self.fetched or "unknown date")[:10]
        extra = (f", {len(self.unavailable)} named by the corpus but absent "
                 f"from AWS") if self.unavailable else ""
        return f"{n} AWS managed policies, snapshot of {when}{extra}"

    def coverage(self, arns) -> dict:
        """Which of these policy arns the snapshot can expand.

        Used to state the limit alongside a figure: a run that expanded 21 of
        the 22 policies a corpus names is a different claim from one that
        expanded all of them.
        """
        want = sorted(set(str(a) for a in arns))
        have = [a for a in want if a in self.statements]
        return {
            "requested": len(want),
            "expanded": len(have),
            "not_in_snapshot": [a for a in want
                                if a not in self.statements
                                and a not in self.unavailable],
            "absent_from_aws": [a for a in want if a in self.unavailable],
            "versions": {a: self.versions[a] for a in have},
        }


def load(path=None, required: bool = False) -> Snapshot | None:
    """Load a snapshot, or return None when expansion was not asked for.

    `path` wins; otherwise the environment variable; otherwise nothing is
    loaded and the caller behaves exactly as before. `required` turns a missing
    file into an error rather than silently analysing without expansion, which
    is what a measurement run wants: a run that meant to expand and quietly did
    not would report the old number under a new name.
    """
    p = path or os.environ.get(ENV_VAR)
    if p is None:
        return None
    if p is True or str(p) in ("", "1", "default"):
        p = DEFAULT_PATH
    p = pathlib.Path(p)
    if not p.is_file():
        if required:
            raise FileNotFoundError(f"managed policy snapshot not found: {p}")
        return None
    return Snapshot(json.loads(p.read_text()), p)


def statements_for(snapshot, arns) -> dict:
    """{arn: statements} for the arns this snapshot carries, else empty."""
    if not snapshot:
        return {}
    return {a: snapshot.statements[a] for a in set(str(x) for x in arns)
            if a in snapshot.statements}

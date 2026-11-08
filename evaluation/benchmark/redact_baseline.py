#!/usr/bin/env python3
"""Replace real account-scoped identifiers in the baseline evidence files.

baseline/baseline_out/ holds what third-party tools printed when they were run
against the lab account. That evidence has to stay in the repository, because
the comparison against Cloudsplaining is only checkable if the input both
tools received is there. The account's own identifiers do not have to stay.

What is replaced and why:

  AKIA / AIDA / AROA      An access key id is not a secret and cannot be used
                          to authenticate. It does, however, carry the AWS
                          account id in a form AWS itself will decode, through
                          `aws sts get-access-key-info`, and the AIDA and AROA
                          unique ids carry it the same way. The ARNs in these
                          files were already redacted to 000000000000, so
                          leaving these in would undo that redaction in the
                          same file.
  console-generated GUID  Part of an auto-generated managed policy name. It
                          does not carry the account id, but it is a unique
                          handle on a real resource.
  local user path         A traceback printed the operator's home directory.
  machine tag value       A tag naming the operator's workstation.

What is deliberately NOT replaced: policy documents, principal names, action
names, resource paths and the 000000000000 placeholder. baseline_diff.py
matches principals by name, so the comparison is unaffected. Run
`agentpathtriage verify --full` afterwards to confirm that.

The mapping is deterministic. Identifiers are sorted and numbered, so the same
input always produces the same output, a repeated identifier keeps one
placeholder, and the replacement preserves each identifier's shape so anything
that parses the format still parses it.

Usage:
    python3 evaluation/benchmark/redact_baseline.py --check   # report only
    python3 evaluation/benchmark/redact_baseline.py           # rewrite
"""

import argparse
import os
import re
import sys

DEFAULT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# An access key id is 20 characters (prefix plus 16); an IAM unique id for a
# user or role is 21 (prefix plus 17). Pinning the suffix at 16 matches the
# key id and silently misses every AIDA and AROA, because the trailing \b
# cannot fall in the middle of an alphanumeric run.
AWS_UNIQUE_ID = re.compile(r"\b(AKIA|AIDA|AROA|ASIA)([A-Z0-9]{16,17})\b")
GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
USER_PATH = re.compile(r"/Users/[A-Za-z0-9_.-]+")

# already-neutral values that must be left exactly as they are
KEEP_GUID = {"00000000-0000-0000-0000-000000000000"}
NEUTRAL_USER = "/Users/researcher"
MACHINE_TAG = ("pathtriage-local-mac", "pathtriage-workstation")


def baseline_dir(root):
    return os.path.join(root, "baseline", "baseline_out")


def files(root):
    d = baseline_dir(root)
    if not os.path.isdir(d):
        return []
    return [os.path.join(d, f) for f in sorted(os.listdir(d))
            if os.path.isfile(os.path.join(d, f))]


def build_mapping(texts):
    """One placeholder per distinct identifier, assigned in sorted order."""
    # Values this script already produced are skipped. Including them would
    # let a newly added real identifier that sorts earlier renumber the
    # existing placeholders, so a second redaction would churn the file.
    ids, guids = set(), set()
    for t in texts:
        ids |= {m.group(0) for m in AWS_UNIQUE_ID.finditer(t)
                if "EXAMPLE" not in m.group(0)}
        guids |= {g for g in GUID.findall(t)
                  if g not in KEEP_GUID and not g.startswith("00000000-0000-4000-8000-")}

    mapping = {}
    per_prefix = {}
    for ident in sorted(ids):
        prefix, suffix = ident[:4], ident[4:]
        per_prefix[prefix] = per_prefix.get(prefix, 0) + 1
        # keep the identifier's own length, so anything that validates the
        # format still validates it: 16 for a key id, 17 for a unique id
        width = len(suffix) - len("EXAMPLE")
        mapping[ident] = f"{prefix}EXAMPLE{per_prefix[prefix]:0{width}d}"
    for n, g in enumerate(sorted(guids), 1):
        mapping[g] = f"00000000-0000-4000-8000-{n:012d}"
    return mapping


def redact(text, mapping):
    for real, fake in mapping.items():
        text = text.replace(real, fake)
    text = USER_PATH.sub(NEUTRAL_USER, text)
    text = text.replace(*MACHINE_TAG)
    return text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="report what would change and exit 1 if anything would")
    ap.add_argument("--root", default=DEFAULT_ROOT,
                    help="repository root to work on. Defaults to the one this "
                         "script lives in. A history rewrite runs the script "
                         "from outside the tree being rewritten, because the "
                         "script does not exist in the older commits, so it "
                         "needs to be told where the tree is.")
    a = ap.parse_args()

    root = os.path.abspath(a.root)
    paths = files(root)
    if not paths:
        # A commit from before the baseline evidence existed has nothing to
        # redact. That is not an error, and a history rewrite must not stop on
        # it. Exiting non-zero here is what made the first rewrite attempt
        # abort silently on every commit.
        print(f"no baseline evidence under {baseline_dir(root)}, nothing to do")
        return 0
    originals = {p: open(p, encoding="utf-8", errors="ignore").read() for p in paths}
    mapping = build_mapping(originals.values())

    changed = []
    for p, text in originals.items():
        new = redact(text, mapping)
        if new != text:
            changed.append(p)
            if not a.check:
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(new)

    for real, fake in sorted(mapping.items()):
        print(f"  {real[:8]}...  ->  {fake}")
    if USER_PATH.search("".join(originals.values())):
        print(f"  /Users/<operator>  ->  {NEUTRAL_USER}")
    if MACHINE_TAG[0] in "".join(originals.values()):
        print(f"  {MACHINE_TAG[0]}  ->  {MACHINE_TAG[1]}")

    verb = "would change" if a.check else "rewritten"
    print(f"\n{len(changed)} file(s) {verb}:")
    for p in changed:
        print(f"  {os.path.relpath(p, root)}")
    if not changed:
        print("  (none; the baseline evidence carries no real identifiers)")

    if a.check and changed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

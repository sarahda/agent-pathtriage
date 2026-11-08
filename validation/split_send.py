#!/usr/bin/env python3
"""Split a generated send into the two things a submission form asks for.

A file under validation/sends/ carries a channel note, then a rule, then the
subject line, then the message. Only the last two go into a GitHub issue or a
report form, so this writes them out separately and leaves the note behind.

  python3 validation/split_send.py validation/sends/avparkhi.md
  python3 validation/split_send.py validation/sends/*.md --outdir validation/sends/paste

Each input produces <name>.title.txt and <name>.body.md in the output
directory. Nothing is rewritten: the body goes out exactly as generated.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

SUBJECT = re.compile(r"^\*\*Subject:\*\*\s*(.+?)\s*$", re.M)


def split(text):
    """The subject line and everything after it, or None when there is no subject."""
    m = SUBJECT.search(text)
    if not m:
        return None
    return m.group(1), text[m.end():].strip() + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sends", nargs="+")
    ap.add_argument("--outdir", default=None,
                    help="where to write; defaults to each send's own directory")
    a = ap.parse_args()

    bad = 0
    for path in a.sends:
        try:
            text = open(path, encoding="utf-8").read()
        except OSError as e:
            print(f"stop: {path}: {e}", file=sys.stderr)
            bad += 1
            continue
        parts = split(text)
        if parts is None:
            print(f"stop: {path} has no '**Subject:**' line", file=sys.stderr)
            bad += 1
            continue
        title, body = parts
        outdir = a.outdir or os.path.dirname(path) or "."
        os.makedirs(outdir, exist_ok=True)
        stem = os.path.splitext(os.path.basename(path))[0]
        tpath = os.path.join(outdir, f"{stem}.title.txt")
        bpath = os.path.join(outdir, f"{stem}.body.md")
        with open(tpath, "w", encoding="utf-8") as fh:
            fh.write(title + "\n")
        with open(bpath, "w", encoding="utf-8") as fh:
            fh.write(body)
        print(f"{stem}: {len(body.split())} words -> {bpath}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

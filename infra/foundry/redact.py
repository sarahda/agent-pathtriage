#!/usr/bin/env python3
"""Replace real GUIDs in lab artifacts with stable placeholders.

Why this exists. The run files record the full Azure resource ids of the
connection and the agents, which carry the subscription id. Seven of them are
already committed with it. `foundry_cp.py` solved the same problem for its own
output and left the reason in a comment worth repeating here: the redaction
belongs where the artifact is WRITTEN, because one applied to the file
afterwards comes back on the next run.

Why not one fixed placeholder for everything. foundry_cp.py maps every GUID to
a single constant, which is right for scopes: two scopes in one subscription
stay equal afterwards. It is wrong for principal ids, because the whole point
of the A2A cells is that the caller's principal is not the callee's and not the
project's. Collapsing them would erase the distinction the experiment rests on.

So each distinct GUID gets its own stable placeholder, numbered in the order
first seen, and the mapping is kept OUTSIDE the repository. Distinctions
survive, the artifacts are publishable, and the mapping is still there locally
if a run has to be traced back to real resources.

  APT_GUID_MAP=... python3 redact.py --in-place infra/foundry/runs/*.json
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys

GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                  r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")

DEFAULT_MAP = pathlib.Path(
    os.environ.get("APT_GUID_MAP", "")
    or pathlib.Path.home() / ".pathtriage-private" / "apt-guid-map.json")


def placeholder(n: int) -> str:
    return f"00000000-0000-0000-0000-{n:012d}"


class Redactor:
    """Stable GUID to placeholder mapping, persisted outside the repository."""

    def __init__(self, map_path: pathlib.Path | None = None):
        self.path = pathlib.Path(map_path or DEFAULT_MAP)
        self.fwd: dict[str, str] = {}
        if self.path.exists():
            try:
                self.fwd = json.loads(self.path.read_text()).get("map", {})
            except Exception:
                # A corrupt map must not silently restart numbering, because
                # that would give one GUID two placeholders across files.
                print(f"redact: {self.path} is unreadable. Refusing to start a "
                      f"new numbering that would disagree with artifacts "
                      f"already written. Move it aside deliberately if that is "
                      f"what you want.", file=sys.stderr)
                raise
        self.dirty = False
        # Placeholders are themselves GUID shaped, so an already redacted file
        # must not be renumbered on a second pass.
        self.known_placeholders = set(self.fwd.values())

    def of(self, guid: str) -> str:
        g = guid.lower()
        if g in self.known_placeholders or guid in self.known_placeholders:
            return guid
        if re.fullmatch(r"0{8}-0{4}-0{4}-0{4}-\d{12}", g):
            return guid           # already a placeholder from a previous pass
        if g not in self.fwd:
            self.fwd[g] = placeholder(len(self.fwd) + 1)
            self.known_placeholders.add(self.fwd[g])
            self.dirty = True
        return self.fwd[g]

    def text(self, s: str) -> str:
        return GUID.sub(lambda m: self.of(m.group(0)), s)

    def obj(self, o):
        if isinstance(o, str):
            return self.text(o)
        if isinstance(o, dict):
            return {self.text(k) if isinstance(k, str) else k: self.obj(v)
                    for k, v in o.items()}
        if isinstance(o, list):
            return [self.obj(v) for v in o]
        return o

    def save(self):
        if not self.dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(
            {"_comment": "Real GUID to placeholder, for the Foundry lab "
                         "artifacts. Keep this out of the repository. Without "
                         "it a redacted run cannot be traced back to real "
                         "resources, which is the point.",
             "map": self.fwd}, indent=2))
        os.chmod(self.path, 0o600)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+", type=pathlib.Path)
    ap.add_argument("--in-place", action="store_true")
    ap.add_argument("--map", type=pathlib.Path, default=None)
    args = ap.parse_args()

    r = Redactor(args.map)
    changed = 0
    for f in args.files:
        if not f.exists():
            print(f"skip, not found: {f}", file=sys.stderr)
            continue
        src = f.read_text()
        before = set(GUID.findall(src))
        try:
            out = json.dumps(r.obj(json.loads(src)), indent=2)
        except json.JSONDecodeError:
            out = r.text(src)
        after = set(GUID.findall(out))
        real = {g for g in after if not re.fullmatch(
            r"0{8}-0{4}-0{4}-0{4}-\d{12}", g.lower())}
        if real:
            print(f"{f}: {len(real)} GUID(s) still look real after redaction. "
                  f"Not written.", file=sys.stderr)
            continue
        if out != src:
            if args.in_place:
                f.write_text(out)
            changed += 1
            print(f"{f}: {len(before)} GUID(s) -> placeholders"
                  f"{'' if args.in_place else '  (dry run)'}")
        else:
            print(f"{f}: already clean")
    r.save()
    print(f"\n{changed} file(s) {'rewritten' if args.in_place else 'would change'}")
    print(f"mapping: {r.path} ({len(r.fwd)} GUIDs)")
    if not args.in_place and changed:
        print("re-run with --in-place to write")
    return 0


if __name__ == "__main__":
    sys.exit(main())

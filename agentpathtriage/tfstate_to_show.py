#!/usr/bin/env python3
"""Convert a raw terraform.tfstate into the shape `terraform show -json` emits.

foundry_cp.py reads the show format (values.root_module.resources with a
`values` dict per resource). The raw state file nests the same attributes under
resources[].instances[].attributes. Converting here means the analyser can be
run from a committed state file on a machine with no terraform binary, which is
how it gets run in CI and how it got run on 2026-10-31.

Nothing about the lab is written into this file: it walks whatever resources
the state contains.

  python3 tfstate_to_show.py --state infra/foundry/terraform.tfstate --json out.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


def convert(raw: dict) -> dict:
    out = []
    for r in raw.get("resources", []):
        rtype, name = r.get("type"), r.get("name")
        mode = r.get("mode", "managed")
        for inst in r.get("instances", []):
            attrs = inst.get("attributes") or {}
            entry = {"type": rtype, "name": name, "mode": mode,
                     "values": attrs}
            idx = inst.get("index_key")
            if idx is not None:
                entry["index"] = idx
            out.append(entry)
    return {"format_version": "1.0",
            "terraform_version": raw.get("terraform_version"),
            "values": {"root_module": {"resources": out},
                       "outputs": {k: {"value": v.get("value")}
                                   for k, v in (raw.get("outputs") or {}).items()}}}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True, type=pathlib.Path)
    ap.add_argument("--json", required=True, type=pathlib.Path)
    args = ap.parse_args()
    raw = json.loads(args.state.read_text())
    if "values" in raw and raw.get("values", {}).get("root_module"):
        print("that file is already in show format; copying through",
              file=sys.stderr)
        args.json.write_text(json.dumps(raw, indent=1))
        return 0
    shown = convert(raw)
    n = len(shown["values"]["root_module"]["resources"])
    if n == 0:
        print("stop: no resource instances found in the state", file=sys.stderr)
        return 2
    args.json.write_text(json.dumps(shown, indent=1))
    print(f"{n} resource instances -> {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

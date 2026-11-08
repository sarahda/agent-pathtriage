#!/usr/bin/env python3
"""Separate real ARM deployment templates from everything else ending in .json.

Why this exists. A marker count over the whole corpus mixes two populations.
`RemoteA2A` appeared in 2 Terraform files and 133 JSON files, which is not a
believable ratio for a deployment pattern, and the JSON files turned out to be
Microsoft's own REST API specifications rather than anything anyone deploys.
Reporting the unfiltered number would have overstated that marker by about
sixty times.

An ARM deployment template declares its schema, and the deployment schemas
live on schema.management.azure.com. A file that does not declare one of those
is not a deployment template, whatever else it is. So each .json file is
classified by its `$schema` and the markers are counted inside the deployment
templates only, with the rest reported separately rather than silently dropped.

Marker list and corpus come from the caller. Nothing about either is written
into this file.

  python3 json_arm.py --corpus corpus_foundry \\
      --markers evaluation/benchmark/foundry_recon.json \\
      --json evaluation/benchmark/json_arm_foundry.json
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys

ARM_SCHEMA_HOST = "schema.management.azure.com"
SCHEMA_RE = re.compile(r'"\$schema"\s*:\s*"([^"]+)"')


def classify(text: str) -> tuple[str, str | None]:
    """(class, schema). Only the declared schema decides."""
    m = SCHEMA_RE.search(text)
    if not m:
        return "no-schema", None
    schema = m.group(1)
    host = schema.split("//", 1)[-1].split("/", 1)[0].lower()
    if host == ARM_SCHEMA_HOST:
        return "arm-deployment", schema
    if "swagger" in schema.lower() or "openapi" in schema.lower():
        return "api-spec", schema
    return "other-schema", schema


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, type=pathlib.Path)
    ap.add_argument("--markers", required=True, type=pathlib.Path,
                    help="a recon json whose 'markers' keys are the strings "
                         "to count")
    ap.add_argument("--json", type=pathlib.Path)
    args = ap.parse_args()

    recon = json.loads(args.markers.read_text())
    markers = sorted((recon.get("markers") or {}).keys())
    if not markers:
        print("stop: no markers found in the recon file", file=sys.stderr)
        return 2

    classes = collections.Counter()
    schemas = collections.Counter()
    hits = {m: collections.Counter() for m in markers}
    examples = collections.defaultdict(list)
    scanned = 0

    files = [f for f in args.corpus.rglob("*.json") if ".git" not in f.parts]
    print(f"{len(files)} .json files to classify\n", flush=True)
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except Exception:
            continue
        scanned += 1
        if scanned % 2000 == 0:
            print(f"  {scanned}/{len(files)}", flush=True)
        cls, schema = classify(text)
        classes[cls] += 1
        if schema:
            schemas[schema] += 1
        for m in markers:
            if m in text:
                hits[m][cls] += 1
                if cls == "arm-deployment" and len(examples[m]) < 5:
                    examples[m].append(str(f.relative_to(args.corpus)))

    out = {
        "corpus": str(args.corpus),
        "json_files_scanned": scanned,
        "classes": dict(classes),
        "top_schemas": dict(schemas.most_common(12)),
        "markers_by_class": {m: dict(c) for m, c in hits.items() if c},
        "arm_deployment_examples": {m: v for m, v in examples.items() if v},
        "rule": (f"A file counts as an ARM deployment template only when its "
                 f"$schema host is {ARM_SCHEMA_HOST}. Everything else is "
                 f"reported separately rather than dropped, so the split can "
                 f"be checked."),
    }

    print(f"corpus: {args.corpus}")
    print(f".json files scanned: {scanned}\n")
    print("classification")
    for k, v in classes.most_common():
        print(f"  {k:18} {v}")
    print()
    print("top declared schemas")
    for k, v in schemas.most_common(8):
        print(f"  {v:6}  {k[:88]}")
    print()
    print("markers, by file class (only markers that appear at all)")
    print(f"  {'marker':44} {'arm':>6} {'api-spec':>9} {'other':>7} {'none':>6}")
    any_arm = False
    for m in markers:
        c = hits[m]
        if not c:
            continue
        if c.get("arm-deployment"):
            any_arm = True
        print(f"  {m[:44]:44} {c.get('arm-deployment',0):6} "
              f"{c.get('api-spec',0):9} {c.get('other-schema',0):7} "
              f"{c.get('no-schema',0):6}")
    print()
    if not any_arm:
        print("No marker appears in a single ARM deployment template. The .json")
        print("surface contributes nothing to the Foundry counts, and the")
        print("unfiltered .json numbers must not be reported.")
    else:
        print("Some markers do appear in ARM deployment templates. Those counts")
        print("are usable; the api-spec and no-schema columns are not.")

    if args.json:
        args.json.write_text(json.dumps(out, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

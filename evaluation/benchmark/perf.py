#!/usr/bin/env python3
"""Time and measure `scan` over a corpus, per template and in total.

A tool paper needs a cost table, and the honest version of it reports the
distribution rather than an average, because analysis time over real
repositories is skewed: most templates are small and a few are not.

Measured per template: wall clock and peak resident memory of the scan
process. The scan runs in a subprocess, which is how a user runs it, so the
numbers include interpreter start up. That is the cost a person actually pays,
and it is reported separately so a per-template figure net of start up can
also be given.

Nothing about the corpus is written into this file. The template list comes
from the topology artifact, so the timing covers exactly the templates the
paper's other numbers are computed over.

  python3 perf.py --corpus corpus_tier2 \\
      --topology evaluation/benchmark/topology_tier2.json \\
      --json evaluation/benchmark/perf_tier2.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import resource
import statistics
import subprocess
import sys
import time


def peak_kb_to_mb(kb: int) -> float:
    # getrusage reports bytes on macOS and kilobytes on Linux.
    if sys.platform == "darwin":
        return kb / (1024 * 1024)
    return kb / 1024


def measure_startup(n: int = 5) -> float:
    """Interpreter plus import cost, so it can be separated from analysis."""
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        subprocess.run([sys.executable, "-c", "import agentpathtriage"],
                       capture_output=True)
        times.append(time.perf_counter() - t0)
    return statistics.median(times)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, type=pathlib.Path)
    ap.add_argument("--topology", required=True, type=pathlib.Path)
    ap.add_argument("--limit", type=int, default=None,
                    help="time only the first N templates, for a quick check")
    ap.add_argument("--json", type=pathlib.Path)
    args = ap.parse_args()

    topo = json.loads(args.topology.read_text())
    rels = [t["t"] for t in topo]
    if args.limit:
        rels = rels[:args.limit]

    print(f"templates to time: {len(rels)}")
    startup = measure_startup()
    print(f"interpreter and import, median of 5: {startup*1000:.0f} ms\n")

    rows = []
    t_all0 = time.perf_counter()
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss

    for i, rel in enumerate(rels, 1):
        d = args.corpus / rel
        if not d.is_dir():
            rows.append({"template": rel, "ok": False, "why": "not in corpus"})
            continue
        r0 = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        t0 = time.perf_counter()
        p = subprocess.run(
            [sys.executable, "-m", "agentpathtriage.cli", "scan", str(d)],
            capture_output=True, text=True)
        dt = time.perf_counter() - t0
        r1 = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        n_files = len(list(d.rglob("*.tf")))
        rows.append({"template": rel, "ok": p.returncode in (0, 1),
                     "exit": p.returncode, "seconds": round(dt, 3),
                     "tf_files": n_files,
                     "peak_mb_hint": round(peak_kb_to_mb(max(r1 - r0, 0)), 1)})
        if i % 25 == 0 or i == len(rels):
            print(f"  {i}/{len(rels)}  {dt:.2f}s  {rel[:56]}")

    total = time.perf_counter() - t_all0
    after = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    peak_mb = peak_kb_to_mb(after)

    ok = [r for r in rows if r.get("ok")]
    secs = sorted(r["seconds"] for r in ok)
    files = [r["tf_files"] for r in ok]

    def pct(p):
        if not secs:
            return None
        k = min(int(round(p / 100 * (len(secs) - 1))), len(secs) - 1)
        return secs[k]

    out = {
        "corpus": str(args.corpus),
        "templates_timed": len(ok),
        "templates_failed": len(rows) - len(ok),
        "whole_corpus_seconds": round(total, 1),
        "per_template_seconds": {
            "min": secs[0] if secs else None,
            "median": round(statistics.median(secs), 3) if secs else None,
            "mean": round(statistics.fmean(secs), 3) if secs else None,
            "p90": pct(90), "p99": pct(99),
            "max": secs[-1] if secs else None,
        },
        "interpreter_startup_seconds": round(startup, 3),
        "per_template_seconds_net_of_startup": {
            "median": round(statistics.median(secs) - startup, 3)
            if secs else None,
        },
        "terraform_files": {
            "total": sum(files),
            "median_per_template": statistics.median(files) if files else None,
            "max_per_template": max(files) if files else None,
        },
        "peak_child_memory_mb": round(peak_mb, 1),
        "slowest": sorted(ok, key=lambda r: -r["seconds"])[:10],
        "method": ("Each template is scanned in a fresh subprocess, which is "
                   "how a user runs it, so the per template figure includes "
                   "interpreter start up. The start up cost is measured "
                   "separately and reported, so a net figure can be quoted "
                   "too. Memory is the peak resident set of child processes, "
                   "which is a ceiling across the run rather than a per "
                   "template measurement."),
    }

    p = out["per_template_seconds"]
    print()
    print(f"whole corpus          {out['whole_corpus_seconds']} s "
          f"over {out['templates_timed']} templates")
    print(f"per template median   {p['median']} s "
          f"(net of start up {out['per_template_seconds_net_of_startup']['median']} s)")
    print(f"              mean    {p['mean']} s")
    print(f"              p90     {p['p90']} s")
    print(f"              p99     {p['p99']} s")
    print(f"              max     {p['max']} s")
    print(f"peak child memory     {out['peak_child_memory_mb']} MB")
    print(f"terraform files       {out['terraform_files']['total']} total, "
          f"median {out['terraform_files']['median_per_template']} per template")
    if out["templates_failed"]:
        print(f"failed                {out['templates_failed']}")

    if args.json:
        args.json.write_text(json.dumps(out, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

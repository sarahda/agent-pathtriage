#!/usr/bin/env python3
"""How many templates assign an agent's role through something the parser does
not resolve, and are therefore invisible to the shared-role rule?

The shared-role rule compares the role each runtime is assigned. It can only
see that two runtimes share a role when both assignments resolve to the same
string. `tf_to_state` substitutes a reference to a resource attribute, so
`aws_iam_role.x.arn` becomes a concrete ARN, but it leaves `${local.y}`
standing. Two runtimes routed through two different locals therefore look like
two different roles even when the locals evaluate to one.

That makes the shared-role count a lower bound, and this measures by how much.
A template where at least one runtime's role is an unresolved reference cannot
be judged either way, so it is reported as undecidable rather than as not
sharing.

Found because the project's own AWS lab stopped being detected after its role
assignment was routed through a local on 2026-10-31.

  python3 role_arn_resolution.py --corpus corpus_tier2 \\
      --topology evaluation/benchmark/topology_tier2.json \\
      --json evaluation/benchmark/role_arn_resolution_tier2.json
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
TF_TO_STATE = HERE / "tf_to_state.py"

UNRESOLVED = re.compile(r"\$\{\s*(local|var|each|count|module)\b")
# Exact types only. A substring match on "agent_runtime" also catches
# aws_bedrockagentcore_agent_runtime_endpoint, which has no role_arn by design,
# and counting those as runtimes with a missing role inflated both the absent
# count and the undecidable count on the first run of this script.
RUNTIME_TYPES = (
    "aws_bedrockagentcore_agent_runtime",
    "awscc_bedrockagentcore_runtime",
)


def role_fields(state: dict):
    root = state.get("values", {}).get("root_module", {})
    out = []
    for r in root.get("resources", []):
        if (r.get("type") or "") in RUNTIME_TYPES:
            out.append((r.get("name"), (r.get("values") or {}).get("role_arn")))
    return out


OPAQUE = re.compile(r"^\$\{\s*(?:local|var|module)\.[^}]+\}$")


def classify(role: str | None) -> str:
    """How much of the role assignment the parser pinned down.

    A partially resolved ARN is still comparable. Two runtimes written as
    `.../${var.p}-leaf` and `.../${var.p}-orchestrator` differ whatever `p` is,
    and two written identically are the same role whatever `p` is. So an
    unresolved variable inside a longer string does not stop the shared-role
    rule from deciding.

    What does stop it is a role_arn that is nothing but one opaque reference.
    `${local.agent_a_role_arn}` and `${local.agent_b_role_arn}` are different
    strings that may name one role, and substitution would be needed to tell.
    """
    if role is None:
        return "absent"
    r = str(role).strip()
    if OPAQUE.fullmatch(r):
        return "opaque-reference"
    if UNRESOLVED.search(r):
        return "partially-resolved"
    return "fully-resolved"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, type=pathlib.Path)
    ap.add_argument("--topology", required=True, type=pathlib.Path)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--json", type=pathlib.Path)
    args = ap.parse_args()

    topo = json.loads(args.topology.read_text())
    rels = [t["t"] for t in topo if t.get("n_agents", 0) >= 1]
    if args.limit:
        rels = rels[:args.limit]

    kinds = collections.Counter()
    per_template = []
    undecidable_multi = []
    multi = 0

    with tempfile.TemporaryDirectory() as tmp:
        st = pathlib.Path(tmp) / "s.json"
        for i, rel in enumerate(rels, 1):
            d = args.corpus / rel
            if not d.is_dir():
                continue
            p = subprocess.run(
                [sys.executable, str(TF_TO_STATE), "--tfdir", str(d),
                 "--json", str(st)], capture_output=True, text=True)
            if p.returncode != 0 or not st.exists():
                kinds["parse-failed"] += 1
                continue
            try:
                state = json.loads(st.read_text())
            except Exception:
                kinds["parse-failed"] += 1
                continue
            rows = role_fields(state)
            if not rows:
                continue
            cls = [classify(r) for _, r in rows]
            for c in cls:
                kinds[c] += 1
            n_rt = len(rows)
            if n_rt >= 2:
                multi += 1
                # Undecidable only when two runtimes carry different opaque
                # references, or a role is missing entirely. Everything else
                # can be settled by comparing the strings.
                opaques = {r for (_, r), c in zip(rows, cls)
                           if c == "opaque-reference"}
                has_absent = any(c == "absent" for c in cls)
                if len(opaques) >= 2 or (opaques and has_absent) or (
                        has_absent and n_rt >= 2 and
                        sum(1 for c in cls if c == "absent") == n_rt):
                    undecidable_multi.append({
                        "template": rel,
                        "runtimes": n_rt,
                        "why": ("two or more different opaque references"
                                if len(opaques) >= 2 else "role not parsed"),
                        "roles": [{"runtime": n, "role": r, "class": c}
                                  for (n, r), c in zip(rows, cls)],
                    })
            per_template.append({"template": rel, "runtimes": n_rt,
                                 "classes": cls})
            if i % 40 == 0:
                print(f"  {i}/{len(rels)}")

    out = {
        "corpus": str(args.corpus),
        "templates_examined": len(per_template),
        "runtime_role_assignments": dict(kinds),
        "multi_runtime_templates": multi,
        "multi_runtime_templates_undecidable": len(undecidable_multi),
        "undecidable": undecidable_multi,
        "meaning": (
            "A partially resolved ARN is still comparable: two runtimes whose "
            "role strings differ outside the variable reference hold different "
            "roles whatever the variable is, and two written identically hold "
            "the same one. The shared-role rule is only blocked when a role is "
            "nothing but an opaque reference and the two runtimes carry "
            "different ones, because substitution could make them equal. The "
            "published shared-role count is a lower bound by at most the "
            "undecidable count."),
    }

    print()
    print(f"templates examined            {out['templates_examined']}")
    print("runtime role assignments by how they resolved:")
    for k, v in sorted(kinds.items(), key=lambda kv: -kv[1]):
        print(f"  {k:22} {v}")
    print()
    print(f"templates with 2+ runtimes    {multi}")
    print(f"  of those, undecidable       {len(undecidable_multi)}")
    if undecidable_multi:
        print()
        print("undecidable templates:")
        for u in undecidable_multi:
            print(f"  {u['template']}")
            for r in u["roles"]:
                print(f"      {r['runtime']}: {str(r['role'])[:62]}  [{r['class']}]")
    else:
        print()
        print("No multi-runtime template in the corpus is undecidable, so the")
        print("shared-role count is not understated on this corpus. The")
        print("limitation is still real for templates written that way.")

    if args.json:
        args.json.write_text(json.dumps(out, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

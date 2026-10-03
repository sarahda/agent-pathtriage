#!/usr/bin/env bash
# baseline_compare.sh (v2) — run existing IAM tools against the agent lab and
# record that they do NOT detect the agent-specific cross-agent primitives.
#
# Honest framing: these tools reason about classic IAM. PMapper even models
# role->role PassRole/AssumeRole. The differentiator is that none of them has a
# model of agent resources (bedrock-agentcore memory / runtime / code-interpreter),
# so none reports anything on CP-1..CP-5. This captures their raw output and
# greps it for any agentcore mention (expected: none).
#
# Requires: AWS creds for the researcher lab account, lab deployed (IAM roles
# are enough; the agent runtimes do not need to exist). Read-only on your account.
#
# Usage:  bash baseline_compare.sh

set -u
export PATH="$HOME/.local/bin:$PATH"
OUT="baseline_out"; mkdir -p "$OUT"

echo "== Cloudsplaining: download account authorization details =="
cloudsplaining download -o "$OUT" 2>&1 | tee "$OUT/cs_download.txt"
CS_JSON=$(ls -t "$OUT"/*.json 2>/dev/null | head -1)
if [ -n "$CS_JSON" ]; then
  echo "== Cloudsplaining: scan ($CS_JSON) =="
  cloudsplaining scan -i "$CS_JSON" -o "$OUT/cs_report" 2>&1 | tee "$OUT/cs_scan.txt"
else
  echo "(cloudsplaining download produced no json; check creds)" | tee "$OUT/cs_scan.txt"
fi

echo
echo "== PMapper (optional; skips cleanly if incompatible with local Python) =="
if pmapper --version >/dev/null 2>&1; then
  pmapper graph create 2>&1 | tee "$OUT/pmapper_create.txt"
  pmapper query 'preset privesc *' 2>&1 | tee "$OUT/pmapper_privesc.txt"
else
  echo "PMapper not runnable in this environment (known collections.abc issue on Python 3.11)." \
    | tee "$OUT/pmapper_skipped.txt"
  echo "Covered by capability analysis: PMapper models principal-to-principal edges" >> "$OUT/pmapper_skipped.txt"
  echo "(incl. PassRole/AssumeRole) but has no agent-resource nodes, so it cannot express CP-1..CP-5." >> "$OUT/pmapper_skipped.txt"
fi

echo
echo "== Do the baselines report ANY agent-resource finding? (expected: none) =="
grep -ri -E "bedrock-agentcore|agentcore|code.?interpreter|:memory/|:runtime/" "$OUT" \
  | grep -vi "skipped\|capability analysis" | sort -u | tee "$OUT/agent_mentions.txt"
n=$(grep -ri -E "bedrock-agentcore|agentcore|code.?interpreter|:memory/|:runtime/" "$OUT" \
     | grep -vi "skipped\|capability analysis" | wc -l | tr -d ' ')
echo
echo "agent-resource findings by baselines: $n   (0 = they don't model the agent layer)"
echo "raw outputs under ./$OUT/ (open cs_report/ for Cloudsplaining's HTML findings)"

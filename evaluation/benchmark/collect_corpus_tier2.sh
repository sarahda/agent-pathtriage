#!/usr/bin/env bash
# collect_corpus_tier2.sh - build the Tier2 (community / third-party) corpus.
# Clean HCL signals only. Dedups to distinct non-fork repos, shallow clone.
# Requires: gh authenticated (gh auth status). Code search ~10 req/min, so sleeps.
# Portable timeout: gtimeout (brew coreutils) or timeout if available, else none.
#
# Usage:
#   bash collect_corpus_tier2.sh           # CAP 300
#   CAP=500 bash collect_corpus_tier2.sh
#
# Then: python3 scan_s1.py --root corpus_tier2 --json tier2_prevalence.json
#       bash gate1_check.sh corpus_tier2
set -u
CAP="${CAP:-600}"
OUT="${OUT:-corpus_tier2}"
CLONE_TIMEOUT="${CLONE_TIMEOUT:-90}"
mkdir -p "$OUT"
SEEN="$OUT/.seen"; : > "$SEEN"
export GIT_TERMINAL_PROMPT=0 GIT_LFS_SKIP_SMUDGE=1

TO=""
if command -v gtimeout >/dev/null 2>&1; then TO="gtimeout ${CLONE_TIMEOUT}"
elif command -v timeout >/dev/null 2>&1; then TO="timeout ${CLONE_TIMEOUT}"
else : ; fi   # no gtimeout/timeout: git lowSpeed below still guards hangs

QUERIES=(
  # agent-template-targeted (grow the agent_runtime population - the gap denominator)
  'aws_bedrockagentcore_agent_runtime extension:tf'
  'aws_bedrockagentcore_memory extension:tf'
  'aws_bedrockagentcore_gateway extension:tf'
  'aws_bedrockagentcore_code_interpreter extension:tf'
  'agent_runtime_artifact extension:tf'
  '"bedrock-agentcore:" extension:tf'
  # original clean HCL signals
  '"iam:PassRole" bedrock extension:tf'
  'aws_bedrockagent_agent extension:tf'
  'aws_bedrockagentcore extension:tf'
  '"iam:PassRole" sagemaker extension:tf'
  'bedrock agent aws_iam_role extension:tf'
)

collect() {
  gh api -X GET search/code -f q="$1" -f per_page=100 \
    --jq '.items[] | select(.repository.fork==false) | .repository.full_name' 2>/dev/null | sort -u
  sleep 7
}

count=0
for q in "${QUERIES[@]}"; do
  echo "== query: $q =="
  while read -r repo; do
    [ -z "$repo" ] && continue
    grep -qxF "$repo" "$SEEN" && continue
    echo "$repo" >> "$SEEN"
    [ "$count" -ge "$CAP" ] && continue
    d="$OUT/${repo/\//__}"
    [ -d "$d" ] && continue
    if $TO git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=60 clone --depth 1 "https://github.com/$repo" "$d" 2>/dev/null; then
      count=$((count+1)); echo "  clone $repo  ($count)"
    else
      echo "  (clone failed or timed out: $repo)"
    fi
  done < <(collect "$q")
done

echo
echo "distinct repos seen: $(wc -l < "$SEEN")   cloned: $count   (cap $CAP)"
echo "next: python3 scan_s1.py --root $OUT --json tier2_prevalence.json"
echo "then: bash gate1_check.sh $OUT   and   python3 agentpathtriage/gap.py --corpus $OUT --json gap_tier2.json"

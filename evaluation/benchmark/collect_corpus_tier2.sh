#!/usr/bin/env bash
# collect_corpus_tier2.sh - build the Tier2 (community / third-party) corpus.
# Clean HCL signals only (the noisy AssumeRole+bedrock / PassRole-wildcard queries
# are excluded on purpose). Dedups to distinct non-fork repos, shallow clone.
# Requires: gh authenticated (gh auth status). Code search is ~10 req/min, so this
# sleeps between queries.
#
# Usage:
#   bash collect_corpus_tier2.sh           # CAP 300 repos
#   CAP=500 bash collect_corpus_tier2.sh
#
# Then: python3 scan_s1.py --root corpus_tier2 --json tier2_prevalence.json
set -u
CAP="${CAP:-300}"
OUT="${OUT:-corpus_tier2}"
mkdir -p "$OUT"
SEEN="$OUT/.seen"; : > "$SEEN"
export GIT_TERMINAL_PROMPT=0 GIT_LFS_SKIP_SMUDGE=1

# clean HCL queries (the three stable signals from corpus sizing)
QUERIES=(
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
    if timeout 60 git clone --depth 1 "https://github.com/$repo" "$d" 2>/dev/null; then
      count=$((count+1)); echo "  clone $repo  ($count)"
    else
      echo "  (clone failed: $repo)"
    fi
  done < <(collect "$q")
done

echo
echo "distinct repos seen: $(wc -l < "$SEEN")   cloned: $count   (cap $CAP)"
echo "next: python3 scan_s1.py --root $OUT --json tier2_prevalence.json"
echo "then: bash gate1_check.sh $OUT"

#!/usr/bin/env bash
# collect_corpus.sh - build the prevalence corpus for extract_static.
# Clones distinct, non-fork public repos matching the queries into ./corpus/<owner__repo>.
# Requires: gh CLI authenticated. Shallow clones, skips forks, caps the total.
#
# Usage:
#   bash collect_corpus.sh            # default cap 80 repos
#   CAP=150 bash collect_corpus.sh    # raise the cap
#
# Then: python3 extract_static.py --corpus ./corpus --json prevalence_raw.json

set -u
CAP="${CAP:-80}"
OUT="corpus"
mkdir -p "$OUT"
SEEN="$OUT/.seen"; : > "$SEEN"

# code-search queries (file-level); we dedup to repos and skip forks below.
QUERIES=(
  'aws_bedrockagentcore extension:tf'
  'bedrock-agentcore extension:tf'
  '"iam:PassRole" bedrock extension:tf'
  'aws_bedrockagent_agent extension:tf'
  '"iam:PassRole" sagemaker extension:tf'
  'azurerm_ai_foundry extension:tf'
)

collect_repos() {
  local q="$1"
  # up to 100 results per query; extract "owner/repo", skip forks
  gh api -X GET search/code -f q="$q" -f per_page=100 \
     --jq '.items[] | select(.repository.fork==false) | .repository.full_name' 2>/dev/null \
     | sort -u
  sleep 7   # code-search rate limit (~10/min)
}

count=0
for q in "${QUERIES[@]}"; do
  echo "== query: $q =="
  while read -r repo; do
    [ -z "$repo" ] && continue
    grep -qxF "$repo" "$SEEN" && continue      # already have it
    echo "$repo" >> "$SEEN"
    [ "$count" -ge "$CAP" ] && continue
    dir="$OUT/${repo/\//__}"
    if [ ! -d "$dir" ]; then
      echo "  clone $repo"
      GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 "https://github.com/$repo" "$dir" 2>/dev/null \
        && count=$((count+1)) \
        || echo "  (clone failed: $repo)"
    fi
  done < <(collect_repos "$q")
done

echo
echo "distinct repos seen: $(wc -l < "$SEEN")   cloned: $count   (cap $CAP)"
echo "next: python3 extract_static.py --corpus ./$OUT --json prevalence_raw.json"

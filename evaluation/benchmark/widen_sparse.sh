#!/usr/bin/env bash
# Add file patterns to the sparse-checkout of every clone in a corpus.
#
# The clones are blobless (--filter=blob:none), so widening the patterns makes
# git fetch the newly matched blobs on demand. No re-clone is needed, which is
# how the missing Bicep was recovered on 2026-10-31.
#
# Idempotent and resumable: a clone that already has every requested pattern is
# skipped, so the script can be interrupted and run again.
#
#   ./widen_sparse.sh corpus_foundry '*.json'
#   ./widen_sparse.sh corpus_foundry '*.json' '*.jsonc'
#
set -uo pipefail

CORPUS="${1:-}"
shift || true
PATTERNS=("$@")

if [ -z "$CORPUS" ] || [ "${#PATTERNS[@]}" -eq 0 ]; then
  echo "usage: $0 <corpus-dir> <pattern> [pattern...]" >&2
  echo "example: $0 corpus_foundry '*.json'" >&2
  exit 2
fi
if [ ! -d "$CORPUS" ]; then
  echo "no such corpus directory: $CORPUS" >&2
  exit 2
fi

count_matching() {
  # Files in the working tree matching the requested patterns, so the gain is
  # measurable rather than assumed.
  local d="$1" n=0 p
  for p in "${PATTERNS[@]}"; do
    n=$(( n + $(find "$d" -name "$p" -not -path '*/.git/*' 2>/dev/null | wc -l) ))
  done
  echo "$n"
}

total=$(find "$CORPUS" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
echo "corpus:   $CORPUS"
echo "clones:   $total"
echo "patterns: ${PATTERNS[*]}"
echo

before=$(count_matching "$CORPUS")
echo "files matching before: $before"
echo

i=0; widened=0; skipped=0; failed=0
failed_list=()
start=$(date +%s)

for d in "$CORPUS"/*/; do
  [ -d "$d/.git" ] || continue
  i=$((i+1))

  have=$(cd "$d" && git sparse-checkout list 2>/dev/null)
  missing=0
  for p in "${PATTERNS[@]}"; do
    grep -qxF -- "$p" <<<"$have" || missing=1
  done
  if [ "$missing" -eq 0 ]; then
    skipped=$((skipped+1))
  else
    if ( cd "$d" && git sparse-checkout add -- "${PATTERNS[@]}" >/dev/null 2>&1 ); then
      widened=$((widened+1))
    else
      failed=$((failed+1)); failed_list+=("$d")
    fi
  fi

  if [ $((i % 20)) -eq 0 ] || [ "$i" -eq "$total" ]; then
    now=$(date +%s); el=$((now-start))
    printf '  %4d/%-4d  widened %-4d skipped %-4d failed %-3d  %ds elapsed\n' \
      "$i" "$total" "$widened" "$skipped" "$failed" "$el"
  fi
done

after=$(count_matching "$CORPUS")
echo
echo "files matching after:  $after   (gained $((after-before)))"
echo "widened $widened, already had it $skipped, failed $failed"

if [ "$failed" -gt 0 ]; then
  echo
  echo "failed clones, re-run to retry them:"
  printf '  %s\n' "${failed_list[@]}"
fi

echo
echo "Now re-run the census, because the corpus changed:"
echo "  python3 evaluation/benchmark/foundry_recon.py --corpus $CORPUS \\"
echo "      --json evaluation/benchmark/foundry_recon.json"

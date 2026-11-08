#!/usr/bin/env bash
# collect_corpus_v3.sh - paginated, resumable corpus collection.
#
# WHY THIS REPLACES collect_corpus_tier2.sh
#   The old collector called the code-search API with per_page=100 and no page
#   loop, so every query returned at most its first page. Measured 2026-10-14
#   with `gh api search/code --jq .total_count`, the 11 queries match 8167
#   files in total; the old collector could see at most 1100 of them, and
#   deduped to 351 distinct repos.
#
#   GitHub code search serves at most 1000 results per query (10 pages of
#   100). A query whose total_count exceeds 1000 is split here into disjoint
#   file size buckets, each paged separately, so the union reaches past the
#   ceiling. The buckets partition the byte range, so no file is counted twice
#   and none falls between them.
#
# RESUMABLE
#   .queries_done        query keys fully harvested  (skipped on re-run)
#   .raw_repos           every repo name any page returned (append only)
#   .seen                deduped repo list, the clone list
#   .clone_manifest.tsv  repo, clone mode, timestamp
#   .clone_failed        repos whose clone failed
#   .query_stats.tsv     per query: total_count, pages fetched, ceiling hit
#   Existing clone directories are never re-cloned. Safe to interrupt.
#
# CLONE MODE
#   Default is a blobless sparse clone carrying only the paths the analysers
#   read. agentpathtriage reads *.tf (tf_to_state, gap, topology,
#   corpus_population, scan_s1) and *.py (codereq.CODE_EXT, codecolo_check).
#   The pattern below is a superset of both.
#   Measured on the existing 60-repo sample the median repo is 3 MB and the
#   mean 85 MB, so a few binary-heavy repos dominate a full clone; a blobless
#   clone never fetches those blobs.
#   SPARSE=0 restores the old full --depth 1 clone.
#   Run verify_sparse_equiv.sh FIRST. It clones the same commit both ways and
#   compares the *.tf and *.py bytes. Do not trust this mode without it.
#
# USAGE
#   bash evaluation/benchmark/collect_corpus_v3.sh
#   DISCOVER_ONLY=1 bash ...    build .seen, clone nothing
#   CLONE_ONLY=1    bash ...    clone whatever .seen already holds
#   CAP=1000        bash ...    stop after 1000 new clones
#   SPARSE=0        bash ...    full clones
#
# Requires gh authenticated (gh auth status) and jq.

set -u

OUT="${OUT:-corpus_tier2}"
CAP="${CAP:-100000}"
SLEEP="${SLEEP:-7}"              # code search allows 10 req/min authenticated
CLONE_TIMEOUT="${CLONE_TIMEOUT:-120}"
SPARSE="${SPARSE:-1}"
MIN_FREE_GB="${MIN_FREE_GB:-20}" # stop cloning below this much free space
DISCOVER_ONLY="${DISCOVER_ONLY:-0}"
CLONE_ONLY="${CLONE_ONLY:-0}"
MAX_PAGES=10                     # the API refuses page 11 of a code search

# gh is only needed to discover. CLONE_ONLY works from an existing .seen with
# git alone, which is what lets the two halves run in different places: search
# where a GitHub token lives, clone where the disk is.
if [ "$CLONE_ONLY" != "1" ]; then
  command -v gh >/dev/null 2>&1 || { echo "gh not found (needed to discover; CLONE_ONLY=1 does not need it)" >&2; exit 2; }
fi
command -v jq  >/dev/null 2>&1 || { echo "jq not found" >&2; exit 2; }
command -v git >/dev/null 2>&1 || { echo "git not found" >&2; exit 2; }
if [ "$CLONE_ONLY" != "1" ]; then
  gh auth status >/dev/null 2>&1 || { echo "gh is not authenticated: run 'gh auth login'" >&2; exit 2; }
fi

mkdir -p "$OUT"
SEEN="$OUT/.seen"
RAW="$OUT/.raw_repos"
DONE="$OUT/.queries_done"
STATS="$OUT/.query_stats.tsv"
ERRLOG="$OUT/.errors.log"
MANIFEST="$OUT/.clone_manifest.tsv"
FAILED="$OUT/.clone_failed"
touch "$SEEN" "$RAW" "$DONE" "$ERRLOG" "$MANIFEST" "$FAILED"
[ -s "$STATS" ] || printf 'query\ttotal_count\tpages_fetched\tceiling_hit\n' > "$STATS"

export GIT_TERMINAL_PROMPT=0 GIT_LFS_SKIP_SMUDGE=1

TO=""
if   command -v gtimeout >/dev/null 2>&1; then TO="gtimeout ${CLONE_TIMEOUT}"
elif command -v timeout  >/dev/null 2>&1; then TO="timeout  ${CLONE_TIMEOUT}"
fi

# The default query set is the AWS AgentCore one, unchanged from
# collect_corpus_tier2.sh so the only difference between the old corpus and
# this one is pagination depth. QUERY_FILE points at a file with one query per
# line instead, which is how a second platform gets its own corpus without a
# second copy of this script.
QUERIES=(
  'aws_bedrockagentcore_agent_runtime extension:tf'
  'aws_bedrockagentcore_memory extension:tf'
  'aws_bedrockagentcore_gateway extension:tf'
  'aws_bedrockagentcore_code_interpreter extension:tf'
  'agent_runtime_artifact extension:tf'
  '"bedrock-agentcore:" extension:tf'
  '"iam:PassRole" bedrock extension:tf'
  'aws_bedrockagent_agent extension:tf'
  'aws_bedrockagentcore extension:tf'
  '"iam:PassRole" sagemaker extension:tf'
  'bedrock agent aws_iam_role extension:tf'
)

if [ -n "${QUERY_FILE:-}" ]; then
  [ -r "$QUERY_FILE" ] || { echo "QUERY_FILE not readable: $QUERY_FILE" >&2; exit 2; }
  QUERIES=()
  while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    QUERIES+=("$line")
  done < "$QUERY_FILE"
  [ "${#QUERIES[@]}" -gt 0 ] || { echo "no queries in $QUERY_FILE" >&2; exit 2; }
  echo "queries: ${#QUERIES[@]} from $QUERY_FILE"
fi

# Disjoint, exhaustive partition of file size in bytes. Only used when a
# query exceeds the 1000-result ceiling.
SIZE_BUCKETS=(
  'size:<500'
  'size:500..1500'
  'size:1500..3000'
  'size:3000..6000'
  'size:6000..12000'
  'size:12000..25000'
  'size:>25000'
)

# gitignore syntax: a pattern with no slash matches at every depth. The list
# itself lives in sparse_patterns.sh, so the collector and the equivalence
# check cannot drift apart again.
. "$(dirname "${BASH_SOURCE[0]}")/sparse_patterns.sh"

free_gb() { df -Pk "$OUT" 2>/dev/null | awk 'NR==2 {printf "%d", $4/1048576}'; }

gh_search() {   # $1 query, $2 page -> JSON on stdout
  local q="$1" page="$2" try=0 out rc
  while [ "$try" -lt 5 ]; do
    out=$(gh api -X GET search/code -f q="$q" -f per_page=100 -f page="$page" 2>>"$ERRLOG")
    rc=$?
    if [ "$rc" -eq 0 ] && [ -n "$out" ]; then printf '%s' "$out"; return 0; fi
    try=$((try+1))
    printf '[retry %d] page=%s q=%s\n' "$try" "$page" "$q" >> "$ERRLOG"
    sleep $(( SLEEP * try * 2 ))
  done
  return 1
}

# Returns 0 only if the query was harvested completely. A partially harvested
# query is left out of .queries_done so a re-run picks it up again.
harvest() {     # $1 query, $2 depth
  local q="$1" depth="${2:-0}" json total pages p got before after b ok=1
  if grep -qxF "$q" "$DONE"; then
    echo "  (already harvested) $q"
    return 0
  fi
  json=$(gh_search "$q" 1) || { echo "  !! search failed, NOT marked done: $q"; return 1; }
  total=$(printf '%s' "$json" | jq -r '.total_count // 0')
  sleep "$SLEEP"
  echo "  total_count=${total}  <<${q}>>"

  if [ "$total" -gt 1000 ] && [ "$depth" -lt 1 ]; then
    echo "  -> past the 1000-result ceiling, splitting by file size"
    for b in "${SIZE_BUCKETS[@]}"; do
      harvest "$q $b" $((depth+1)) || ok=0
    done
    if [ "$ok" -eq 1 ]; then
      printf '%s\n' "$q" >> "$DONE"
    else
      echo "  !! a size bucket failed, parent NOT marked done: $q"
      return 1
    fi
    return 0
  fi

  pages=$(( (total + 99) / 100 ))
  [ "$pages" -gt "$MAX_PAGES" ] && pages="$MAX_PAGES"
  before=$(wc -l < "$RAW")
  for (( p=1; p<=pages; p++ )); do
    if [ "$p" -eq 1 ]; then
      got="$json"
    else
      got=$(gh_search "$q" "$p") || { echo "  !! page $p failed, NOT marked done"; ok=0; break; }
      sleep "$SLEEP"
    fi
    printf '%s' "$got" \
      | jq -r '.items[]? | select(.repository.fork==false) | .repository.full_name' \
      >> "$RAW"
  done
  after=$(wc -l < "$RAW")
  echo "     pages=${pages}  repo rows added=$(( after - before ))"
  [ "$ok" -eq 1 ] || return 1
  printf '%s\t%s\t%s\t%s\n' "$q" "$total" "$pages" \
    "$( [ "$total" -gt 1000 ] && echo yes || echo no )" >> "$STATS"
  printf '%s\n' "$q" >> "$DONE"
}

clone_one() {   # $1 repo, $2 dest
  local repo="$1" d="$2"
  if [ "$SPARSE" = "1" ]; then
    $TO git clone --depth 1 --filter=blob:none --sparse \
        "https://github.com/$repo" "$d" >/dev/null 2>&1 </dev/null || return 1
    ( cd "$d" && git sparse-checkout set --no-cone "${SPARSE_PATTERNS[@]}" \
        >/dev/null 2>&1 </dev/null ) || return 1
  else
    $TO git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=60 \
        clone --depth 1 "https://github.com/$repo" "$d" >/dev/null 2>&1 </dev/null || return 1
  fi
  return 0
}

# Clones made before v3 are not in the manifest. Record them as full, once,
# so the manifest describes the whole corpus and the mix stays auditable.
bootstrap_manifest() {
  local d repo n=0 known
  known=$(mktemp)
  awk -F'\t' 'NF {print $1}' "$MANIFEST" | sort -u > "$known"
  while IFS= read -r d; do
    repo=$(basename "$d" | sed 's|__|/|')
    grep -qxF "$repo" "$known" && continue
    printf '%s\tfull\tpre-v3\n' "$repo" >> "$MANIFEST"
    printf '%s\n' "$repo" >> "$known"
    n=$((n+1))
  done < <(find "$OUT" -mindepth 1 -maxdepth 1 -type d)
  rm -f "$known"
  [ "$n" -gt 0 ] && echo "manifest: recorded $n pre-existing clone(s) as mode=full"
  return 0
}

bootstrap_manifest

# ---------------------------------------------------------------- discover
if [ "$CLONE_ONLY" != "1" ]; then
  echo "== discovery =="
  qfail=0
  for q in "${QUERIES[@]}"; do
    harvest "$q" 0 || qfail=$((qfail+1))
  done
  sort -u "$RAW" "$SEEN" > "$SEEN.tmp" && mv "$SEEN.tmp" "$SEEN"
  echo
  echo "distinct non-fork repos discovered: $(wc -l < "$SEEN")"
  [ "$qfail" -gt 0 ] && echo "!! $qfail query/queries incomplete. Re-run to finish them."
fi

[ "$DISCOVER_ONLY" = "1" ] && { echo "DISCOVER_ONLY set, stopping before clone."; exit 0; }

# ------------------------------------------------------------------- clone
echo
echo "== clone (mode: $( [ "$SPARSE" = "1" ] && echo sparse-blobless || echo full ), free $(free_gb)GB) =="
count=0; skipped=0; failed=0; stopped=""
while read -r repo; do
  [ -z "$repo" ] && continue
  d="$OUT/${repo/\//__}"
  if [ -d "$d" ]; then skipped=$((skipped+1)); continue; fi
  if [ "$count" -ge "$CAP" ]; then stopped="CAP $CAP reached"; break; fi
  if [ "$(free_gb)" -lt "$MIN_FREE_GB" ]; then
    stopped="free space below ${MIN_FREE_GB}GB"; break
  fi
  if clone_one "$repo" "$d"; then
    count=$((count+1))
    printf '%s\t%s\t%s\n' "$repo" \
      "$( [ "$SPARSE" = "1" ] && echo sparse || echo full )" \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$MANIFEST"
    [ $(( count % 25 )) -eq 0 ] && echo "  cloned $count ... (free $(free_gb)GB)"
  else
    failed=$((failed+1))
    printf '%s\n' "$repo" >> "$FAILED"
    rm -rf "$d" 2>/dev/null
  fi
done < "$SEEN"

echo
[ -n "$stopped" ] && echo "stopped early: $stopped"
echo "discovered   : $(wc -l < "$SEEN")"
echo "already had  : $skipped"
echo "newly cloned : $count"
echo "clone failed : $failed   (see $FAILED)"
echo "total dirs   : $(find "$OUT" -mindepth 1 -maxdepth 1 -type d | wc -l)"
echo "free space   : $(free_gb)GB"
echo
echo "next, re-derive every corpus number as a delta against the committed"
echo "artifacts, then adopt them only once you have looked at the delta:"
echo "  python3 evaluation/benchmark/remeasure.py --corpus $OUT"
echo "  python3 evaluation/benchmark/remeasure.py --corpus $OUT --promote"
echo "  python3 evaluation/reproduce.py --full"

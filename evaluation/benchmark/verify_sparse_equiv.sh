#!/usr/bin/env bash
# verify_sparse_equiv.sh - does a sparse clone carry the same files the
# analysers read as a full clone does?
#
# collect_corpus_v3.sh defaults to a blobless sparse clone. That is only safe
# if, for the paths agentpathtriage reads, a sparse clone and a full clone of
# the same commit hold the same set. The analysers read *.tf (tf_to_state,
# gap, topology, corpus_population, scan_s1) and *.py (codereq.CODE_EXT,
# codecolo_check).
#
# Both clones are taken NOW, from the same remote, so a repo that changed
# since the original corpus was collected cannot show up as a difference.
# Only the sparse flag differs between the two.
#
# Usage:
#   bash verify_sparse_equiv.sh                 # 10 repos from corpus_tier2
#   N=25 CORPUS=corpus_tier2 bash verify_sparse_equiv.sh
#
# Exit 0 if every sampled repo matches, 1 if any repo differs.

set -u
CORPUS="${CORPUS:-corpus_tier2}"
N="${N:-10}"
WORK="${WORK:-$(mktemp -d)}"
export GIT_TERMINAL_PROMPT=0 GIT_LFS_SKIP_SMUDGE=1

# The same list the collector uses, sourced rather than copied. The copy that
# used to live here had already drifted from the collector's.
. "$(dirname "${BASH_SOURCE[0]}")/sparse_patterns.sh"

# Build the find expression from the pattern list, so the check covers exactly
# the paths the clone is meant to carry. The old version compared only *.tf and
# *.py, which said nothing about the yaml, json and ts a CloudFormation or CDK
# corpus is made of.
FIND_EXPR=()
for pat in "${SPARSE_PATTERNS[@]}"; do
  case "$pat" in !*) continue;; esac
  [ ${#FIND_EXPR[@]} -gt 0 ] && FIND_EXPR+=( -o )
  FIND_EXPR+=( -name "$pat" )
done

if   command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"
elif command -v shasum    >/dev/null 2>&1; then SHA="shasum -a 256"
else echo "no sha256sum or shasum" >&2; exit 2
fi

TO=""
if command -v gtimeout >/dev/null 2>&1; then TO="gtimeout 180"
elif command -v timeout  >/dev/null 2>&1; then TO="timeout 180"
fi

# hash every path in a list file, relative to a repo root. Paths may contain
# spaces, so read them one line at a time rather than through xargs.
hash_list() {   # $1 repo root, $2 list file
  local root="$1" lst="$2" rel
  while IFS= read -r rel; do
    [ -z "$rel" ] && continue
    ( cd "$root" && $SHA "$rel" 2>/dev/null )
  done < "$lst" | awk '{print $1}' | sort
}

# Sample repos that actually contain a .tf file, since those are the ones the
# measurements depend on. Deterministic order, so a re-run samples the same.
repos=$(find "$CORPUS" -mindepth 1 -maxdepth 1 -type d \
        | sort \
        | while read -r d; do
            if find "$d" -name '*.tf' -print -quit | grep -q .; then
              basename "$d" | sed 's|__|/|'
            fi
          done \
        | head -n "$N")

[ -z "$repos" ] && { echo "no repos with .tf found under $CORPUS" >&2; exit 2; }

echo "workdir: $WORK"
echo
printf '%-50s %8s %8s %s\n' "repo" "full" "sparse" "verdict"
printf '%s\n' "--------------------------------------------------------------------------------"

bad=0; checked=0; skipped=0
for repo in $repos; do
  f="$WORK/full/${repo//\//__}"
  s="$WORK/sparse/${repo//\//__}"
  mkdir -p "$(dirname "$f")" "$(dirname "$s")"

  $TO git clone --depth 1 "https://github.com/$repo" "$f" >/dev/null 2>&1 || {
    printf '%-50s %8s %8s %s\n' "$repo" "-" "-" "SKIP (full clone failed)"
    skipped=$((skipped+1)); continue; }
  $TO git clone --depth 1 --filter=blob:none --sparse "https://github.com/$repo" "$s" >/dev/null 2>&1 || {
    printf '%-50s %8s %8s %s\n' "$repo" "-" "-" "SKIP (sparse clone failed)"
    skipped=$((skipped+1)); continue; }
  ( cd "$s" && git sparse-checkout set --no-cone "${SPARSE_PATTERNS[@]}" >/dev/null 2>&1 ) || {
    printf '%-50s %8s %8s %s\n' "$repo" "-" "-" "SKIP (sparse-checkout failed)"
    skipped=$((skipped+1)); continue; }

  # the two clones must be the same commit, or the comparison means nothing
  cf=$(cd "$f" && git rev-parse HEAD 2>/dev/null)
  cs=$(cd "$s" && git rev-parse HEAD 2>/dev/null)
  if [ "$cf" != "$cs" ]; then
    printf '%-50s %8s %8s %s\n' "$repo" "-" "-" "SKIP (HEAD moved mid-check)"
    skipped=$((skipped+1)); continue
  fi

  ( cd "$f" && find . \( "${FIND_EXPR[@]}" \) -type f | sed 's|^\./||' | sort ) > "$WORK/f.lst"
  ( cd "$s" && find . \( "${FIND_EXPR[@]}" \) -type f | sed 's|^\./||' | sort ) > "$WORK/s.lst"
  nf=$(wc -l < "$WORK/f.lst"); ns=$(wc -l < "$WORK/s.lst")
  checked=$((checked+1))

  if diff -q "$WORK/f.lst" "$WORK/s.lst" >/dev/null; then
    # paths match; now check the bytes behind every one of them match too
    hash_list "$f" "$WORK/f.lst" > "$WORK/f.sha"
    hash_list "$s" "$WORK/s.lst" > "$WORK/s.sha"
    if diff -q "$WORK/f.sha" "$WORK/s.sha" >/dev/null; then
      printf '%-50s %8s %8s %s\n' "$repo" "$nf" "$ns" "match"
    else
      printf '%-50s %8s %8s %s\n' "$repo" "$nf" "$ns" "CONTENT DIFFERS"
      bad=$((bad+1))
    fi
  else
    printf '%-50s %8s %8s %s\n' "$repo" "$nf" "$ns" "PATHS DIFFER"
    diff "$WORK/f.lst" "$WORK/s.lst" | head -10 | sed 's/^/      /'
    bad=$((bad+1))
  fi
  rm -rf "$f" "$s"
done

echo
echo "checked: $checked   skipped: $skipped   mismatched: $bad"
if [ "$bad" -gt 0 ]; then
  echo "VERDICT: sparse clone is NOT equivalent. Run the collector with SPARSE=0."
  exit 1
fi
if [ "$checked" -eq 0 ]; then
  echo "VERDICT: nothing was checked. No evidence either way."
  exit 2
fi
echo "VERDICT: sparse and full clones carry the same bytes, for every pattern in sparse_patterns.sh, on all $checked sampled repos."
rm -rf "$WORK"
exit 0

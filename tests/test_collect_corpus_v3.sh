#!/usr/bin/env bash
# logic tests for collect_corpus_v3.sh discovery, against a fake gh.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../evaluation/benchmark/collect_corpus_v3.sh"
export PATH="$HERE/fixtures/fake_gh:$PATH"
fails=0

ok()  { printf '  PASS  %s\n' "$1"; }
bad() { printf '  FAIL  %s\n     expected: %s\n     actual:   %s\n' "$1" "$2" "$3"; fails=$((fails+1)); }
eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1" "$2" "$3"; }

newenv() {
  W=$(mktemp -d)
  export CALLLOG="$W/calls" TOTALS="$W/totals"
  : > "$CALLLOG"
  unset FAILPAGE
}

run() { # extra env assignments come from the caller
  ( cd "$W" && OUT=c DISCOVER_ONLY=1 SLEEP=0 bash "$SCRIPT" >"$W/out.txt" 2>&1 )
  echo $?
}

# the 11 real queries; give every one 0 except the ones a test names
zero_totals() {
  : > "$TOTALS"
  while IFS= read -r q; do printf '%s|0\n' "$q" >> "$TOTALS"; done <<'EOF'
aws_bedrockagentcore_agent_runtime extension:tf
aws_bedrockagentcore_memory extension:tf
aws_bedrockagentcore_gateway extension:tf
aws_bedrockagentcore_code_interpreter extension:tf
agent_runtime_artifact extension:tf
"bedrock-agentcore:" extension:tf
"iam:PassRole" bedrock extension:tf
aws_bedrockagent_agent extension:tf
aws_bedrockagentcore extension:tf
"iam:PassRole" sagemaker extension:tf
bedrock agent aws_iam_role extension:tf
EOF
}
set_total() { # $1 query, $2 total
  grep -vxF "$1|$(grep -F "$1|" "$TOTALS" | head -1 | cut -d'|' -f2)" "$TOTALS" > "$TOTALS.t" 2>/dev/null
  grep -vF "$1|" "$TOTALS" > "$TOTALS.t"; mv "$TOTALS.t" "$TOTALS"
  printf '%s|%s\n' "$1" "$2" >> "$TOTALS"
}

echo "T1  a 657-result query is paged to completion, not truncated at 100"
newenv; zero_totals
set_total 'aws_bedrockagentcore_agent_runtime extension:tf' 657
run >/dev/null
eq "pages for that query" 7 \
   "$(grep -c 'q=aws_bedrockagentcore_agent_runtime extension:tf$' "$CALLLOG")"
eq "one probe per other query" 10 \
   "$(grep -c 'CALL page=1 ' "$CALLLOG" | awk '{print $1-1}')"
eq "repos discovered" 657 "$(wc -l < "$W/c/.seen" | tr -d ' ')"

echo
echo "T2  the old behaviour would have given 100; v3 must beat it"
eq "more than one page" "yes" "$( [ "$(wc -l < "$W/c/.seen")" -gt 100 ] && echo yes || echo no )"

echo
echo "T3  a query over the 1000 ceiling splits into the 7 size buckets"
newenv; zero_totals
set_total 'bedrock agent aws_iam_role extension:tf' 2672
for b in 'size:<500' 'size:500..1500' 'size:1500..3000' 'size:3000..6000' \
         'size:6000..12000' 'size:12000..25000' 'size:>25000'; do
  set_total "bedrock agent aws_iam_role extension:tf $b" 300
done
run >/dev/null
eq "buckets probed"   7    "$(grep -c 'CALL page=1 q=bedrock agent aws_iam_role extension:tf size:' "$CALLLOG")"
eq "union of buckets" 2100 "$(wc -l < "$W/c/.seen" | tr -d ' ')"
eq "parent marked done" "yes" \
   "$(grep -qxF 'bedrock agent aws_iam_role extension:tf' "$W/c/.queries_done" && echo yes || echo no)"

echo
echo "T4  a single query is capped at 1000 even if total_count is larger"
newenv; zero_totals
set_total 'aws_bedrockagentcore extension:tf' 1452
for b in 'size:<500' 'size:500..1500' 'size:1500..3000' 'size:3000..6000' \
         'size:6000..12000' 'size:12000..25000' 'size:>25000'; do
  set_total "aws_bedrockagentcore extension:tf $b" 1500   # each bucket also over
done
run >/dev/null
# depth 1 does not split again, so each bucket contributes at most 10 pages
eq "per-bucket cap honoured" 1000 \
   "$(grep -c 'CALL page=.* q=aws_bedrockagentcore extension:tf size:<500' "$CALLLOG" | awk '{print $1*100}')"

echo
echo "T5  re-running skips a query already in .queries_done"
newenv; zero_totals
set_total 'aws_bedrockagentcore_memory extension:tf' 350
run >/dev/null
first=$(grep -c 'CALL page=' "$CALLLOG")
: > "$CALLLOG"
run >/dev/null
eq "first run made calls" "yes" "$( [ "$first" -gt 0 ] && echo yes || echo no )"
eq "second run makes none" 0 "$(grep -c 'CALL page=' "$CALLLOG")"
eq ".seen unchanged" 350 "$(wc -l < "$W/c/.seen" | tr -d ' ')"

echo
echo "T6  a failing page leaves the query unmarked so a re-run retries it"
newenv; zero_totals
set_total 'aws_bedrockagentcore_gateway extension:tf' 423
export FAILPAGE='aws_bedrockagentcore_gateway:3'
run >/dev/null
eq "not marked done" "yes" \
   "$(grep -qxF 'aws_bedrockagentcore_gateway extension:tf' "$W/c/.queries_done" && echo no || echo yes)"
eq "pages 1-2 kept"  200 "$(wc -l < "$W/c/.seen" | tr -d ' ')"
unset FAILPAGE
: > "$CALLLOG"
run >/dev/null
eq "re-run completes it" "yes" \
   "$(grep -qxF 'aws_bedrockagentcore_gateway extension:tf' "$W/c/.queries_done" && echo yes || echo no)"
eq "all 423 now seen" 423 "$(wc -l < "$W/c/.seen" | tr -d ' ')"

echo
echo "T7  forks are dropped"
newenv; zero_totals
run >/dev/null
eq "empty corpus stays empty" 0 "$(wc -l < "$W/c/.seen" | tr -d ' ')"

echo
echo "T8  .seen is the union, an existing .seen is never truncated"
newenv; zero_totals
mkdir -p "$W/c"; printf 'legacy/repo\n' > "$W/c/.seen"
set_total 'aws_bedrockagentcore_memory extension:tf' 50
run >/dev/null
eq "legacy entry survives" "yes" \
   "$(grep -qxF 'legacy/repo' "$W/c/.seen" && echo yes || echo no)"
eq "union size" 51 "$(wc -l < "$W/c/.seen" | tr -d ' ')"

echo
if [ "$fails" -eq 0 ]; then echo "all tests passed"; exit 0; fi
echo "$fails test(s) failed"; exit 1

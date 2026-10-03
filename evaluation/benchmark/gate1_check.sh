#!/usr/bin/env bash
# gate1_check.sh - answers 10/20 Gate 1: is the config-to-role gap COMPUTABLE from
# static IaC? i.e. do agent templates declare, in the .tf, BOTH
#   (a) an agent binding (memory / code-interpreter / gateway / agent-runtime), and
#   (b) a granted role carrying bedrock-agentcore (or wildcard) permissions,
# in the same template. If few templates have both, the gap metric cannot scale and
# AsiaCCS is off regardless of chainable counts.
#
# Usage: bash gate1_check.sh corpus_tier2
set -u
ROOT="${1:-corpus_tier2}"

tfdirs() { find "$ROOT" -name '*.tf' -not -path '*/.terraform/*' -exec dirname {} \; | sort -u; }

both=0; binding_only=0; role_only=0; neither=0; total=0
BIND='aws_bedrockagentcore|bedrock-agentcore:(Get|Retrieve|Invoke|Create|Start|List).*(Memory|Event|CodeInterpreter|AgentRuntime|Gateway)|aws_bedrockagentcore_(memory|runtime|gateway|code_interpreter)'
GRANT='bedrock-agentcore:|aws_bedrockagentcore'

while read -r d; do
  [ -z "$d" ] && continue
  total=$((total+1))
  # (a) binding declared in this dir's .tf
  if grep -rqE "$BIND" "$d"/*.tf 2>/dev/null; then hasb=1; else hasb=0; fi
  # (b) a role/policy granting bedrock-agentcore actions in this dir
  if grep -rqE 'aws_iam_(role_policy|policy)' "$d"/*.tf 2>/dev/null && \
     grep -rqE "$GRANT" "$d"/*.tf 2>/dev/null; then hasg=1; else hasg=0; fi
  if   [ $hasb -eq 1 ] && [ $hasg -eq 1 ]; then both=$((both+1))
  elif [ $hasb -eq 1 ]; then binding_only=$((binding_only+1))
  elif [ $hasg -eq 1 ]; then role_only=$((role_only+1))
  else neither=$((neither+1)); fi
done < <(tfdirs)

echo "=== Gate 1: is config-to-role gap computable from static IaC? ==="
echo "tf templates scanned:        $total"
echo "both binding AND role (GAP COMPUTABLE):  $both"
echo "binding only (role elsewhere/runtime):   $binding_only"
echo "role only (no declared binding):         $role_only"
echo "neither:                                 $neither"
echo
echo "Gate 1 PASS if 'both' is a non-trivial count (the gap metric has a population)."
echo "If 'both' ~ 0 but 'binding only'/'role only' high -> bindings and grants live apart"
echo "or tools are registered at runtime -> gap not statically computable at scale -> arXiv."

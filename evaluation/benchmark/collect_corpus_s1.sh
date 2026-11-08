#!/usr/bin/env bash
# collect_corpus_s1.sh - clone the S1 (vendor-official) prevalence corpus.
# Public official/vendor sources that contain Terraform. Shallow, LFS skipped.
# Portable timeout: uses gtimeout (brew coreutils) or timeout if available, else
# runs git clone without a hang-guard (macOS has no `timeout` by default).
#
# Usage:  bash collect_corpus_s1.sh        # -> ./corpus_s1/<owner__repo>
set -u
OUT="${OUT:-corpus_s1}"
CLONE_TIMEOUT="${CLONE_TIMEOUT:-90}"
mkdir -p "$OUT"
export GIT_TERMINAL_PROMPT=0 GIT_LFS_SKIP_SMUDGE=1

# resolve a portable timeout wrapper (empty string = no timeout)
TO=""
if command -v gtimeout >/dev/null 2>&1; then TO="gtimeout ${CLONE_TIMEOUT}"
elif command -v timeout >/dev/null 2>&1; then TO="timeout ${CLONE_TIMEOUT}"
else : ; fi   # no gtimeout/timeout: git lowSpeed below still guards hangs

REPOS=(
  awslabs/amazon-bedrock-agentcore-samples
  aws-ia/terraform-aws-bedrock
  aws-samples/aws-generative-ai-terraform-samples
  aws-samples/sample-getting-started-with-amazon-agentcore
  azure-ai-foundry/foundry-samples
  Azure/terraform-azurerm-avm-res-cognitiveservices-account
  Azure-Samples/AI-Gateway
  Azure-Samples/azureai-samples
)

for r in "${REPOS[@]}"; do
  d="$OUT/${r/\//__}"
  if [ -d "$d" ]; then echo "have $r"; continue; fi
  if $TO git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=60 clone --depth 1 "https://github.com/$r" "$d" 2>/dev/null; then
    echo "OK   $r"
  else
    echo "MISS $r  (clone failed or timed out - skip)"
  fi
done
echo
echo "next: python3 scan_s1.py --root $OUT --json s1_prevalence.json"

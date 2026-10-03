#!/usr/bin/env bash
# collect_corpus_s1.sh - clone the S1 (vendor-official) prevalence corpus.
# Public, official/vendor sources that contain Terraform. Shallow, LFS skipped.
# Usage:  bash collect_corpus_s1.sh         # -> ./corpus_s1/<owner__repo>
set -u
OUT="${OUT:-corpus_s1}"
mkdir -p "$OUT"
export GIT_TERMINAL_PROMPT=0 GIT_LFS_SKIP_SMUDGE=1

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
  if timeout 90 git clone --depth 1 "https://github.com/$r" "$d" 2>/dev/null; then
    echo "OK   $r"
  else
    echo "MISS $r  (renamed/removed - skip)"
  fi
done
echo
echo "next: python3 scan_s1.py --root $OUT --json s1_prevalence.json"

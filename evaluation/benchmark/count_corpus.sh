#!/usr/bin/env bash
# count_corpus.sh - size the AgentPathTriage prevalence (E2) corpus via GitHub code search.
# Requires: gh CLI authenticated (`gh auth status`).
# Note: GitHub code search counts FILES on default branches of indexed repos; total_count
# is approximate but fine for sizing. Code search is rate-limited (~10 req/min), so this
# sleeps between calls. Dedup to distinct repos/templates happens later, after collection.

set -u
q() {
  # $1 = label, $2 = code-search query
  local n
  n=$(gh api -X GET search/code -f q="$2" --jq '.total_count' 2>/dev/null || echo "ERR")
  printf "%-55s %s\n" "$1" "$n"
  sleep 7
}

echo "=== Tier 1: dedicated AgentCore / Foundry IaC (exhaustive slice) ==="
q "AgentCore Terraform (aws_bedrockagentcore)"        'aws_bedrockagentcore extension:tf'
q "AgentCore in HCL (bedrock-agentcore)"              'bedrock-agentcore extension:tf'
q "AgentCore CloudFormation (yaml)"                   'BedrockAgentCore extension:yaml'
q "AgentCore CloudFormation (json)"                   'BedrockAgentCore extension:json'
q "AgentCore CDK (TypeScript)"                        'bedrock-agentcore extension:ts'
q "Foundry Terraform (azurerm ai foundry)"            'azurerm_ai_foundry extension:tf'
q "Foundry Bicep (accounts/projects)"                 'CognitiveServices/accounts/projects extension:bicep'
q "Foundry connected agent (bicep)"                   'connectedAgent extension:bicep'

echo
echo "=== Tier 2: delegation pattern in agent-adjacent IaC (scale) ==="
q "PassRole + bedrock (HCL)"                          '"iam:PassRole" bedrock extension:tf'
q "AssumeRole + bedrock (HCL)"                        '"sts:AssumeRole" bedrock extension:tf'
q "aws_bedrock_agent role (HCL)"                      'aws_bedrockagent_agent extension:tf'
q "bedrock agent + iam_role (HCL)"                    'bedrock agent aws_iam_role extension:tf'
q "sagemaker + PassRole (HCL)"                        '"iam:PassRole" sagemaker extension:tf'
q "PassRole wildcard resource (HCL)"                  '"iam:PassRole" "Resource" "*" extension:tf'

echo
echo "Done. Use total_count as an upper bound per query; collect + content-hash dedup next."

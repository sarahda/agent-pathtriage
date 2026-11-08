#!/usr/bin/env bash
# Build the minimal ARM64 agent image and push it to both lab ECR repos.
# Run this AFTER `terraform apply` has created the ECR repos, then apply again
# so the agent runtimes can pull `:latest`.
set -euo pipefail

# Region and prefix come from the deployment, not from this file. They were
# written here as literals, which meant changing var.name_prefix or var.region
# silently pushed to the wrong repository name.
REGION="${1:-$(terraform output -raw region 2>/dev/null || echo us-east-1)}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
PREFIX="$(terraform output -raw agent_a_ecr 2>/dev/null | sed -E 's#.*/([^/]+)/[^/]+$#\1#')"
if [ -z "$PREFIX" ]; then
  echo "cannot read the repository prefix from terraform output." >&2
  echo "Run terraform apply for the ECR repositories first." >&2
  exit 1
fi
echo "region=$REGION  account=$ACCOUNT_ID  prefix=$PREFIX"

aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

for agent in agent-a agent-b; do
  REPO="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${PREFIX}/${agent}"
  # ARM64 is mandatory for AgentCore
  docker buildx build --platform linux/arm64 -t "${REPO}:latest" --push ./agent-src
  echo "pushed ${REPO}:latest"
done

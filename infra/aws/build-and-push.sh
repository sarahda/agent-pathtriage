#!/usr/bin/env bash
# Build the minimal ARM64 agent image and push it to both lab ECR repos.
# Run this AFTER `terraform apply` has created the ECR repos, then apply again
# so the agent runtimes can pull `:latest`.
set -euo pipefail

REGION="${1:-us-east-1}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
PREFIX="apt-lab"

aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

for agent in agent-a agent-b; do
  REPO="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${PREFIX}/${agent}"
  # ARM64 is mandatory for AgentCore
  docker buildx build --platform linux/arm64 -t "${REPO}:latest" --push ./agent-src
  echo "pushed ${REPO}:latest"
done

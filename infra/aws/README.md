# infra/aws: AgentPathTriage Lab (AWS Bedrock AgentCore)

A minimal two-agent AgentCore lab for reproducing cross-agent IAM privilege
escalation. **AgentA** runs under an over-privileged role (the disclosed
starter-toolkit role); **AgentB** is a correctly-scoped victim. AgentA's four
wildcard permissions are what let it reach AgentB's resources.

> This lab is intentionally insecure and runs only in a researcher-controlled
> account. See ../RESPONSIBLE_USE.md.

## Files
- `main.tf` / `variables.tf` : provider, region, tags
- `iam.tf` : **RoleA (over-privileged)** and **RoleB (scoped)** — the core of the study
- `resources.tf` : AgentB's ECR repo and memory store (the witnesses)
- `agents.tf` : the two `agent_runtime` resources
- `outputs.tf` : ARNs that `extract` and the PoCs consume
- `agent-src/` : minimal ARM64 placeholder agent + Dockerfile
- `build-and-push.sh` : build/push the agent image (ARM64)

## Requirements
- AWS provider **>= 6.51** (AgentCore resources)
- Region with AgentCore support (**us-east-1** default)
- Docker with `buildx` (image must be **ARM64 / Graviton**)

## Deploy (two-phase: repos must exist before the image is pushed)
```bash
terraform init
terraform apply -target=aws_ecr_repository.agent_a -target=aws_ecr_repository.agent_b  # 1. repos
./build-and-push.sh us-east-1                                                          # 2. push image
terraform apply                                                                        # 3. runtimes + memory
```

## Teardown (leave no orphans; watch for cost)
```bash
terraform destroy
```

## Notes
- `force_delete = true` on ECR so `destroy` is clean.
- AgentCore runtimes accrue cost while they exist; destroy when not in use.
- The over-privileged wildcards in `iam.tf` map to the primitives:
  ECR `*` -> CP-1/CP-5, `bedrock-agentcore:*` on `memory/*` -> CP-3,
  `InvokeCodeInterpreter` `*` -> CP-5, `InvokeAgentRuntime` on `runtime/*` -> CP-2.

# CP-1 / P1: ECR Cross-Agent Image Exfiltration

**Primitive:** CP-1 (credential inheritance) via an over-privileged execution role.
**Source (E1 oracle):** Mitigant, *AgentCore or AgentSore* (Jun 2026); Unit 42, *Agent God Mode* (2026).
**MITRE:** ATT&CK T1552.001, T1213; ATLAS AML.T0086.

## What this shows
AgentA runs under `RoleA`, whose policy grants `ecr:BatchGetImage` on `*`. That
wildcard lets AgentA pull **AgentB's** container image, which it does not own.
`RoleB` (scoped to its own repo) attempting the same is denied by AWS. Every
result is the live ECR API response; nothing is hardcoded.

## Preconditions
- The lab is deployed (`../../infra/aws`, `terraform apply`).
- The operator may assume `RoleA` and `RoleB` (trust policy in `iam.tf`),
  simulating a low-privilege principal that has obtained the agent role.

## Steps
```bash
cd attacks/cp1_ecr_cross_agent
python3 exploit.py
```
The script: assumes `RoleA`, calls `ecr:BatchGetImage` on AgentB's repo (witness);
assumes `RoleB`, calls the same on AgentA's repo (control); writes the outcomes to
`verification_log.json`.

## Observed result
- **RoleA -> AgentB image:** allowed (`batch_get_image returned 1 image`). Cross-agent reach confirmed.
- **RoleB -> AgentA image:** denied (`AccessDeniedException: no identity-based policy allows ecr:BatchGetImage`).
- **Witness confirmed:** RoleA allowed and RoleB denied.

## Telemetry signature
`BatchGetImage` calls appear in CloudTrail as ECR data/management events; a pull
of another agent's repository by an agent execution role is the detection signal.

## Notes / honesty
The witness is a plain read of two real API outcomes (allow vs deny). The control
role is denied by AWS with an explicit reason, recorded verbatim in the log.

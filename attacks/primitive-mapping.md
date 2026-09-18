# CP Primitive ↔ Documented Path Mapping (AWS)

Maps the five candidate primitives to the publicly documented AgentCore paths
(Mitigant, Unit 42) and to the concrete IAM action + resource scope that enables
each. This table is the specification `extract` works against: each row is an
`act` edge it must recover from configuration.

| CP | Primitive | Documented path (oracle) | IAM action(s) | Resource scope that enables it | Status |
|----|-----------|--------------------------|---------------|-------------------------------|--------|
| **CP-1** | Credential inheritance | Mitigant P1 (ECR image exfiltration) | `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer` | `*` (any repo) instead of own repo ARN | ✅ reproduced (P1) |
| **CP-2** | Unmediated inter-agent invocation | Mitigant P4 (runtime hijack) | `bedrock-agentcore:InvokeAgentRuntime` | `runtime/*` instead of own runtime ARN | ⬜ to reproduce |
| **CP-3** | Shared state poisoning | Mitigant P2 (memory access + poisoning) | `bedrock-agentcore:*` incl. `ListEvents`,`CreateEvent` | `memory/*` instead of own memory ARN | ✅ reproduced (P2) |
| **CP-4** | Tool scope over-grant | (partial — Gateway/tool binding) | tool/gateway invoke actions | tool binding wider than task scope | ⬜ candidate |
| **CP-5** | Execution substrate reuse | Mitigant P3 / Sonrai (code interpreter) | `bedrock-agentcore:InvokeCodeInterpreter` | `*` (shared interpreter across tiers) | ⬜ to reproduce |

## The signal `extract` looks for

For every IAM statement in an agent execution role, the escalation-enabling
condition is the **same shape**: an agentic/ECR action whose `Resource` is a
wildcard (`*` or `.../*`) rather than the agent's own resource ARN. That wildcard
is what turns a self-scoped permission into cross-agent reach.

- **own-scope** (safe): `Resource = arn:aws:...:memory/<this-agent-memory>`
- **wildcard** (CP): `Resource = arn:aws:...:memory/*`  → reaches other agents

So `extract` maps each statement to an `act` edge, and flags the edge as
cross-agent-reachable when the resource is a wildcard over an agentic resource type.

## MITRE ATLAS mapping (for the catalogue)

| CP | ATLAS / ATT&CK |
|----|----------------|
| CP-1 | ATT&CK T1552.001, T1213 |
| CP-2 | ATLAS AML.T0086 |
| CP-3 | ATLAS AML.T0086 (access), AML.T0080 (poisoning) |
| CP-5 | ATT&CK T1059.009; ATLAS AML.T0053 |

## Honesty note

CP-1 and CP-3 are **reproduced** (live-API verified, clean asymmetry). CP-2 and
CP-5 have a clear IAM signal but are **not yet reproduced end-to-end**. CP-4 is a
candidate whose witness depends on how Gateway tool bindings are scoped. The
matrix records these as `unresolved` until the three-part evidence standard is met.

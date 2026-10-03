# infra/foundry - Microsoft Foundry cross-agent lab (Wk3 kickoff)

The Foundry counterpart to `infra/aws`. Same thesis - a confused deputy at the
agent-identity layer - on a second managed platform, so the finding is not an
AWS-only artifact. This is the **kick-off**: the IaC is schema-grounded and
applies against a real subscription; end-to-end deploy + live witness is Wk4.

## The crux: OBO vs managed identity

On AWS the delegation edge is `iam:PassRole` / `sts:AssumeRole`. On Foundry the
equivalent is **how a call is authenticated as it crosses from one agent to
another**:

- **Managed identity passthrough** (`authType = ProjectManagedIdentity`): the call
  runs under the project's *managed identity*, whoever the caller is. If Agent A
  invokes Agent B over such a path, A executes with **B's** role assignments.
- **On-behalf-of (OBO / `AAD` delegated token)**: the call carries the *caller's*
  identity, so A's own permissions gate it.

The lab makes the two agents asymmetric - Agent B's identity can read a Key Vault
secret, Agent A's cannot - and exposes the auth mode as one variable
(`use_managed_identity_passthrough`). Flipping it flips whether the cross-agent
escalation exists. That single knob is the whole mechanism.

## What deploys (applies on a real subscription)

Resource types/API versions are taken verbatim from `azure-ai-foundry/
foundry-samples` (official), so this is not guessed HCL:

- one AI Foundry account (`Microsoft.CognitiveServices/accounts`, kind `AIServices`)
- two projects - `agentA`, `agentB` - each with its own user-assigned identity
- a Key Vault + secret (the sensitive target); **idB** gets `Key Vault Secrets
  User`, **idA** gets nothing
- a project connection on A whose `authType` is the passthrough knob

The A→B *connected-agent invocation* itself is an agent-service runtime action
(`agents.json`), reasoned over by `foundry_cp.py` - exactly as the AWS lab's agent
runtimes sit above its IAM.

## CP determination (`foundry_cp.py`)

Reads `terraform show -json` + `agents.json` and decides `Esc` and CP-1..CP-5.
Nothing hardcoded - every decision comes from role assignments, connection
authType, and the invocation topology.

| Primitive | Foundry mechanism the determiner keys on |
|---|---|
| CP-1 credential inheritance | invocation runs under callee's managed identity (passthrough) → caller gains callee's roles |
| CP-2 unmediated invocation | invocation with no per-call OBO check (`mediated=false`) |
| CP-3 shared-memory poisoning | a memory/thread store shared by >1 agent |
| CP-4 tool scope over-grant | a managed identity holds a broad data-plane role |
| CP-5 substrate reuse | one identity attached to >1 project/agent |

## Logic validated now (no Azure needed)

`test_foundry_cp.py` runs the determiner on synthetic states with known answers,
with the same controls as the AWS falsification:

| State | authType | A's own access | Esc A→B |
|---|---|---|---|
| escalation | ProjectManagedIdentity | none | **1** (gains KV Secrets User; CP-1,CP-2,CP-4) |
| control (OBO) | AAD | none | **0** (caller token gates it) |
| falsification | ProjectManagedIdentity | already granted | **0** (no gain) |

`CP-4` holds in every state (B genuinely has the broad role); only the *escalation*
(CP-1/CP-2) toggles with the auth mode - which is the point.

## Seeds E3 (AWS ↔ Foundry asymmetry)

The two platforms expose the same confused deputy through different primitives
(PassRole/AssumeRole vs managed-identity passthrough) and offer different native
controls (trust-side ARN conditions vs OBO enforcement). The `authType` knob is the
Foundry side of the E3 asymmetry matrix.

## Deploy (Wk4)

```bash
az login
cd infra/foundry
terraform init
terraform apply                                   # escalation state (passthrough)
python3 ../../agentpathtriage/foundry_cp.py --tfdir . --agents agents.json
terraform apply -var use_managed_identity_passthrough=false   # control (OBO)
python3 ../../agentpathtriage/foundry_cp.py --tfdir . --agents agents.json
terraform destroy
```

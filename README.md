# AgentPathTriage

Cross-agent IAM privilege-escalation discovery for managed agentic cloud platforms — AWS Bedrock AgentCore and Microsoft Foundry.

## Overview

Managed agentic platforms let one agent invoke another and call tools that execute under platform-assigned IAM identities. When agent A invokes agent B, the resulting cloud action executes under an identity associated with B — the invoked agent's execution role, or (depending on configuration) a delegated user identity — rather than necessarily the caller's own permissions. Where that identity exceeds the caller's, this is a privilege escalation across a *delegation boundary*: a confused-deputy problem at the IAM layer rather than the prompt layer.

AgentPathTriage models this delegation boundary, catalogues the escalation primitives that arise on each platform, and extracts escalation paths from deployed configuration. It extends **PathTriage** from static human/service IAM to the agent-delegation layer.

## Research questions

- **RQ1** — Can cross-agent escalation be expressed as a reachability property over a delegation graph grounded in provider IAM evaluation, in a provider-independent form?
- **RQ2** — Which escalation primitives exist on Bedrock AgentCore and Microsoft Foundry, and do the two platforms admit the same primitives?
- **RQ3** — Can the delegation graph be extracted automatically from deployed configuration?
- **RQ4** — How often do publicly available agent deployment templates exhibit at least one primitive?

## Scope

**In scope:** escalation arising from customer-side IAM configuration of managed agent platforms (AWS Bedrock AgentCore, Microsoft Foundry).

**Out of scope:** vulnerabilities in the platforms themselves; prompt-injection payload craft and model jailbreaking (treated as a trigger, not a mechanism); GCP / Vertex AI.

This project studies escalation arising from how customers configure agent IAM, not defects in the cloud platforms.

## Repository structure

| Path | Contents |
|---|---|
| `docs/` | Related work and project documentation |
| `model/` | Formal delegation model (graph definition and escalation predicate) |
| `infra/` | Reproducible lab environments (`aws/`, `foundry/`) |
| `attacks/` | Per-primitive proof-of-concept scripts and reproduction notes |
| `agentpathtriage/` | Tool package (`extract` / `check` / `rank`) |
| `evaluation/` | Evaluation protocol, oracle reproduction, corpus results |
| `detection/` | Control-plane detection rules |
| `tests/` | Unit and integration tests |
| `report/` | Technical report |

## Usage

`agentpathtriage` provides a command-line interface with three commands:

- `extract` — deployed configuration → delegation graph
- `check` — decide the escalation predicate for a given principal; return a witness path
- `rank` — order witnesses by an exploitability rubric adapted from PathTriage

## Responsible use

This repository contains security-research material, including proof-of-concept exploit scripts and an intentionally vulnerable lab environment. Use it only against accounts and tenants you own or are authorised to test. See [`RESPONSIBLE_USE.md`](RESPONSIBLE_USE.md).

## Relationship to PathTriage

AgentPathTriage extends PathTriage. The lab harness is reused for infrastructure only; the delegation-edge semantics are new.

## License

See [`LICENSE`](LICENSE).



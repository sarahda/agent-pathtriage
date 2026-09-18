# Baseline Comparison: why existing tools miss cross-agent escalation

**Purpose.** Kill the "did you just grade your own homework?" doubt by showing
that the best existing IAM/attack-graph tools, run on the *same* lab, do **not**
detect the cross-agent reach that AgentPathTriage does. This is external
validation of the contribution, not a self-authored benchmark.

## Tools to run (all on the same deployed lab: RoleA over-privileged, RoleB scoped)

| Tool | What it does | How it's run on the lab |
|---|---|---|
| **PMapper** (NCC Group) | Builds an IAM privesc graph over principals; queries reachability | `pmapper graph create` against the account, then `pmapper query "who can do bedrock-agentcore:* with memory/*"` |
| **AWS IAM Access Analyzer** | Flags external/over-broad access; generates least-privilege policy from CloudTrail | Enable analyzer on the account; inspect findings for RoleA; run policy generation |
| **Cloudsplaining** | Scores identity policies for over-permissiveness | `cloudsplaining scan` on the account authorization details |
| **AgentPathTriage (ours)** | Delegation graph incl. agent nodes; flags wildcard cross-agent `act` edges | `extract` on the deployed config |

## The hypothesis (what we expect, and why)

Existing tools evaluate **one principal in isolation** and have **no concept of an
agent whose execution identity differs from the caller**. So they should:

- **PMapper:** see RoleA as a role with broad permissions, but **not** model that
  invoking AgentB runs under AgentB's identity. It cannot express the cross-agent
  hop. It may flag RoleA as "powerful" but not the *delegation* reach.
- **Access Analyzer:** may flag RoleA's wildcards as over-broad, but it analyses
  each role alone, does **not** trace `iam:PassRole` or agent invocation, and has
  **no agent/delegation model**. It will not report "RoleA reaches AgentB's memory".
- **Cloudsplaining:** purely policy-local; reports "wildcard resource used" as a
  lint finding, with **no reachability** and no notion of the other agent.
- **AgentPathTriage:** reports the 4 cross-agent `act` edges (ECR, memory, runtime,
  interpreter) as reach into *another agent's* resources.

## Result table (fill after running; expected shape shown)

| Capability | PMapper | Access Analyzer | Cloudsplaining | **AgentPathTriage** |
|---|---|---|---|---|
| Flags RoleA wildcards as over-broad | partial | yes | yes | yes |
| Models agents as nodes | **no** | **no** | **no** | **yes** |
| Cross-agent reach (RoleA -> AgentB resources) | **no** | **no** | **no** | **yes (4 edges)** |
| Distinguishes RoleB (scoped) as safe by reach | no (policy-level only) | partial | no | **yes** |
| Decides the escalation predicate Esc(p) | **no** | **no** | **no** | **yes** |

**Headline number for the slide:** cross-agent edges detected —
`PMapper 0 / Access Analyzer 0 / Cloudsplaining 0 / AgentPathTriage 4`.

## Honesty guardrails
- Run each tool exactly as its docs intend; do not cripple a baseline to win.
- If a baseline *does* surface something relevant (e.g. Access Analyzer flagging
  the wildcard), report it — the point is not "they find nothing" but "they don't
  model the cross-agent delegation", which is a precise, defensible claim.
- Record each tool's version and exact command in `baseline/run-log.md`.
- The comparison is about **the delegation dimension**, not general quality; state
  that explicitly so it isn't read as "our tool is strictly better at everything".

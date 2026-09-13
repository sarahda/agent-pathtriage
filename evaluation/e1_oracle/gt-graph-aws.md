# Ground-Truth Delegation Graph — AWS Lab 1 (by hand, v0)

The "answer key" for one AWS lab, drawn by hand from the Mitigant/Unit42 role.
When `extract` runs on this lab, its graph should match this. This is what we check
the tool against (does it recover the same reach we drew?).

## Setup (2 agents, same account)
- **AgentA** — attacker-controlled agent. Runs as **RoleA** = the over-privileged
  AgentCore starter-toolkit role (wildcard scopes).
- **AgentB** — victim agent. Owns its own memory store, container image, code
  interpreter, and runtime.

## Nodes
- agents: AgentA, AgentB
- role: RoleA
- resources (owned by AgentB): B-memory, B-image, B-interpreter, B-runtime

## Edges (the answer key)
```
AgentA  --assume-->  RoleA

RoleA  --act: ecr:BatchGetImage  (repo/*)          -->  B-image        [wildcard -> cross-agent]
RoleA  --act: bedrock-agentcore:* (memory/*)       -->  B-memory       [wildcard -> cross-agent]
RoleA  --act: InvokeCodeInterpreter (*)            -->  B-interpreter  [wildcard -> cross-agent]
RoleA  --act: InvokeAgentRuntime (runtime/*)       -->  B-runtime      [wildcard -> cross-agent]

B-image, B-memory, B-interpreter, B-runtime  --owned_by-->  AgentB
```

## What the answer key says
- `auth(AgentA)` = AgentA's own resources only.
- `eff(AgentA)` also includes all four of AgentB's resources (via the wildcard edges).
- So `eff \ auth` has four items  ->  **Esc(AgentA) = TRUE**, with 4 witnesses
  (the four Mitigant/Unit42 paths: image, memory, interpreter, runtime).

## How we use it
- Run `extract` on this lab's config, then compare its graph to this one.
- **Recall = (witnesses the tool recovers) / 4.** Reported per the E1 method.
- Drawn by hand *before* running the tool, so it's an independent answer key.

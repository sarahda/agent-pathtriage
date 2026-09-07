# Formal Model v0 — Cross-Agent Delegation Graph

Week 0 draft. Defines the delegation graph, the authorised/effective sets, and the
escalation predicate `Esc`. Grounded in real provider IAM evaluation (not an abstract
relation). Revised as the catalogue and `propagate` normalisation mature.

## 1. Graph

A deployed agent system is modelled as a directed graph `G = (V, E)` with typed nodes

```
V = P ∪ A ∪ T ∪ R
```

- `P` — principals (users, service identities, CI identities)
- `A` — agents (Bedrock AgentCore agents; Foundry connected agents)
- `T` — tools (code interpreters, MCP servers, gateways, tool bindings)
- `R` — resources (memory stores, container images, runtimes, and other cloud resources)

Edges are labelled by relation:

| Edge | Meaning |
|---|---|
| `invoke(x, a)` | principal or agent `x` can cause agent `a` to execute |
| `assume(a, ρ)` | agent `a` executes under role / identity `ρ` |
| `propagate(a, b)` | `a`'s execution context reaches `b` — impersonation (same identity flows on) as opposed to a scoped re-issue (act-on-behalf with a reduced identity) |
| `act(ρ, r)` | role / identity `ρ` is authorised for resource `r` **under provider policy evaluation** |

The contribution over an abstract predicate is that `act` is **instantiated**, not assumed:
- **AWS** — identity-, resource-, and trust-policy resolution (effect, action, resource scope, conditions).
- **Azure/Foundry** — Entra role assignment and OAuth token audience/scope; the OBO-vs-managed-identity choice determines which `ρ` a delegated action runs under.

## 2. Authorised set

The resources a principal can reach **directly**, under its own identity:

```
auth(p) = { r ∈ R | act(ρ_p, r) }
```

where `ρ_p` is `p`'s own role/identity.

## 3. Effective set

The resources a principal can reach **through one or more agent hops** — the reach the
delegation edges actually grant:

```
eff(p) = { r ∈ R | ∃ path  p --invoke--> a₁ --propagate*--> aₙ --assume--> ρ --act--> r }
```

`propagate*` is zero or more propagation hops. `eff(p) ⊇ auth(p)`: everything reachable
directly is also reachable through the (possibly empty) hop sequence.

## 4. Escalation predicate

A principal is escalated iff delegation lets it reach resources its own identity cannot:

```
Esc(p)  ⟺  eff(p) \ auth(p) ≠ ∅
```

Each `r ∈ eff(p) \ auth(p)` is a **witness**: a resource reached only via the agent hops.
The `check` command decides `Esc(p)` and returns a witness path.

## 5. Worked instance (from the extract PoC)

The AgentCore starter-toolkit over-privileged role, extracted from configuration:

```
AgentA --assume--> Role
Role --act[ecr:BatchGetImage           on repository/*]--> ECR images
Role --act[bedrock-agentcore:*         on memory/*    ]--> Agent memory
Role --act[InvokeCodeInterpreter       on *           ]--> Code interpreters
Role --act[InvokeAgentRuntime          on runtime/*   ]--> Agent runtimes
```

The wildcard resource scopes (`*`, `.../*`) make each `act` reach resources belonging to
**other** agents (AgentB). So for the principal driving AgentA:

- `auth` = AgentA's own resources only;
- `eff` additionally includes AgentB's ECR image, memory, interpreter, and runtime;
- therefore `eff \ auth ≠ ∅`  ⟹  **`Esc = TRUE`**, with four witnesses (the four Mitigant/Unit42 paths).

This is the confused deputy at the IAM layer: every step is individually permitted; the
escalation is the wildcard-enabled cross-agent reach. The PoC (`agentpathtriage/extract_poc.py`)
computes exactly this from the role JSON.

## 6. Open items (v0 → v1)

- **`propagate` normalisation** — AWS credential propagation via role assumption is not
  semantically identical to Foundry identity propagation (OBO vs managed identity). v1 must
  either unify them or record the divergence as an explicit soundness caveat.
- **Soundness / completeness** — state the conditions under which a computed witness is a
  true escalation (no false witness) and whether all escalations are found (no missed witness),
  relative to the fidelity of `extract`.
- **`propagate` in the PoC** — the current extract handles a single role (`assume` + `act`);
  agent-to-agent `propagate` edges are not yet extracted.

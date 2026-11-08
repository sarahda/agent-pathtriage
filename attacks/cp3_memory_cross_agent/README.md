# CP-3 / P2: Memory Cross-Agent Exfiltration and Poisoning

**Primitive:** CP-3 (shared-state poisoning) via an over-privileged execution role.
**Source (E1 oracle):** Mitigant, *AgentCore or AgentSore* (Jun 2026); Unit 42, *Agent God Mode* (2026).
**MITRE:** ATLAS AML.T0086 (memory access), AML.T0080 (memory poisoning); ATT&CK T1552.

## What this shows
AgentA runs under `RoleA`, whose policy grants `bedrock-agentcore:*` on `memory/*`.
That wildcard lets AgentA both **read** and **write** AgentB's memory store, which
it does not own. The reproduction is a full chain: a secret is seeded into AgentB's
memory, RoleA exfiltrates it across the agent boundary, and RoleA writes a forged
event back (poisoning). `RoleB`, scoped to its own memory ARN, is denied when it
tries to read AgentA's memory. All outcomes are live AgentCore API responses.

## Preconditions
- The lab is deployed with **two** memory stores (AgentA and AgentB), so the
  control is a genuine foreign-memory access, not a self-access.
- The operator may assume `RoleA` and `RoleB`.

## Steps
```bash
cd attacks/cp3_memory_cross_agent
python3 exploit.py
```
The script: (1) seeds a unique secret into AgentB's memory as the owner;
(2) assumes `RoleA` and reads the secret back (exfil); (3) assumes `RoleA` and
writes a forged event (poison); (control) assumes `RoleB` and reads AgentA's
memory, expecting denial. Outcomes are written to `verification_log.json`.

## Observed result
- **Seed:** a unique secret event written to AgentB's memory.
- **Exfil (RoleA):** the exact seeded secret is read back across the boundary (`secret FOUND`).
- **Poison (RoleA):** a forged event is written and confirmed present.
- **Control (RoleB -> AgentA memory):** denied (`AccessDeniedException: no identity-based policy allows bedrock-agentcore:ListEvents`).
- **Witness confirmed:** exfil and poison both succeeded; clean asymmetry against the scoped role.

## Telemetry signature
`CreateEvent` / `ListEvents` on a memory store by an agent execution role that is
not the store's owner. Note that AgentCore masks `CreateEvent` bodies in CloudTrail
(`HIDDEN_DUE_TO_SECURITY_REASONS`), so the signal is the call pattern, not content.

## Notes / honesty
The witness is defined as exfil AND poison actually succeeding (the seeded secret
is matched exactly, and the forged event is retrieved after writing), so the
outcome cannot be faked. The control uses a second, foreign memory store to show
that the scoped role is genuinely denied, rather than relying on a single store
where the scoped role would legitimately have access.

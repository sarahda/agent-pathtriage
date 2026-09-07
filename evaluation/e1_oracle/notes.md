# E1 Oracle — AgentCore over-privileged role

**Verdict: E1 established.** Unit42 (original disclosure) + Mitigant (4-path
operationalisation) publish the over-privileged role and per-API attack steps,
which is sufficient to reproduce in-lab and to test whether `extract`/`check`
recover the paths from configuration alone.

## Oracle = 4 witness paths
| Path | Mechanism | Key API | MITRE |
|---|---|---|---|
| P1 ECR image exfiltration | pull any image -> read Memory ID | `ecr:BatchGetImage` | T1213, T1552.001 |
| P2 Memory access & poisoning | dump/poison any memory store | `ListEvents`, `CreateEvent` | AML.T0086, AML.T0080 |
| P3 Code interpreter escalation | run in a more-privileged interpreter | `InvokeCodeInterpreter` | T1059.009, AML.T0053 |
| P4 Runtime hijack | invoke any agent runtime | `InvokeAgentRuntime` | AML.T0086 |

## Notes
- Starter toolkit deprecated (AgentCore CLI now), but existing deployments keep
  the over-permissioned role -> supports the prevalence argument (RQ4).
- AWS added a docs warning after Unit42 disclosure; warning does not fix
  already-deployed roles.
- Positioning: AWS empirical discovery is NOT our novelty (Unit42/Mitigant/
  BeyondTrust). Use only as E1 oracle. Novelty = automated extraction,
  cross-provider, prevalence.

## extract PoC
`agentpathtriage/extract_poc.py` + `agentcore_role.json` -> `delegation_graph.png`
shows config -> delegation graph, flags wildcard `act` edges as cross-agent
reach, and evaluates Esc = TRUE. Toy PoC (single role); real tool must also
parse trust policies and agent-to-agent `propagate` edges.

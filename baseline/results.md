# Baseline comparison

Existing IAM analysis tools run against the same researcher lab, to locate the
exact point where their model stops and the cross-agent class begins. Both tools
were **run** (not inferred) on the deployed lab account (559292738121), 2026-10-03.

## What was run

- **Cloudsplaining 0.9.1** - `download` (account authorization details) + `scan`.
  Read-only.
- **PMapper (principalmapper) on Python 3.9 (conda env `pmap`)** -
  `graph create --include-regions us-east-1` + `query 'preset privesc *'`.
  Read-only. (The local Python 3.11 copy is unusable - a removed
  `from collections import Mapping` import - so the tool was run under a 3.9 env;
  region was pinned to us-east-1 because the default all-region sweep hangs on a
  disabled opt-in region.)

## Results on the lab

### Cloudsplaining

| Risk | Instances |
|---|---|
| **Privilege Escalation** | **0** |
| Data Exfiltration | 0 |
| Resource Exposure | 0 |
| Credentials Exposure | 2 |
| Infrastructure Modification | 2 |

Zero privilege-escalation findings, even with the over-privileged agent roles
(RoleC with `bedrock-agentcore:*`) present. Its privesc detection is a fixed set
of classic IAM patterns (`iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, …);
it is policy-local and models no cross-principal edge, so neither the
`bedrock-agentcore` actions nor the RoleA→RoleC chain are seen. The two
Credentials-Exposure and two Infrastructure-Modification findings are policy-local
classic risks; none describes the cross-agent chain.

### PMapper

```
Graph: 11 nodes, 1 edge, 1 admin, 10 tracked policies
Edge found:  role/apt-lab-roleA-thin  --sts:AssumeRole-->  role/apt-lab-roleC-overprivileged
preset privesc * :  user/pathtriage-admin is an administrative principal
                    (no escalation path reported)
```

The key empirical result: **PMapper models the delegation edge that Cloudsplaining
misses** - it builds `roleA-thin → roleC-overprivileged` via `sts:AssumeRole` in
its graph. **But it still reports 0 privilege-escalation paths.** The only
principal it calls administrative is the pre-existing human user
`pathtriage-admin`, not RoleC. PMapper has the role-to-role edge model but no
model of what RoleC's `bedrock-agentcore:*` grants, so it cannot value the
destination of the edge as a privilege gain.

## The boundary (empirical)

| Capability | Cloudsplaining | PMapper | AgentPathTriage |
|---|---|---|---|
| Classic single-principal privesc | fixed-pattern set (0 here) | yes | out of scope |
| Models role→role delegation edge (AssumeRole/PassRole) | **no** | **yes (edge found)** | yes |
| Flags the cross-role chain as an escalation | no | **no (privesc 0)** | **yes** |
| Models agent resources (memory/runtime/code-interpreter) → CP-1..CP-5 | no | no | **yes** |

Both baselines report **0** escalation on the lab, but for different reasons, and
the two reasons bracket the contribution:

1. **Cloudsplaining** never sees the delegation edge (no cross-principal model).
2. **PMapper** sees the edge but cannot tell the destination is powerful (no
   agent-resource / effective-permission model).
3. **AgentPathTriage** computes `eff(p)` across the agent resources reached
   through the edge, so it flags RoleA→RoleC as an escalation.

This is not a claim that the baselines are weak tools - they are strong at what
they model. The point is where the model ends: PMapper's edge model stops exactly
where agent-resource semantics begin, which is the gap this project fills. The
comparison is reported as this capability boundary plus two empirical anchors
(Cloudsplaining 0 privesc; PMapper 1 edge modelled yet 0 privesc), not as a
shared detection-rate number, since the tools have no common finding type for the
cross-agent class.

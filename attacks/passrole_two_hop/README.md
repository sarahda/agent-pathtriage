# CP: Two-Hop Delegation Escalation (PassRole / AssumeRole chain)

## Summary

A principal with **no direct resource permissions** reaches an over-privileged
resource by delegating execution to a second role. The escalation is invisible
to any analysis that inspects one principal's own policy in isolation; it only
appears when you follow the delegation edge.

```
RoleA_thin  --iam:PassRole / sts:AssumeRole-->  RoleC (over-privileged)  --act-->  AgentB memory
```

- **RoleA_thin** — only `iam:PassRole` and `sts:AssumeRole`, both scoped to RoleC.
  No `bedrock-agentcore` permissions of its own.
- **RoleC** — `bedrock-agentcore:*` on `memory/*` (intentionally over-privileged,
  research only).
- **Target** — AgentB's memory store.

## Why it matters

Single-hop analysis (including AWS IAM Access Analyzer and PMapper's default
principal view) evaluates each role's own action/resource pairs. RoleA_thin has
none that touch AgentB, so it is classified as safe. But because RoleA_thin can
hand execution to RoleC, its *effective* reach is the union with RoleC's
permissions.

This is the exact case our mutation testing flagged as a false negative
(`hard_passrole_two_hop`): the single-hop checker misses it. Recovering it is
the motivation for the multi-hop `propagate` step.

## Witnesses (live verification)

`exploit.py` verifies the chain against live AWS. Nothing is hardcoded; every
verdict is read from a real STS or AgentCore API response.

| Step | Action | Expected | Meaning |
|------|--------|----------|---------|
| W1 | RoleA_thin reads AgentB memory directly | `AccessDenied` | RoleA_thin has no direct access (control) |
| W2 | RoleA_thin assumes RoleC | success | the delegation hop |
| W3 | as RoleC, read AgentB memory | success | escalation reached |

`escalation_confirmed` is computed as `(not W1.ok) and W3.ok`, so it is True only
when RoleA_thin genuinely cannot act alone but can through the chain.

We exercise the **AssumeRole** variant for the live check because it needs no
running agent runtime (cheaper, faster). The **PassRole** edge is the equivalent
graph edge: passing RoleC to the AgentCore service launches an agent that runs as
RoleC, transferring the same effective permissions. Both are delegation edges
that `propagate` traverses.

## Run

```bash
python exploit.py \
  --role-a-thin "<role_a_thin_arn>" \
  --role-c      "<role_c_arn>" \
  --memory      "<agent_b_memory_arn>"
```

ARNs come from `terraform output` in `infra/aws/` (`role_a_thin_arn`,
`role_c_arn`, `agent_b_memory_arn`).

### Falsification check

Point `--role-a-thin` at RoleC itself. W1 then succeeds (RoleC has direct
access), so `escalation_confirmed` flips to False: a principal that already holds
the permission is not an escalation. This confirms the verdict tracks the real
API responses rather than a fixed outcome.

## Files

- `exploit.py` — the three-witness verifier.
- `verification_log.json` — the recorded run (real API responses, timestamps,
  assumed-role identities).

## Infrastructure

Provisioned by `infra/aws/passrole.tf` (RoleC, RoleA_thin, their inline policies)
and the existing `agent_b` memory store. The over-privileged roles are
intentionally insecure, exist only in a researcher-controlled account, and are
removed with `terraform destroy` after use.

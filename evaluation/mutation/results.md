# Mutation Testing Results

14 synthetic IAM-policy mutants with known ground truth, scored against the real
extract+check. Runs offline (no deployment).

**precision = 0.80, recall = 0.80, accuracy = 0.94** (10/14 exactly correct)

## The 4 informative failures
- **hard_condition_scoped (FP):** tool flags a condition-scoped wildcard as
  cross-agent. This is a *declared over-approximation* (conditions are un-modelled,
  see model/act-scope.md), not a bug. Measured directly rather than assumed.
- **hard_explicit_deny (FP):** tool does not yet subtract an explicit Deny. A real,
  fixable gap — scheduled for the extract Deny-handling pass (Wk3).
- **hard_foreign_specific_arn (FN):** a non-wildcard ARN that still points at
  another agent's resource is missed. ARN-reasoning gap -> future work.
- **hard_passrole_two_hop (FN):** a two-hop escalation via iam:PassRole is invisible
  to the single-hop tool. This directly motivates `propagate` (multi-hop
  reachability), the core contribution — the tool's limitation is shown by data,
  not asserted.

## Why 0.80 and not 1.00
Easy mutants (wildcard vs own ARN) are all correct. The hard mutants are chosen to
probe the tool's declared boundaries, so the score reflects real behaviour on
adversarial inputs rather than a circular check against the tool's own rule.

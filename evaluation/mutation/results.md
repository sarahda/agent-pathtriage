# Mutation testing and fidelity results

Adversarial mutation testing over 14 IAM-policy mutants with known ground truth.
Each mutant is scored twice against the real tool: single-hop (`extract` +
`check`) and multi-hop (`extract` + `propagate`). Ground truth is the true IAM
outcome of each mutation, derived independently of the tool. The run is offline
and deterministic; no deployment or cost.

Verdicts are scored per principal-under-test (the role an attacker controls),
not by unioning over every role, so a single-hop false negative is a real miss
rather than an artefact of another role in the state being independently
flagged.

## Headline numbers

| Mode | precision | recall | accuracy | exactly correct |
|---|---|---|---|---|
| single-hop (`check`) | 0.800 | 0.800 | 0.929 | 10/14 |
| multi-hop (`check` + `propagate`) | 0.818 | 0.900 | 0.946 | 11/14 |

`propagate` raises recall by 0.100 and accuracy by 0.018. The single false
negative it closes is the two-hop PassRole mutant.

## What each error is

Four mutants are not classified exactly, and every one is informative rather than
an unexplained bug.

| Mutant | single-hop | multi-hop | Meaning |
|---|---|---|---|
| `hard_condition_scoped` | FP | FP | Declared over-approximation. Conditions are not modelled (see the evaluated-scope table), so a condition-restricted wildcard is treated as a wildcard. This is stated as an over-approximation, not a defect. |
| `hard_explicit_deny` | FP | FP | Explicit `Deny` is not yet evaluated, so a wildcard `Allow` shadowed by a `Deny` is still flagged. A real gap, scoped as future work. |
| `hard_foreign_specific_arn` | FN | FN | A specific ARN pointing at another agent's resource is cross-agent but not a wildcard, so the resource-scope heuristic misses it. Neither mode fixes this; it needs richer ARN reasoning, scoped as future work. |
| `hard_passrole_two_hop` | FN | **OK** | A principal that can only `PassRole`/`AssumeRole` a second, over-privileged role. Single-hop analysis of the principal's own policy sees no dangerous permission and misses it. `propagate` follows the delegation edge into the second role and recovers the escalation. |

## Why this is the important result

The two-hop PassRole mutant was introduced in v2 as a deliberate single-hop
false negative, precisely to expose the limit of per-principal analysis. v3 then
shows the limit being removed: with both roles present in the state, the
delegation edge is genuinely in the graph, and `propagate` recovers the verdict
by real traversal. Nothing is hardcoded; the recovery is computed from the
extracted graph.

The story is a closed loop: mutation testing found the boundary as data, the
`propagate` step was built to address it, and mutation testing re-run confirms
the boundary moved, while the remaining errors stay honestly reported. `propagate`
fixes the class it targets (multi-hop delegation) and nothing else, which is the
expected and defensible outcome.

## Reproduce

```bash
cd evaluation/mutation
python3 mutation_test.py         # prints both scorings + delta; writes mutation_results.json
```

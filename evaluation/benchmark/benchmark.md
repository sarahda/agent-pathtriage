# External benchmark: IAM Vulnerable (BishopFox)

## Purpose

E1 measures recall on cross-agent paths, but no public benchmark exists for the
cross-agent case, which is the gap this project fills. This benchmark gives the
underlying delegation-reachability engine an external correctness measure on a
dataset this project did not author. IAM Vulnerable is a Terraform-deployed,
vulnerable-by-design playground of documented AWS IAM privilege-escalation
methods (the Rhino Security Labs set), with the escalatable principals published
as ground truth.

## Scope, stated honestly

The agentic `extract` models bedrock-agentcore edges; it does not read generic
IAM. A separate adapter, `extract_iam.py`, reads IAM Vulnerable's generic shape
(customer-managed policies, user and role principals, wildcard PassRole,
trust-based AssumeRole chains) and emits the same delegation-graph format, so the
unchanged `check.py` and `propagate.py` run on it.

This benchmark scores the **delegation subset**, which is what `propagate`
targets:

- **In scope, escalating (11):** the 10 PassRole-to-service paths and the
  AssumeRole chain start role. A correct tool should flag these.
- **In scope, safe (5):** the `tool-testing` false-positive cases, which should
  not be flagged.
- **Out of scope (excluded):** single-principal policy self-modification
  (CreatePolicyVersion, Attach/Put policy), credential creation, group
  membership, and trust self-update. A delegation-reachability model does not
  represent these, and they are excluded from scoring rather than counted as
  misses.

## What the result shows

The headline is the recall gap between single-hop and multi-hop on the same
external graph:

- **`check` (single-hop)** flags a principal only from its own policy. The
  escalation entries here hold only PassRole or AssumeRole, not a dangerous
  permission of their own, so single-hop recall on the delegation subset is near
  zero.
- **`propagate` (multi-hop)** follows the delegation edges (PassRole to a
  passable role, and the trust-based AssumeRole chain) into the over-privileged
  target, recovering the escalations single-hop cannot see.

This reproduces, on an independent published benchmark, the same finding the
mutation testing predicted: single-hop analysis structurally misses multi-hop
delegation, and `propagate` recovers it.

## Declared over-approximations (visible in precision)

Consistent with the evaluated-scope position, two limitations show up on the
safe cases and are reported rather than hidden:

- **Explicit Deny is not evaluated**, so a wildcard Allow shadowed by a Deny
  (fp1, fp2, fp3) is still flagged. These are false positives.
- **Conditions are not evaluated**, so a condition-restricted wildcard (fp5) is
  flagged. A resource-constrained wildcard (fp4) is handled correctly, because
  the resource scope is checked.

One further over-approximation is specific to this adapter: a wildcard
`iam:PassRole` (`Resource: "*"`) is modelled as a delegation edge to every role,
without checking whether the target role's trust policy admits the service the
role would be passed to. The escalation verdict on the entry principal is still
correct, because a passable over-privileged role exists in the account, but the
specific witness role cited may not be the intended one. This is noted so the
witness path is read with that caveat.

## How to run

The benchmark is static: only the deployed configuration is analysed, so no
exploitation or role assumption is required.

```bash
# 1. deploy IAM Vulnerable (IAM-only, no cost; both privesc-paths and
#    tool-testing modules deploy by default, non-free modules stay commented out)
git clone https://github.com/BishopFox/iam-vulnerable
cd iam-vulnerable
terraform init
terraform apply            # uses your default AWS profile

# 2. extract the delegation graph from the deployed state
cd /path/to/agent-pathtriage/evaluation/benchmark
python3 extract_iam.py --tfdir /path/to/iam-vulnerable --json iam_graph.json

# 3. score single-hop vs multi-hop against the independent ground truth
python3 run_benchmark.py --graph iam_graph.json --truth ground_truth.json

# 4. tear down
cd /path/to/iam-vulnerable && terraform destroy
```

`run_benchmark.py` prints recall and precision for each mode, the principals
recovered only by `propagate`, and writes `benchmark_results.json`. If any
ground-truth name is not found in the graph, it is listed so the mismatch is
visible rather than silently lowering recall.

## Files

- `extract_iam.py` — generic-IAM adapter (users, roles, managed policies,
  attachments, wildcard PassRole, trust chains) emitting the shared graph format
- `run_benchmark.py` — scores `check` and `propagate` against ground truth
- `ground_truth.json` — independent ground truth (escalating entries + safe cases)

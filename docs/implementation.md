# Implementation

What the README used to carry inline. The front page is for someone arriving
from the paper; this is for someone about to run or change the tool.

## Two steps, if you want the intermediate state

```bash
# 1. Terraform source to the shape `terraform show -json` produces
python3 evaluation/benchmark/tf_to_state.py --tfdir path/to/terraform --json state.json

# 2. Findings: reached resources, the chain to each, and the risk split
python3 agentpathtriage/report.py --state state.json --json findings.json
```

`report.py` separates what a linter would also find from what only delegation
creates, names the roles that one service trusts without any narrowing
condition, and sets aside admin grade principals, which gain nothing by
chaining.

Against a live account, `reach.py` and `extract_graph.py` also accept
`--tfdir` and read `terraform show -json` directly.

## In CI

An exit code is not enough for a team that already has findings, so `scan`
takes a baseline and writes SARIF.

```bash
agentpathtriage scan infra/ --write-baseline .agentpathtriage-baseline.json
agentpathtriage scan infra/ --baseline .agentpathtriage-baseline.json
agentpathtriage scan infra/ --sarif agentpathtriage.sarif --sarif-base "$PWD"
```

A baseline hides only a finding it already names, so a newly reachable
resource is never suppressed by an older entry. Suppressed findings are
counted in the output and written into the SARIF marked suppressed rather than
dropped, and a baseline written by a different build of the analyser says so.
Section 8b of `model/formal-spec.md` states the rules and the tests hold both
directions.

```yaml
- uses: sarahda/agent-pathtriage@main   # pin a tag once one is cut
  with:
    path: infra
    baseline: .agentpathtriage-baseline.json
```

Six rules, `APT001` to `APT006`. The four that are escalations fail a run.
Unconditional shared trust and a plain wildcard grant are reported and do not,
because neither is a claim of this work.

## What the graph models

| Edge | Meaning |
|---|---|
| `act` | the identity is authorised for the resource, with the matched scope |
| `delegate` | the identity can be obtained: `iam:PassRole`, `sts:AssumeRole` where the target's trust policy admits the caller, a trust policy, rewriting the target's permissions, minting its credentials, joining a group, rewriting a role's trust, or taking over a resource that already runs as it |
| `trusts` | a service principal is trusted by a role, and whether a condition narrows who may use it |
| `assume` | an agent executes under a role |
| `handoff` | an agent is configured, or permitted, to call another agent |

The hand off edge is declared in the agent platform's own configuration rather
than in IAM, which is what makes this graph agentic rather than a relabelled
IAM graph. It is recovered three ways and each edge records which: a variable
holding another agent's ARN, a variable addressed at an agent whose value is a
module input, and a role permitted to invoke another agent.

Two conditions on a delegate edge are worth stating, because both were missing
once and each produced findings that could not happen:

- `sts:AssumeRole` needs the trust side as well as the identity side. A role
  is assumable only by a principal its trust policy names, so a policy
  allowing `sts:AssumeRole` on `*` reaches nothing whose trust names only a
  service. An edge that fails this is kept and marked with the reason.
- A takeover edge needs an action AWS authorises against that kind of
  resource, with its dependent actions satisfied, and whose request can set
  what the deputy runs or the identity it runs as. All three come from the
  Service Authorization Reference and botocore's API models rather than from a
  list written here.

## Layout

| Path | Contents |
|---|---|
| `agentpathtriage/` | the tool: `iam_eval`, `extract_graph`, `reach`, `report`, `gap`, `managed_policies` |
| `agentpathtriage/data/` | dated snapshots: AWS managed policy documents, the derived takeover action table |
| `evaluation/benchmark/` | `tf_to_state`, corpus scans, benchmark scoring, baselines, topology |
| `model/` | delegation model, the escalation predicate, and what `act` checks |
| `infra/` | reproducible lab environments (`aws/`, `foundry/`) |
| `attacks/` | per primitive proof of concept scripts and reproduction logs |
| `baseline/` | comparison against tools written outside this project |
| `validation/pr/` | disclosure packages |
| `docs/` | results, evidence, related work, IAM permission mapping |
| `tests/` | regression tests, one per defect found |
| `slides/`, `report/` | presentation figures and the technical report |

## Modules

| Module | Does |
|---|---|
| `iam_eval` | one policy evaluation core: explicit Deny wins, `NotAction` and `NotResource`, IAM glob matching on actions and ARNs, and partial condition evaluation that drops a statement whose condition can never be satisfied |
| `extract_graph` | builds the graph from state shaped JSON, including service principal nodes, shared unnarrowed trust, identity control, resource takeover and agent hand offs |
| `reach` | computes `auth`, `eff` and the difference, with the deputy condition: holding `iam:PassRole` is not an escalation unless the caller can also make something run as the role |
| `managed_policies` | loads AWS managed policy documents from a dated snapshot, so a figure can be cited against a known policy version |
| `report` | the findings, ranked by reach gained |
| `gap` | config to role gap over a corpus, scored per agent runtime |
| `tf_to_state` | Terraform source to state shaped JSON, including `aws_iam_policy_document` data sources |

## Building the corpus

Public Terraform found through GitHub code search queries, listed in
`evaluation/benchmark/collect_corpus_v3.sh`. The search API serves at most
1000 results per query, so a query above that ceiling is split into disjoint
file size buckets and each bucket is paged separately.

```bash
bash evaluation/benchmark/verify_sparse_equiv.sh      # check the clone mode first
bash evaluation/benchmark/collect_corpus_v3.sh        # discover, then clone
python3 evaluation/benchmark/corpus_population.py --corpus corpus_tier2
```

Every cloned repository is accounted for, so coverage is readable rather than
asserted:

| Step | Count |
|---|---|
| non-fork repositories cloned | 1647 |
| no Terraform at all | 4 |
| Terraform but no agent runtime | 1461 |
| with an agent runtime | 182 |
| template directories in those | 331 |
| excluded by the filter | 84 |
| fork copies of a template already counted | 27 |
| **final templates** | **220** |
| agent runtimes in them | 242 |

The 84 exclusions are 83 `hashicorp/terraform-provider-aws` test fixtures
under `internal/service/bedrockagentcore/testdata` and this repository's own
`infra`, cloned because it matches the same search signals.

A second corpus covers the same declaration outside Terraform, using
`queries_cfn_cdk.txt`. What a code search reports as `total_count` is an
estimate: on the run of 2026-11-02 seven of the ten queries returned more
repository rows when paged than their reported total.

A unit is counted once. A template byte identical to another is one unit, and
a file under a test fixture, a snapshot directory or a vendored benchmark copy
is not a deployment. Both are reported with the units named rather than
dropped silently, because without that the denominator counts one awslabs
sample eight times.

## What the corpus shows

```bash
python3 evaluation/benchmark/topology.py   --corpus corpus_tier2 --json topology.json
python3 evaluation/benchmark/shared_role.py --topology topology.json --corpus corpus_tier2
python3 agentpathtriage/gap.py             --corpus corpus_tier2 --json gap.json
python3 evaluation/benchmark/adjudicate_gaps.py --gap gap.json --corpus corpus_tier2
```

| Measurement | Value |
|---|---|
| templates with two or more agents | 18 of 220 (8.2%) |
| of those, all agents run as one execution role | 5 of 18 (27.8%) |
| templates with a declared hand-off | 6 of 220 (2.7%) |
| agents wired to one named callee whose role still permits calling any | 3 |
| runtimes whose role grants more than the configuration wires | 17 of 242 (7.0%) |

The 5 templates whose agents share one execution role are all of the templates
in the corpus that do so, not a sample of them. That is a census of the 18
multi-agent templates the corpus contains, and says nothing about how common
the pattern is in deployments, which this method cannot measure.

Adjudicating the 17 runtimes whose role is wider than their wiring gives 13
single-agent, 2 narrow, 2 shared-role and 0 cross-agent. The two shared-role
rows are two runtimes of one template, which the shared-role scan finds
independently, so that is one case reached by two routes rather than two cases.
No cross-agent escalation arises from this route at 242 runtimes, which is the
same answer the 157-runtime corpus gave.

## Reproducing each figure

```bash
# third party benchmark, BishopFox IAM-Vulnerable
git clone --depth 1 https://github.com/BishopFox/iam-vulnerable.git
python3 evaluation/benchmark/tf_to_state.py --tfdir iam-vulnerable --json iv_state.json
python3 agentpathtriage/reach.py --state iv_state.json --json iv_reach.json
python3 evaluation/benchmark/score_benchmark.py --state iv_state.json --reach iv_reach.json

# third party scenario, CloudGoat agentcore_identity_confusion
git clone --depth 1 https://github.com/RhinoSecurityLabs/cloudgoat.git
python3 evaluation/benchmark/tf_to_state.py \
  --tfdir cloudgoat/cloudgoat/scenarios/aws/agentcore_identity_confusion/terraform \
  --json cg_state.json
python3 agentpathtriage/report.py --state cg_state.json

# an independent tool on the same input
python3 evaluation/benchmark/baseline_cloudsplaining.py --state iv_state.json --reach iv_reach.json

# the corpus
python3 evaluation/benchmark/topology.py    --corpus corpus_tier2 --json topology.json
python3 evaluation/benchmark/shared_role.py --topology topology.json --corpus corpus_tier2
python3 agentpathtriage/gap.py              --corpus corpus_tier2 --json gap.json
python3 evaluation/benchmark/adjudicate_gaps.py --gap gap.json --corpus corpus_tier2

# escalation census, with and without managed policy expansion
python3 evaluation/benchmark/corpus_takeover_census.py \
    --corpus corpus_tier2 --topology evaluation/benchmark/topology_tier2.json \
    --snapshot agentpathtriage/data/aws_managed_policies.json \
    --json evaluation/benchmark/corpus_takeover_census.json

# the population outside Terraform, and the chain denominator
python3 evaluation/benchmark/cfn_cdk_runtimes.py --corpus corpus_cfn \
    --json evaluation/benchmark/cfn_cdk_cfn_corpus.json
python3 evaluation/benchmark/chain_cfn.py --corpus corpus_cfn \
    --scan evaluation/benchmark/cfn_cdk_cfn_corpus.json \
    --json evaluation/benchmark/chain_cfn_corpus.json

# all of it, diffed against the committed artifacts
agentpathtriage verify --full
```

## Testing

```bash
python3 -m pytest tests -q
```

One test per defect found, each exercising the real pipeline rather than a
hand built graph. Reintroducing any of those defects fails at least one test,
which was checked by reverting each fix in turn rather than assumed.

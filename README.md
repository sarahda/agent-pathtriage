# AgentPathTriage

Artifact for *Replacing the Agent: measuring cross-agent takeover
preconditions in public infrastructure as code*.

AgentPathTriage finds cross-agent IAM privilege escalation on managed agentic
cloud platforms. It reads infrastructure as code, so a deployment can be
analysed before it exists. No cloud account, no deployment, no credentials in
the analysis path.

## The question

A managed agent platform lets one agent hand work to another. The receiving
agent runs under its own execution identity, so the action is taken with that
identity's permissions and not the caller's. Two agents can each hold a role
that passes a least privilege review and the deployment can still escalate,
because the hand off composes them. Nothing in either policy is wrong on its
own, which is why analysis that evaluates one identity at a time does not see
it.

```
auth(p) = what the deployment authorised p to reach
eff(p)  = what p reaches once every delegation edge is followed
Esc(p) <=> eff(p) \ auth(p) != empty
```

A principal holding a broad permission but handing off to nobody has
`eff = auth`, so it is not escalated here. That case is ordinary single
identity over permissioning and is reported separately, as is self escalation.

## What the paper reports

Public infrastructure as code, collected by GitHub code search and analysed
without deploying anything.

| | |
|---|---|
| Terraform projects analysed | 220, in 3519 files |
| with two or more agents | 20 by runtime, 18 by declaration block |
| all agents under one execution role | 7 of 20 |
| units the chain analysis covered | 27 (18 Terraform, 9 CloudFormation) |
| **complete cross-agent escalations** | **0** |
| one sided 95 percent upper bound | 10.5 percent |
| takeover candidates blocked on `iam:PassRole` alone | 26 across 16 projects |
| of those, one agent reaching another | 10 |
| Foundry template directories surveyed | 16450 from 360 repositories |
| connection `authType` values that store a credential | 183 of 516, about 35 percent |

Zero is the result, not a failure to look. The engine recovers the delegation
paths in BishopFox IAM-Vulnerable that a single identity check misses, and the
26 blocked candidates are deployments one permission short of the path.

Every figure above is defined once in `paper/numbers.tex`, and each definition
names the artifact it was read from.

## Reproducing the numbers

```bash
pip install -e .
python3 evaluation/reproduce.py --fast
python3 evaluation/verify_paper_numbers.py \
    --numbers paper/numbers.tex --bench evaluation/benchmark
python3 evaluation/independent_checks.py
```

`verify_paper_numbers.py` re-derives every macro in the paper from the artifact
its definition names, and fails on any disagreement. `independent_checks.py` is
a second pass that re-derives several published figures from the raw source
with deliberately different patterns.

## Scanning your own Terraform

```bash
agentpathtriage scan /path/to/your/terraform
```

Exit codes, so it can sit in CI: `0` nothing found, `1` findings, `2` the run
itself failed. A missing directory is `2`, never `1`. `agentpathtriage doctor`
says what is missing, and proves the install works by scanning a template
rather than only listing imports. `action.yml` runs the same check in GitHub
Actions and reports to the code scanning tab.

## The live demonstration

`attacks/passrole_runtime_takeover/` builds the takeover in a real AWS account:
nine cells, each a question, each writing its outcome to `runs/`.

```bash
cd attacks/passrole_runtime_takeover
python3 lab.py setup
python3 exploit.py --all
python3 persistence.py
python3 lab.py teardown && python3 teardown_verify.py
```

Every resource name carries a random suffix per run. The planted agent reports
the name of its credential source, never a value. `teardown_verify.py` reads
the account back afterwards and separates a resource still deleting from one
left behind. Read `RESPONSIBLE_USE.md` first: this creates billable resources
in whatever account your credentials point at.

## Layout

| | |
|---|---|
| `agentpathtriage/` | the analysis: state extraction, reachability, reporting |
| `evaluation/` | the benchmark, the stored artifacts, and the two verifiers |
| `paper/` | the paper source, including `numbers.tex` |
| `attacks/` | the live demonstrations |
| `infra/` | the lab infrastructure as code, AWS and Foundry |
| `model/` | what the predicate checks, and what it skips |
| `docs/implementation.md` | for someone about to run or change the tool |
| `validation/` | how the external reports were prepared |

## Disclosure

Findings that named a specific public deployment were reported to their owners
before publication, through the channel each repository's own policy asks for.
The reports and the recipients are not in this repository: each owner was asked
whether they would agree to be named, and the paper records the outcome
instead. `validation/` carries the generator and the template, with
`channels.example.json` in place of the routing file.

## License

Code under the license in `LICENSE`. The corpora are third party and are not
redistributed here. `evaluation/benchmark/` holds the collection queries and
the derived artifacts, not the cloned repositories.

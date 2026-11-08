# Check your Terraform for cross-agent IAM escalation. One command, no AWS account.

Reads source only. Nothing is deployed, nothing is called, no credentials are
used. If you have a Terraform directory that defines a Bedrock AgentCore
runtime, this tells you which resources each agent can reach through another
agent's identity.

## Run it

```bash
git clone https://github.com/sarahda/agent-pathtriage agentpathtriage && cd agentpathtriage
pip install -e .
agentpathtriage scan /path/to/your/terraform
```

If something is missing, `agentpathtriage doctor` says what, and it proves the
install works by scanning a template rather than only listing imports.

Exit codes, so it can sit in CI: `0` nothing found, `1` findings, `2` the run
itself failed. A missing directory is `2`, never `1`.

## Reading the output

```
principals analysed:              4
reachable only through delegation: 1   <- what this tool adds
risk visible in the principal's own policy: 2   (a policy linter finds these too)
admin-grade, chain adds nothing:   0
escalation of unmeasurable extent: 1
```

- **reachable only through delegation** is the number to look at. These are
  resources no single policy grants the principal. They become reachable
  because one agent can act through another agent's identity.
- **risk visible in the principal's own policy** is separated out on purpose. A
  linter already finds those, and they are not this tool's contribution.
- **admin-grade** principals are set aside. They already hold everything, so
  chaining adds nothing and counting them would inflate the number.
- **unmeasurable extent** means the escalation reaches a role carrying an AWS
  managed policy. The grant is real, but the document lives at AWS rather than
  in your configuration, so the size of the reach cannot be measured here.

Each finding names the resource reached, the identity it is reached through,
the action, and why the hop is possible:

```
  gained only through delegation:
      arn:aws:bedrock:...:knowledge-base/kb-prod
         via agentcore_agent_runtime_role using bedrock:Retrieve
         sandy ==iam:PassRole[pattern]==> agentcore_agent_runtime_role
         possible because: passrole + bedrock-agentcore:CreateCodeInterpreter
                           on bedrock-agentcore.amazonaws.com (trust not narrowed)
```

## Want the fix as well

```bash
agentpathtriage repair /path/to/your/terraform
```

It proposes the narrowest change that removes each finding, applies it to a
copy of your configuration, and re-runs the analysis to check that it did. A
proposal that fails that check is not shown as a fix. Two classes are reported
without one, because the fix is structural rather than a policy edit: two
agents under one execution role, and a wildcard invoke grant with no declared
target to narrow to.

## What it will get wrong

Stated up front, because a tool's limits decide whether its output is worth
your time.

- Permission boundaries, SCPs and session policies are not read. A reach your
  organisation blocks at a higher level is still reported.
- Conditions are decided in one direction only. A condition that can never hold
  removes the grant; anything undecidable is treated as permitting and marked.
- Terraform modules are analysed per directory. A hand-off that crosses a
  module boundary is reported with an unresolved far end rather than dropped.
- A runtime created with `for_each` is counted once, as a declaration.
- Resource-based policies are not yet composed with identity policies.

Direction of error: it reports too much rather than too little. Everything it
skips can only narrow access, so a finding is a candidate to check, not a
confirmed break.

## Checking our numbers rather than yours

```bash
agentpathtriage verify
```

Re-derives every number in the paper from the committed code and diffs it
against the committed artifacts. `--full` also re-walks the corpus.

## The question

Two things would help, and either one is useful on its own:

1. Does the output describe something real in your environment, or is it noise?
2. If it is real, is it something you would raise as an issue, or something you
   already knew and accepted?

A one-line answer is enough. A "this is noise because X" is as useful as a
confirmation, and more useful than no reply.

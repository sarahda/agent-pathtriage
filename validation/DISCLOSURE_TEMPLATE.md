# Disclosure template (F1)

One file per report, copied into `validation/external.md` as a row. Fill every
field or do not send: a blank field is where a false report comes from.

## Pre-send gate

Do not send unless all five are true. This exists because the AgentCore
weather-agent sample looked over-granted under a configuration-only reading and
was not: its code reaches AWS through SDK wrapper classes and a generic
`use_aws` tool, so no grant there can be called unnecessary. One wrong report
and the next one is not read.

- [ ] `codereq.py` returns `verdict_possible: true` for this template
- [ ] the specific action being reported appears in `over_granted`
- [ ] the finding is `cross-agent` or `shared-role` under `adjudicate_gaps.py`,
      not `single-agent` or `narrow`
- [ ] the three reproduction commands run clean on a fresh clone
- [ ] the limitations section below is included unedited

If the finding is `single-agent`, it may still be worth sending, but the
condition goes in the first paragraph: it becomes real only when two instances
of the module land in one account. Do not describe it as a present escalation.

## Message

> Subject: Cross-agent IAM reach in <repo> Terraform (static analysis, no deployment)
>
> Hello,
>
> I am a masters student at UNSW working on IAM privilege escalation in managed
> agent platforms. While measuring a corpus of public Bedrock AgentCore
> Terraform, <repo> came up, and I wanted to send it to you before it appears in
> anything I publish.
>
> **What I found.** <one sentence: which identity reaches which resource through
> which other identity>
>
> **Why it composes.** <one sentence: shared execution role, or unnarrowed
> service trust plus the ability to start that service>
>
> **How to check it yourself,** without deploying anything or using any AWS
> credentials:
>
> ```
> python3 evaluation/benchmark/tf_to_state.py --tfdir <path> --json state.json
> python3 agentpathtriage/report.py --state state.json
> ```
>
> **What I may have wrong.** <paste the limitations list>. In particular I read
> configuration, not a deployed account, so an organisation-level control I
> cannot see may already block this.
>
> **Timing.** I intend to submit a paper on 16 December 2026. I would rather
> describe this with your repository named and your response included than
> anonymised. Would you be willing to agree to publication before then? If not,
> I will anonymise it and record only that it was reported and acknowledged.
>
> Happy to be told this is a non-issue, and why. That is a useful answer too.

## Limitations

This list is sent unedited with every report. It is what the analysis may have
wrong, written for the person receiving it rather than for a reviewer.

- Configuration is read, not a deployed account. An organisation policy, a
  permissions boundary or a session policy that is not in the Terraform may
  already block this.
- Conditions are decided in one direction only. An allow that depends on a
  condition which cannot be decided statically is reported as an allow and
  marked conditional, so a condition that never holds in your account still
  shows up here.
- The contents of AWS managed policies are not in the configuration. An
  escalation into a role that carries one is reported, but how far it reaches
  is not measured.
- Modules are analysed per directory. A hand-off that crosses a module
  boundary is reported with an unresolved far end.
- A runtime created by `for_each` or `count` is counted once, as a
  declaration rather than as instances.
- Resource-based policies are not composed with identity policies.
- A shared execution role is a property of the template as written. If you
  deploy the agents into separate accounts, or override the role per agent at
  apply time, it does not apply to your deployment.
- No deployment, no API call and no credential was used to produce this. If
  that means the finding does not match your account, that is the most likely
  reason and I would like to hear it.

## Record

| Field | Value |
|---|---|
| Repository | |
| Finding class | cross-agent / shared-role / single-agent |
| `codereq` verdict | |
| Channel | SECURITY.md / AWS security / GitHub issue |
| Sent | |
| Acknowledged | |
| Ticket or issue id | |
| Response | |
| Publication agreed before 12/16 | yes / no / no reply |
| Evidence grade reached | E1 fixed / E2 ran it / E3 acknowledged / none |

## What counts as which grade

- **E1 fixed.** A commit, a release note or a reply saying it was changed.
- **E2 ran it.** Someone who is not me ran the tool and judged the output.
- **E3 acknowledged.** A ticket number or a human reply confirming receipt.

E3 is the floor and is achievable by sending. E1 and E2 are not controllable and
are not planned for: if they arrive they go in the paper, if they do not the
external evidence rests on the third-party benchmarks, which is stated plainly
rather than hidden.

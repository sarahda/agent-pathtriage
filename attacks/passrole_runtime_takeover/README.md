# CP: Cross-agent runtime takeover (UpdateAgentRuntime / PassRole)

## Summary

A principal holding only the AWS managed policy `BedrockAgentCoreFullAccess`
calls `UpdateAgentRuntime` on an agent runtime it does not own, replacing both
what that runtime executes and the role it executes as. The caller never
touches the victim's role, its policies or its code repository.

```
attacker (BedrockAgentCoreFullAccess)
    --bedrock-agentcore:UpdateAgentRuntime--> victim runtime
    --iam:PassRole--------------------------> victim execution role
```

`UpdateAgentRuntime` marks both `agentRuntimeArtifact` and `roleArn` as
required, and carries `environmentVariables` beside them, so one call sets the
code, the identity it runs as and what the code is aimed at. `iam:PassRole` is
the only one of them the managed policy withholds, and it withholds it only
for roles whose name does not match `*BedrockAgentCore*`.

## Why it matters

Single-principal analysis clears this. The attacker's policy names no resource
belonging to the victim: it names `bedrock-agentcore:*` on AgentCore resources
in general. The victim's execution role is correctly scoped and grants the
attacker nothing. Neither policy is wrong on its own. The reach appears only
when the takeover edge is followed, and whether it is open is decided by a
string match on the victim role's name.

This is the path that 26 blocked takeover candidates in the Tier 2 corpus stop
on, all of them on `iam:PassRole`.

## Cells

| Cell | What moves | Expected |
|---|---|---|
| `positive-control` | operator makes the same call | allowed |
| `control` | attacker holds the managed policy only | denied on `iam:PassRole` |
| `treatment` | one inline `iam:PassRole` statement is added | allowed, definition replaced |
| `recheck` | that statement is removed again | denied on `iam:PassRole` |
| `name-condition` | victim role is named `*BedrockAgentCore*` | allowed, no added permission |
| `gain` | nothing; who can read the canary | only the victim role |
| `effect` | the planted code is run | the canary comes back in the response |
| `falsification` | attacker is given the canary directly | allowed, but nothing to gain |

## Running it

Requires credentials for a researcher-controlled account and the lab
resources in place.

```bash
python3 lab.py setup              # three runtimes, three roles, one attacker principal
./upload-code.sh                  # build the two agent zips, put them in the bucket
python3 exploit.py --all          # all cells, with propagation waits included
python3 exploit.py --cell control # or one at a time
python3 lab.py teardown           # remove everything setup made
```

Records land in `runs/run-<cell>-<timestamp>.json`, one per call, holding the
request, the response or the full exception, the victim's state read back from
AgentCore before and after, the attacker's policies at that moment, and AWS's
policy simulator verdict for the same question.

## Three things the script refuses to do

Each because an earlier experiment in this project did it and produced a
result that looked right and was not.

1. It does not trust intent. The role a runtime runs as is read back from
   AgentCore before and after every call.
2. It does not treat every `AccessDenied` as a block. The denial has to name
   the action the cell is about, or the run is recorded as inconclusive.
3. It does not give up on the first assume failure. IAM trust policies and
   policy attachments take time to propagate, so the assume is retried and the
   attacker's effective policy is recorded with every cell.

## Results

See `FINDINGS-2026-11-03.md`.

> This lab is intentionally insecure and runs only in a researcher-controlled
> account. See `../../RESPONSIBLE_USE.md`.

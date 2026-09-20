# E1 Recall

## Detection recall (extract + check on the lab config)
recall = 5 / 5 — the tool recovers, from configuration alone, the cross-agent
resource access that each documented oracle path targets (ECR, memory, code
interpreter, runtime). RoleB (scoped) is correctly Esc = False (no false positive).

## Reproduction (end-to-end exploit, separate axis)
2 / 5 reproduced live-API: P1 (ECR pull), P2 (memory exfil+poison).
P3 (interpreter), P4 (runtime) mapped but not yet exploited (Wk2).

## Honest note
Detection recall of 5/5 reflects that the lab role is intentionally
over-privileged, so all four agentic resource types are present and recovered.
The tool's real discrimination is shown by (a) not flagging the scoped RoleB, and
(b) the baseline comparison and E2 prevalence on third-party configs.

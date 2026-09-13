# `act` — What It Checks (v0)

`act(ρ, r)` answers one question: **can identity `ρ` reach resource `r`?**
This note fixes what `act` looks at and what it skips for now, so the scope
doesn't quietly grow during term.

## What `act` looks at

**AWS**
- Identity policies: Effect, Action (including wildcards like `*` or `svc:*`), and Resource (including `*` and `arn:.../*`).
- Resource policies where they exist (e.g. an ECR repository policy).
- The trust policy on an `assume` edge (who is allowed to assume `ρ`).
- An explicit `Deny` always wins over an `Allow`.

**Azure / Foundry**
- Entra role assignments (what the role allows, and at what scope).
- Whether the action runs as the *user's* identity (OBO) or the *agent's own* managed identity.

## What `act` skips for now (v0)

| Skipped | Why | What it means for results |
|---|---|---|
| IAM condition keys (source IP, tags, MFA, ...) | These depend on the request at runtime, not on the static config | We might flag a reach that a condition would actually block |
| Permission boundaries / org-level SCP denies | These need org context we don't read yet | We might flag a reach that an org deny would block |
| Tag-based (ABAC) rules decided at request time | Dynamic, not in the static config | Same as above |
| Whether the resource currently exists | We read config, not live state | A flagged path is *possible*, not *confirmed live* |

## Which way the errors go

- `act` **flags too much, never too little.** Everything it skips (conditions, boundaries, org denies) can only *tighten* access. So a path we flag might turn out to be blocked at runtime — but we won't *miss* a path the policy actually grants.
- Because of this, a flagged path is a **candidate**, not a confirmed break. The E1 check (does the tool recover the real, documented attack paths?) is what confirms the model finds true ones. A flagged path that a skipped condition would block is a known limitation we report, not a hidden bug.
- **v1 plan:** start reading condition keys and boundaries so we flag fewer false paths, and state the guarantees more formally.

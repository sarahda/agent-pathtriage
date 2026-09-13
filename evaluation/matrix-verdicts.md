# Matrix Cells & When to Call Something "Blocked" (v0)

Every cell in the primitive × provider matrix gets exactly one of four labels.
This note fixes what each label means, so "blocked" isn't decided differently
each time.

## Four labels

| Label | Meaning |
|---|---|
| **exploitable** | We reproduced the attack end-to-end in the lab, under a normal (default or common) setup. |
| **blocked** | The platform stops it by design — no setup can turn it on. |
| **blocked-by-default** | Off by default, but a specific setting turns it on (we name the setting). |
| **unresolved** | Not reproduced yet, and not shown to be blocked either. Still pending — this is *not* a claim. |

## To label a cell "blocked", all three must hold

Otherwise it stays **unresolved** (we just haven't done it), not **blocked**.

1. **We can name what stops it.** Point to the exact platform control (for example: Entra refuses to chain one service principal's token into another; the delegation step hands over a *reduced* identity instead of the full one).
2. **No setting turns it back on.** If some customer setting re-enables it, the cell is **blocked-by-default**, not **blocked**.
3. **We have proof, not just silence.** Back it with something positive — a denied API call with its reason, vendor docs describing the control, or an observed identity hand-down — not "we tried and nothing happened."

## The asymmetry result

The strongest cross-provider finding is a pair: the same primitive is **exploitable**
on one platform and **blocked** on the other, with the blocking mechanism named
(check #1). Template: PathTriage's finding that Azure blocks service-principal-to-
service-principal token chaining.

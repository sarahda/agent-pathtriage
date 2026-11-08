# Formal Model v1: Cross-Agent Delegation Graph

This version replaces the v0 draft. v0 described a model the code did not implement:
it named a `propagate` edge that was never built, it assumed one way of obtaining
another identity when the implementation found eight, and it stated that conditions
were not read at all when the evaluator now decides some of them. Every defect found
in the 2026-10-14 review was a gap of that kind, between what the model claimed and
what the code did, so this version is written against the code as it stands and
carries a trace table that names the function and the test for each clause.

Where the model and the implementation still differ, the difference is stated here
rather than left for a reader to discover.

## 1. Graph

A deployed agent system is a directed graph `G = (V, E)` with typed nodes:

```
V = P ∪ A ∪ S ∪ R
```

| Set | Contents |
|---|---|
| `P` | principals: IAM users, roles, groups |
| `A` | agents: AgentCore runtimes, classic Bedrock agents, Foundry connected agents |
| `S` | service principals: `bedrock-agentcore.amazonaws.com`, `lambda.amazonaws.com`, and so on |
| `R` | resources: memory stores, knowledge bases, code interpreters, gateways, buckets, and other cloud resources |

Service principals are nodes rather than annotations because two roles trusting the
same service with nothing narrowing the trust are interchangeable to anything that
can make that service act. That is the published AgentCore cross-agent mechanism, and
it is not expressible if the trust is only an attribute of a role.

Five edge relations:

| Edge | Meaning |
|---|---|
| `act(ρ, r)` | identity `ρ` is authorised for resource `r` under provider policy evaluation, with the scope of the pattern that matched |
| `delegate(x, ρ)` | `x` can obtain identity `ρ` |
| `trusts(s, ρ)` | service principal `s` is trusted by role `ρ`, with a flag for whether a condition narrows who may use it |
| `assume(a, ρ)` | agent `a` executes under role `ρ` |
| `handoff(a, b)` | agent `a` is configured, or permitted, to call agent `b` |

`handoff` is the edge that makes this graph agentic rather than a relabelled IAM
graph: it is declared in the agent platform's own configuration, not in IAM, so no
IAM analysis can recover it. Each `handoff` edge records how it was found, and the
three grades are not interchangeable:

| Evidence | Meaning |
|---|---|
| `declared_resolved` | a variable on `a` holds `b`'s ARN, and `b` is in this configuration |
| `declared_unresolved` | a variable on `a` is addressed at an agent whose value comes from outside this directory. The near end is certain, the far end is not. |
| `permitted` | `a`'s execution role may invoke `b`, with no declaration that it does |

The gap between `declared_resolved` and `permitted` is the measurable form of the
thesis claim: an agent configured to call one named agent while permitted to call any
agent in the account is a confused deputy waiting for an input that names a different
target.

## 2. `act`: instantiated, not assumed

`act` is decided by one policy evaluator shared by every caller, so the agentic path
and the generic IAM path cannot drift apart. It implements:

- explicit `Deny` beats `Allow`, decided per request rather than per statement
- `NotAction` and `NotResource`
- IAM glob matching on both actions and ARNs, case insensitive
- partial condition evaluation, defined in section 6

An unconditional `Deny` is final. A conditional `Deny` is reported but does not erase
the `Allow`, because a condition that may not hold at runtime cannot be relied on to
block.

## 3. Obtaining an identity

v0 assumed delegation meant `iam:PassRole` or `sts:AssumeRole`. The implementation
recognises eight ways to obtain another identity, and the distinction matters because
three of them need no further ability while one needs a great deal.

| Mechanism | Actions | Further ability needed |
|---|---|---|
| assume | `sts:AssumeRole`, or a trust policy naming the caller | none |
| pass a role to a service | `iam:PassRole` | yes, see the deputy condition |
| rewrite the target's permissions | `iam:PutRolePolicy`, `iam:AttachRolePolicy`, and the user and group forms | none |
| rewrite a managed policy | `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion` | none |
| mint the target's credentials | `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile` | none |
| join a group | `iam:AddUserToGroup` | none |
| rewrite a role's trust | `iam:UpdateAssumeRolePolicy` | none |
| take over a resource that already runs as the role | service Write actions whose verb mutates, plus remote execution namespaces | none |

The last row is the one a pure IAM graph misses. Seizing a Lambda function or an SSM
managed instance that already runs as a role gives the attacker that role's reach
without ever being handed the role.

### The deputy condition

Holding `iam:PassRole` is not an escalation. Passing a role to a service the caller
cannot start reaches nothing. The edge is enabled only when:

```
enabled(x --PassRole--> ρ)  ⟺  ∃ s ∈ S :  trusts(s, ρ)
                                        ∧ ¬scoped(trusts(s, ρ))
                                        ∧ can_run(x, s)
```

where `can_run(x, s)` holds when `x` is allowed any Write-level action in service `s`,
decided by the same evaluator so an explicit `Deny` still removes it, and `scoped`
means the trust statement carries a condition key that narrows who may assume:
`aws:SourceArn`, `aws:SourceAccount`, `sts:ExternalId`, `aws:PrincipalArn` or
`aws:PrincipalOrgID`. Any other condition key leaves the trust unscoped, because it
does not restrict the caller.

### Hops compose, and each one is its own caller

A path of two hops is enabled hop by hop, each against the statements of that
hop's SOURCE. That is not an approximation: IAM evaluates one request against
one principal, so the `iam:PassRole` and the service action on a single call
are checked against the same caller. A principal holding `PassRole` cannot
borrow a different role's ability to start the service, because assuming that
role makes the role the caller, and then the role's `PassRole` is what counts.

So no fixpoint is needed over enablement, and adding one would report paths
the provider refuses. The pair of tests below pins both directions: a helper
that can start the service but cannot pass the target composes to nothing, and
a helper that can do both composes to a reachable witness.

A role whose trust policy names a principal directly is assumable by that
principal with no `sts:AssumeRole` in the principal's own policy, and that is
modelled: the trust policy alone grants it.

The Write-level action set is derived from the offline AWS Service Authorization
Reference rather than written by hand. A hand-written table was the single largest
source of hidden tuning in the earlier implementation: removing the benchmark's own
actions from it dropped recall from 11/11 to 1/11, which showed the table had been
fitted to the benchmark rather than to AWS.

### Invoking an agent

The verb that invokes an agent depends on the platform the target runs on, and
probing one verb against both platforms is wrong in both directions:

| Target | Invoke actions |
|---|---|
| `aws_bedrockagentcore_agent_runtime` | `bedrock-agentcore:InvokeAgentRuntime` |
| `aws_bedrockagent_agent` | `bedrock:InvokeAgent`, `bedrock-agent-runtime:InvokeAgent` |

### Delegated invocation, the second cross-agent mechanism

Everything above obtains an identity. A caller ends up holding, or acting as,
the role assignments of some other principal, and its reach grows because the
set it borrowed is larger. Microsoft Foundry carries a second mechanism that
grows reach without any role set being borrowed, and the two have to be kept
apart because a rule written for the first is silent on the second.

In this one the caller keeps its own identity. A role assignment authorises it
to invoke another agent, the callee runs under its own identity, and the callee
acts on the caller's behalf. Nothing is passed to the caller and no assignment
changes, yet the caller can now cause every action the callee may take. Written
against the predicate:

```
invokes(a, b)  iff  the caller holds an invoke-capable role assignment at a
                    scope containing b, AND a connection carries the call and
                    executes as the caller's own agent identity
eff(a)         =    own(a) ∪ ⋃ { eff(b) | invokes(a, b) }
Esc(a)         iff  eff(a) \ auth(a) ≠ ∅
```

Four clauses decide whether an edge exists, and each one is a way the rule
would otherwise be wrong.

**Both halves are required.** A role assignment alone is a permission nobody
exercises, and a connection alone is a path nobody may take. The lab shows the
difference directly: with the assignment withdrawn and the connection left in
place the call fails, and the edge disappears with it.

**The identity class decides whether this rule applies at all.** A connection
that executes as a managed identity is a different mechanism, because the
callee then acts as itself and not on the caller's behalf, so this rule reports
nothing rather than reporting a finding it did not measure. A connection that
executes as the signed-in user is not a cross-agent finding either, since the
reach gained is the user's and was already theirs. An auth type that matches
neither class is recorded as undecidable, and an edge carries the basis on
which its class was decided.

**An edge is not an escalation.** The predicate is about reach, so an edge whose
callee holds nothing adds nothing, and an edge into a resource the caller can
already touch adds nothing either. Both are measured rather than argued: the
falsification cell gives the caller a role on the same service the callee
reaches, keeps the trace otherwise identical, and the edge survives while `Esc`
turns false.

**Reach is keyed by resource, not by role assignment.** A callee can reach a
resource through a tool connection holding its own credential, with no role
assignment anywhere, and that reach is real. Keying on assignments misses it,
and keying on the pair of role and scope makes the falsification cell
incomparable with the treatment cell. A connection is credited only to the
agent whose definition refers to it. A connection to another agent is a hop and
not reach: a chain of agents that ends in nothing is not an escalation.

Scope containment is path containment over segments, not a string prefix. A
grant higher up the tree authorises a call further down it, a grant on a sibling
does not, and a resource group whose name begins with another's name contains
nothing of it.

Invoke capability is read from the role definition rather than from a list of
role names, and an exclusion in a definition beats a wildcard grant in the same
definition. Names alone are consulted only when no definition is in hand, and
then a role the documentation marks as unable to interact with agents is not
assumed able to.

## 4. The three sets

```
auth(p) = { r ∈ R | act(ρ_p, r) }
```

the resources `p` reaches under its own identity, including any identity it inherits
by group membership, and including the control plane when `p` is admin grade.

```
D(p) = { ρ | p reaches ρ by one or more ENABLED delegate edges }
eff(p) = auth(p) ∪ ⋃_{ρ ∈ D(p)} { r ∈ R | act(ρ, r) }
```

`D(p)` is computed by breadth-first search over enabled edges only, with a visited
set, so a delegation cycle terminates. `eff(p) ⊇ auth(p)` by construction.

## 5. Escalation, and what is not escalation

```
Esc(p)  ⟺  eff(p) \ auth(p) ≠ ∅
```

Each `r ∈ eff(p) \ auth(p)` is a witness: a resource reached only through delegation.
A witness carries the identity it was reached through, the action that reached it, and
the chain of delegate edges with the reason each one is enabled.

Three classes of finding are kept apart, because merging them would let the delegation
number be inflated by findings that are not about delegation:

| Class | Definition | Why separate |
|---|---|---|
| delegation escalation | `Esc(p)` with the witness reached through another identity | the contribution |
| self escalation | `p` can rewrite its own permissions, so its reach grows without any second identity being obtained | real, but a single identity widening itself |
| own-policy risk | `p` already holds a wildcard-scoped grant and delegates to nobody, so `eff = auth` | a policy linter finds this, and it is not this project's contribution |

A principal that holds a broad permission but hands off to nobody is not escalated
under this predicate. Admin-grade principals are set aside entirely: they already hold
everything, so chaining adds nothing and reporting them would pad the count.

An escalation into a role carrying an AWS managed policy is reported as real but
unmeasurable, because the policy document lives at AWS rather than in the
configuration. Reporting it as a non-finding would be a silent miss, and reporting a
reach size for it would be invented.

## 6. Soundness direction

The analysis over-approximates in one direction, deliberately and uniformly: it may
report a reach that something outside the configuration would block, and it does not
report a reach the configuration grants. Everything it does not read can only tighten
access.

Not read, and therefore possibly over-reported:

| Not read | Effect |
|---|---|
| permission boundaries, SCPs, session policies | a reach an org-level deny would block is still reported |
| resource-based policies, except where passed in | the same |
| whether the resource currently exists | a reported path is possible, not confirmed live |
| AWS managed policy documents | reach into them is reported as unmeasurable |

Conditions are the exception to "not read", and the rule is narrower than either v0
statement. A condition is decided only when it can be decided soundly in one
direction:

```
condition_satisfiable(c) ∈ { SATISFIABLE, UNSATISFIABLE, UNKNOWN }
```

`UNSATISFIABLE` means the condition can never hold, so the statement is dead and a
dead statement is not a grant. `UNKNOWN` is treated as satisfiable, and the resulting
allow is tagged conditional so a reader can tell it apart from a clean allow. Only two
families are decided: date comparisons against the current time, and identity-key
equality when the principal is known. Everything else is `UNKNOWN`.

The benchmark pins both directions with one pair. IAM-Vulnerable's `fn3` grants on
`DateGreaterThan aws:TokenIssueTime 2020-01-01`, which always holds now and is
exploitable. Its `fp5` grants on `DateLessThan` the same date, which can never hold
and is the benchmark author's designed false positive. Treating conditions as absent
fails `fp5`; treating them as blocking fails `fn3`.

### Configuration recovery assumptions

The analysis reads Terraform source rather than a deployed account, so some values
must be recovered rather than observed. Each recovery is an assumption, and each is
over-approximating in the same direction:

| Construct | Assumption | Why it is sound in one direction |
|---|---|---|
| `count` and `for_each` index | the subscript is dropped and the single declaration is used | the declaration is what the policy attaches to; not collapsing it orphaned every policy on a counted role, which under-reported |
| a `locals` ternary with one resolvable branch | the resolvable branch is taken | the other branch names something outside this directory, whose permissions no directory-scoped analysis could have checked |
| a ternary with two resolvable branches | left undecided | the condition decides, and it cannot be read. Guessing would invent a value |
| a resolved value still holding `${var.x}` | accepted | the same unresolved input appears in the ARN synthesised for the resource, so the two still match |
| a module boundary | the far end of a hand-off is reported `declared_unresolved` | the near end is certain and the far end is honestly unknown |
| the corpus path | exclusion matches the path INSIDE the corpus | the substrings name repositories in the corpus, not places on disk. Matching the whole path made the result depend on where the corpus was addressed from |
| a runtime created by `for_each` | counted once, as a declaration rather than as instances | prevalence is reported over declarations, and is stated that way |

## 7. What a resource-scope gap is, and is not

A resource-scope gap means a runtime's execution role holds an AgentCore action on a
resource pattern wider than the resources wired to that runtime. It is a
precondition, not a finding. Reporting the count as a prevalence of cross-agent
escalation would overstate it, so adjudication is a separate pass with four verdicts:

| Verdict | Meaning |
|---|---|
| `cross-agent` | the pattern covers a resource another agent in the same template owns |
| `shared-role` | two agents run under one role, so each already holds the other's reach and no hand-off has to be guessed |
| `single-agent` | the template declares one agent. Latent at module level: real once two instances of the module land in one account, which a per-directory analysis cannot observe |
| `narrow` | the wider pattern does not in fact cover another agent's resource |

On the tier-2 corpus all ten resource-scope gaps adjudicate to `single-agent` or
`narrow`. The deployable cases come from the shared-role pass instead, where 3 of 14
multi-agent templates run two agents under one execution role.

## 7b. Required permissions, and the direction of error there

`codereq` answers a different question from the rest of the engine: not what an
identity MAY do but what its code appears to NEED. The difference is the only
honest basis for calling a grant unnecessary, and that claim is the one that
leaves the building, in a report to a repository owner.

So the error direction is inverted on purpose. Everywhere else the engine
over-approximates REACH. Here it over-approximates NEED: it would rather call a
grant necessary than call a necessary grant unnecessary.

The verdict is withheld, rather than guessed, in three cases:

| Withheld when | Why |
|---|---|
| an unresolved SDK wrapper touches the namespace | a wrapper method is not an API name. `CodeInterpreter.invoke` issues `InvokeCodeInterpreter`, not `Invoke`, so asserting the action would make every other grant in that namespace look unused |
| a generic AWS tool is present | a tool such as `use_aws` lets the model issue any call at run time, so the source cannot bound what is needed |
| the code did not parse, or there is none | unreadable code is not evidence that nothing is needed |

Measured on the AgentCore weather-agent sample, which reaches AWS through
`BrowserClient`, `CodeInterpreter`, `MemoryClient` and a `use_aws` tool: a
reading that looks only for boto3 finds no requirement and reports all three of
the template's AgentCore grants as unnecessary. All three reports would be
wrong. With the rules above the verdict is withheld, which is the correct
answer.

The other direction is reported and costs nothing: the weather-agent code calls
`bedrock-agentcore:CreateEvent`, which the configuration never grants. A
configuration-only reading can be wrong in both directions, and saying so is
part of stating the limits honestly.

**Known dependence.** The wrapper and generic-tool lists are hand written. A
wrapper outside the list leaves its namespace resolved when it should not be,
which produces a false unnecessary-grant verdict. There is no authoritative
source for SDK wrapper names to derive this from, so it cannot be removed, only
stated and compensated for by a human reading the code before any report is
sent.

## 7c. Repair, and what makes one minimal

A finding without a fix leaves the work where it found it. The repair pass
proposes the narrowest edit that removes an escalation, applies it to a copy of
the configuration, and RE-RUNS the analysis. A repair that has not been
re-analysed is a suggestion, and a suggestion is what a linter already gives.

Preference order, narrowest first:

  1. add a condition      the declared path keeps working. Narrowing a service
                          trust with `aws:SourceArn` is the published
                          cross-service confused-deputy fix, and the agent to
                          scope it to is the one the `assume` edge already
                          names
  2. narrow a resource    a pattern becomes the exact ARNs. Correct, but it can
                          remove access the deployment meant to have
  3. remove an action     last, and bluntest

A candidate is accepted only when the witness is gone AND no new escalation
appeared anywhere. A repair that fixes one principal by breaking another is not
a repair.

What the acceptance test does NOT catch, stated because a repair that is
validated here is still only validated inside the model:

  - an equivalent escalation along a path the analyser does not model, such as
    a condition that becomes satisfiable only after the repair
  - a repair that is minimal within the modelled scope but not once SCPs,
    permission boundaries or session policies are considered
  - a repair the live platform rejects for a reason outside the model

Two classes are reported without an automatic repair, because the fix is
structural rather than a policy edit:

  - two agents under one execution role. The fix is a role each, which this
    pass will not write.
  - an agent with no declared hand-off but a wildcard invoke grant. There is no
    declared target to narrow to.

Blast radius is judged positionally. `runtime/*` reaches every runtime;
`runtime/mcp/runtime-endpoint/*` reaches one. Treating a star anywhere as
"any" reported a role scoped to one agent as permitted to invoke any agent,
and it also made a correct repair look like it had failed.

## 8. Completeness

The model finds an escalation only if the mechanism that creates it is one of the
eight in section 3 and the edge that carries it survives configuration recovery.
Known incompleteness, stated rather than implied:

- a hand-off declared in container code rather than in Terraform is not seen, because
  only the deployment configuration is read
- a hand-off crossing a module boundary has an unresolved far end
- a resource-based policy not passed in is not composed with identity policies
- an escalation that depends on an AWS managed policy's contents is reported but its
  extent is not measured
- cross-account paths are not followed
- `codereq`'s withholding rules depend on a hand-written list of SDK wrappers
  and generic tools; a wrapper outside the list yields a false unnecessary-grant
  verdict

### The corpus bounds every prevalence number, and the collector bounds the corpus

Every count whose denominator is the corpus is a statement about the corpus, not about
deployed environments. Three separate limits stack, and each is a different kind of gap.

1. GitHub code search indexes a subset of public repositories and only their default
   branches. A template in a private repository, an unindexed repository, or a
   non-default branch cannot be collected at all.
2. The collector's eleven queries name specific AgentCore resource types and two
   `iam:PassRole` phrasings. A multi-agent template using none of those strings is not
   matched. The query list is in `collect_corpus_v3.sh` and is the honest statement of
   what the population is defined as.
3. The API serves at most 1000 results per query. `collect_corpus_v3.sh` pages to that
   ceiling and splits a query above it into disjoint file-size buckets, so the recovered
   set is the union of the buckets rather than the first page. The earlier collector did
   not page, and `.query_stats.tsv` records `total_count` against the pages actually
   fetched so the shortfall for any query is readable rather than assumed.

Limit 3 is a defect and is fixed. Limits 1 and 2 are properties of the method and remain,
so a corpus-derived count is reported as a count within the collected corpus, and a
complete sweep of an identified subpopulation is called a census of that subpopulation
only, never of deployments.

A fourth limit is the snapshot. Each repository is cloned at depth 1, so the corpus holds
one commit per repository, taken when that repository was cloned. The 351 repositories the
unpaginated collector found were cloned on 2026-09-29 and the 1296 added by the paginated
collector on 2026-10-15, so the corpus is two snapshots rather than one. This affects the
distribution of last-commit dates, which is read off those pinned commits. It does not
affect any count derived from file contents, because each count reads the commit that is
actually present. The two dates are not reconciled by re-cloning the older 351: that set
contains the third-party benchmark fixtures (BishopFox/iam-vulnerable,
RhinoSecurityLabs/cloudgoat) whose pinned checkouts are what the recall, precision and
route counts were measured against, and moving them would invalidate those numbers to fix
a limitation that only touches one table.

## 8b. A finding's identity, and what a baseline is allowed to hide

Sections 1 to 8 say what an escalation is. They do not say what a *finding* is, and
two features need that: suppressing findings a reviewer has already triaged, and
emitting findings in a format an interface can display. Both were added for CI use
rather than for any claim in this paper, and neither may weaken the predicate.

A result row is per principal and carries several classes at once, so it is not a
finding. A finding is one item from this partition, and the partition is total over
what the engine computes:

| rule | the fact it asserts | fails a run |
|---|---|---|
| APT001 delegation-escalation | `a ∈ eff(p) \ auth(p)`, witnessed by a chain | yes |
| APT002 self-escalation | `p` holds an action that rewrites `auth(p)` | yes |
| APT003 shared-execution-role | two or more agents name one execution role | yes |
| APT004 unquantified-escalation | `p` reaches a role carrying a policy whose document is not in the configuration | yes |
| APT005 interchangeable-roles | one service is trusted by several roles with nothing narrowing the grant | no |
| APT006 own-policy-risk | a wildcard-scoped grant inside `auth(p)` | no |

APT005 and APT006 do not fail a run. Neither is a claim of this work and neither is
on its own a defect, so gating on them would make the exit code mean something other
than "this configuration permits an escalation". APT003 does fail a run, and this is
a widening of the exit code from the version that preceded it: with a shared
execution role `eff = auth` for each agent, so the delegation predicate is correctly
false, and yet each agent holds everything the other holds. Section 5 already treats
that as a finding of its own class; the exit code now agrees with section 5.

**Identity.** A finding is named by a fingerprint over the facts that constitute it,
and deliberately not over the explanation of it. For APT001 that is the principal,
the resource reached and the action, and not the chain. Two chains reaching the same
resource with the same action assert the same fact about who can reach what, so they
are one finding. The parts are joined on a separator, because a concatenation makes
`("a", "bc")` and `("ab", "c")` the same name and silently merges two findings into
one.

**What suppression may hide.** A baseline records fingerprints and nothing else. It
may hide only a finding whose fingerprint it already contains, so a wider reach, a
new action or a new principal is never hidden by an entry made before it existed.
This is the property that matters and is tested in both directions: a baselined
finding stops failing the run, and a newly reachable resource still fails it.

Three further restrictions follow from treating suppression as dangerous rather than
convenient.

A baseline carries the hash of the analyser that wrote it. A fingerprint means what
it meant under the build that produced it, and under a different build the same name
may denote a different fact. The mismatch is reported rather than enforced: refusing
to run would be worse, because a tool that fails on an upgrade gets removed from CI.
This is the same rule as the corpus cache in section 8, arrived at the same way: a
stored judgement that outlives the code which made it reports a number nobody can
account for.

Nothing is suppressed silently. Suppressed findings are counted in the text output
and written into the SARIF carrying an explicit suppression, because a baseline
records that somebody decided to live with a finding, which is not the same as the
finding not existing. A baseline entry matching nothing in the current scan is also
reported: it is either a finding that was fixed, or evidence that the fingerprints
have moved underneath the baseline.

Only the failing rules are recorded. Baselining a note would be recording that a
policy linter has an opinion.

**Location.** A finding is placed at the line of the resource block that declares its
subject, found by the comment-blanking pass the parser already uses, so a resource
header inside a comment is not a location and a line number is a line in the real
file. Where the subject cannot be placed, the finding is still emitted against the
directory's first file and marked as not located, so that a line number is never read
as evidence. This is presentation and carries no claim.

## 9. Trace: clause, code, test

Every clause above has an implementation and at least one test that fails if the
clause is violated. The tests run the real pipeline, from Terraform source through
`tf_to_state`, `extract_graph` and `reach`, rather than a hand-built graph, because
the defects lived in parsing and graph construction rather than in the traversal.

| Clause | Code | Test |
|---|---|---|
| Deny beats Allow | `iam_eval.evaluate` | `test_explicit_deny_beats_allow` |
| conditional Deny does not erase the Allow | `iam_eval.evaluate` | `test_conditional_deny_does_not_erase_the_allow` |
| `NotAction` | `Statement.covers_action` | `test_not_action_is_honoured` |
| action and resource globs | `glob_match` | `test_action_and_resource_globs` |
| unscoped service trust | `trust_entries_from_policy` | `test_unconditioned_service_trust_is_distinguished_from_a_scoped_one`, `test_scoped_service_trust_blocks_the_deputy` |
| deputy condition | `reach.can_run_service`, `reach.enable_delegations` | `test_passrole_without_the_ability_to_run_the_service_is_not_an_escalation`, `test_prefix_passrole_and_shared_service_trust_find_the_escalation` |
| broad but non-delegating is not escalation | `reach.analyse` | `test_overprivileged_but_non_delegating_role_is_not_an_escalation` |
| resource takeover | `extract_graph.takeover_actions` | `test_taking_over_a_resource_that_runs_as_a_role_is_an_escalation` |
| a name that is an expression keys by the logical name and is recorded | `extract_graph.Index._key_name` | `test_an_agent_name_that_is_an_expression_does_not_stop_the_run` |
| rewrite another identity's policy | `CONTROL_ACTIONS` | `test_writing_a_policy_onto_another_identity_is_an_escalation` |
| rewrite a shared managed policy | `POLICY_CONTROL_ACTIONS` | `test_controlling_a_managed_policy_reaches_everyone_it_is_attached_to` |
| mint credentials | `BECOME_ACTIONS` | `test_minting_credentials_for_another_user_is_an_escalation` |
| join a group | `JOIN_ACTIONS` | `test_joining_a_group_is_an_escalation` |
| rewrite a role trust | `RETRUST_ACTIONS` | `test_rewriting_a_role_trust_is_an_escalation` |
| group membership in `auth` | `Index.statements` | `test_group_membership_counts_towards_a_user_reach` |
| self escalation is a separate class | `reach.SELF_ESCALATION_MARK` | `test_rewriting_your_own_permissions_is_self_escalation_not_delegation` |
| unmeasurable managed policy reported | `reach.analyse` | `test_unreadable_aws_managed_policy_is_reported_not_silently_dropped` |
| cycles terminate | `reach.reachable` | `test_delegation_cycle_terminates` |
| determinism | `reach.run`, `gap.tf_files` | `test_reach_is_deterministic`, `test_scan_is_independent_of_file_order`, `test_file_reads_are_sorted` |
| per-runtime scoring | `gap.scan_template` | `test_every_runtime_in_a_template_is_scored` |
| dead condition is not a grant | `condition_satisfiable` | `test_condition_that_can_never_hold_is_not_a_grant` |
| unknown condition is satisfiable and marked | `condition_satisfiable` | `test_unknown_condition_is_treated_as_satisfiable_and_marked` |
| policy forms are parsed | `tf_to_state` | `test_jsonencode_policies_are_parsed_not_left_opaque`, `test_heredoc_policies_are_parsed`, `test_policy_document_data_source_is_rendered` |
| account and region normalise | `DATA_NORMALISE` | `test_account_and_region_data_sources_normalise` |
| `count` index collapses | `tf_to_state.reference`, `INDEX_REF` | `test_indexed_role_reference_keeps_the_policy_attached`, `test_indexed_resource_reference_resolves_in_a_policy_resource`, `test_for_each_and_splat_indices_also_collapse` |
| invoke verb by platform | `extract_graph.invoke_actions_for` | `test_agentcore_wildcard_does_not_reach_a_classic_bedrock_agent`, `test_classic_invoke_verb_is_recognised` |
| an expression does not eat the next key | `Parser.expression_tail` | `test_expression_after_a_reference_does_not_corrupt_the_next_key`, `test_two_attributes_on_one_line_both_survive` |
| locals resolve | `tf_to_state.parse_locals` | `test_a_local_carrying_the_execution_role_resolves` |
| one resolvable branch is taken | `ternary_branches`, `pick_branch` | `test_a_nested_ternary_is_left_unresolved_rather_than_guessed`, `test_a_ternary_with_two_resolvable_branches_is_not_decided` |
| a resolved value may hold a module input | `pick_branch` | `test_a_resolved_branch_may_still_carry_a_module_input` |
| boto3 calls become actions | `codereq.Visitor` | `test_boto3_calls_become_actions` |
| an unused grant is reportable | `codereq.assess` | `test_a_grant_the_code_never_uses_is_reportable` |
| an SDK wrapper withholds its namespace | `SDK_WRAPPERS` | `test_sdk_wrapper_suppresses_the_verdict_for_its_namespace` |
| a generic AWS tool withholds everything | `GENERIC_AWS_TOOLS` | `test_a_generic_aws_tool_withholds_the_verdict_entirely` |
| unparseable code withholds the verdict | `codereq.assess` | `test_unparseable_code_withholds_the_verdict` |
| no code withholds the verdict | `codereq.code_files` | `test_no_code_withholds_the_verdict` |
| code needing what config omits is reported | `codereq.assess` | `test_code_needing_what_config_omits_is_reported` |
| a test file is not production code | `codereq.code_files` | `test_test_files_are_not_read_as_production_code` |
| exclusion judged inside the corpus | `gap.is_excluded` | `test_exclusion_is_judged_inside_the_corpus_not_on_the_whole_path` |
| the same corpus scores the same by either path | `gap.collect` | `test_scan_gives_the_same_answer_for_relative_and_absolute_corpus` |
| blast radius is positional | `resource_spans_many` | `test_a_wildcard_inside_one_named_resource_is_not_any` |
| hops compose, each against its own source | `reach.enable_delegations`, `reach.reachable` | `test_a_second_hop_does_not_lend_its_service_permission_backwards`, `test_a_hop_that_holds_both_does_compose` |
| a trust naming a principal is a delegation | `trust_entries_from_policy` | `test_a_trust_naming_a_user_directly_is_a_delegation` |
| a hand-off scoped to the declared target is exact | `extract_graph` scope | `test_a_handoff_scoped_to_the_declared_target_is_exact` |
| no findings exits 0 | `cli.cmd_scan` | `test_no_findings_exits_zero` |
| findings exit 1 | `cli.cmd_scan` | `test_findings_exit_one` |
| a failed run exits 2, never 1 | `cli.RunFailed` | `test_a_missing_directory_exits_two_not_one`, `test_a_directory_with_no_terraform_exits_two` |
| either path form scores the same | `cli` | `test_the_same_directory_scores_the_same_by_either_path` |
| json output parses | `cli.cmd_scan` | `test_json_format_is_parseable` |
| doctor proves the install by scanning | `cli.cmd_doctor` | `test_doctor_reports_ready` |
| the corpus is the union of every result page, not the first | `collect_corpus_v3.sh` harvest | `test_collector_shell_harness` |
| a re-measurement never reuses another run's cache | `reproduce.code_stamp`, `reproduce.read_stamp` | `test_an_empty_marker_is_not_accepted_as_a_stamp`, `test_a_missing_marker_is_not_accepted_as_a_stamp`, `test_a_marker_written_now_matches_the_current_stamp`, `test_the_stamp_changes_when_the_analyser_code_changes`, `test_the_stamp_changes_when_the_corpus_grows`, `test_the_stamp_is_stable_for_an_unchanged_corpus` |
| the surviving duplicate does not depend on cache order | `topology.load_rows`, `gap.load_rows` | `test_the_surviving_duplicate_does_not_depend_on_cache_order`, `test_the_survivor_is_the_alphabetically_first_path`, `test_templates_with_different_hashes_are_all_kept`, `test_the_hash_is_not_carried_into_the_output` |
| every corpus number in the README comes from an artifact | `README.md` results | `test_the_funnel_table_matches_the_corpus_artifact`, `test_the_runtime_count_matches_the_gap_artifact`, `test_the_prevalence_table_matches_the_artifacts`, `test_the_adjudication_split_matches_the_artifact`, `test_the_census_claim_names_the_whole_multi_agent_set` |
| the funnel accounts for every cloned repository | `corpus_population.report` | `test_the_funnel_adds_up` |
| the baseline evidence carries no real account identifier | `redact_baseline.py` | `test_no_real_aws_unique_identifier`, `test_no_operator_home_directory`, `test_no_real_account_id`, `test_the_redactor_has_nothing_left_to_do`, `test_the_redactor_is_idempotent` |
| configuration-declared use counts as use | `codereq.granted_actions` | `test_a_declared_handoff_counts_as_use_of_the_invoke_action`, `test_a_declared_handoff_keeps_invoke_out_of_over_granted`, `test_the_guard_does_not_hide_a_genuinely_unused_grant` |
| a variable name counts as a hand-off only when it names a callee | `handoff_code.names_a_callee` | `test_a_name_that_identifies_a_callee_counts`, `test_a_generic_runtime_address_does_not_count`, `test_a_credential_or_memory_handle_does_not_count`, `test_an_unrelated_variable_does_not_count`, `test_a_role_arn_is_not_an_agent`, `test_the_env_read_pattern_finds_every_spelling`, `test_a_repository_with_no_python_yields_no_verdict` |

| the finding classes partition what the engine computes | `findings.RULES`, `findings.FAILING` | `test_every_rule_has_a_level_and_only_failing_rules_are_errors`, `test_a_linter_visible_grant_does_not_fail_the_run` |
| two agents on one execution role is a finding that fails the run | `findings._shared_execution_roles` | `test_two_agents_on_one_role_is_a_finding_that_fails_the_run`, `test_an_agent_whose_role_did_not_resolve_is_not_grouped` |
| a finding's name is stable, and names the fact rather than the explanation | `findings.fingerprint`, `findings.collect` | `test_the_same_template_names_its_findings_the_same_way`, `test_a_fingerprint_cannot_be_spelled_two_ways`, `test_an_extra_reachable_resource_is_a_new_finding` |
| a baseline hides only what it already names | `findings.apply_baseline` | `test_a_baselined_finding_stops_failing_the_run`, `test_a_new_finding_still_fails_a_baselined_run`, `test_only_failing_rules_are_recorded_in_a_baseline` |
| nothing is suppressed silently | `cli._render_findings`, `sarif.build` | `test_suppressed_findings_are_counted_out_loud`, `test_a_baseline_entry_that_matches_nothing_is_reported`, `test_a_suppressed_finding_is_written_out_marked_suppressed` |
| a baseline carries the identity of the analyser that wrote it | `findings.analyser_stamp`, `findings.baseline_warning` | `test_the_analyser_stamp_changes_when_the_analyser_does`, `test_a_baseline_from_another_build_warns` |
| a baseline that cannot be read is a failed run, not a clean one | `cli.cmd_scan` | `test_a_missing_baseline_is_an_error_not_a_clean_scan`, `test_a_file_that_is_not_a_baseline_is_an_error` |
| what is printed is the list the exit code is derived from | `cli._render_findings` | `test_what_is_printed_and_what_is_exited_on_are_the_same_list` |
| a finding is placed at the line that declares its subject | `findings.resource_lines`, `findings.Locator` | `test_a_finding_points_at_the_line_that_declares_it`, `test_a_resource_header_inside_a_comment_is_not_a_resource`, `test_a_finding_that_cannot_be_placed_says_so` |
| the SARIF is one a code scanning tab can actually display | `sarif.build`, `sarif._uri` | `test_the_sarif_is_version_2_1_0_with_one_run`, `test_every_result_points_at_a_rule_that_exists`, `test_every_result_has_a_relative_location_inside_the_tree`, `test_every_result_carries_its_fingerprint`, `test_the_sarif_reports_the_shared_role_finding`, `test_a_clean_template_produces_an_empty_but_valid_sarif`, `test_the_sarif_version_is_the_package_version` |
| a result a code scanning tab would discard is flagged | `cli.cmd_scan` | `test_a_sarif_whose_results_cannot_be_placed_warns` |
| the published workflow calls flags the command line has | `action.yml` | `test_the_action_runs_the_command_the_readme_documents` |

| delegated invocation needs a grant and a carrier | `foundry_delegation.invoke_edges` | `test_treatment_reaches`, `test_control_role_revoked_is_blocked`, `test_edges_carry_the_facts_that_decided_them` |
| the identity class decides whether this rule applies | `foundry_delegation.auth_identity_class` | `test_negative_control_managed_identity_is_not_this_rule`, `test_user_delegated_auth_is_not_a_cross_agent_finding`, `test_unclassified_auth_type_is_undecidable_not_absent`, `test_auth_identity_class_records_its_basis`, `test_falls_back_to_the_configuration_identity_when_no_instance_identity` |
| an invocation edge is not an escalation | `foundry_delegation.analyse_delegation` | `test_falsification_caller_already_reaches_the_resource`, `test_a_callee_with_no_privilege_yields_no_escalation` |
| scope containment is over segments, not strings | `foundry_delegation.scope_contains` | `test_grant_higher_up_the_scope_still_authorises`, `test_grant_on_a_sibling_scope_does_not_authorise`, `test_resource_group_prefix_is_not_containment` |
| reach is keyed by resource, and an agent is a hop | `foundry_delegation._tool_reach`, `foundry_delegation._is_a2a` | `test_a_tool_connection_is_credited_only_to_the_agent_that_uses_it`, `test_the_a2a_connection_is_not_counted_as_reach`, `test_a_tool_without_a_resource_id_falls_back_to_its_target` |
| `eff` is the transitive closure and the path is named | `foundry_delegation._reach` | `test_two_hops_are_followed_and_the_path_is_named` |
| invoke capability comes from the definition, and exclusion beats wildcard | `foundry_delegation.role_invokes_agents` | `test_role_definition_beats_the_name_list`, `test_documented_owner_and_contributor_are_not_invoke_capable`, `test_exclusion_overrides_a_wildcard_grant`, `test_both_action_spellings_are_accepted`, `test_user_impersonation_is_not_an_invoke_action`, `test_unknown_custom_role_is_undecidable`, `test_against_the_role_definitions_captured_from_azure`, `test_the_impersonation_exclusion_is_the_only_agent_carve_out` |
| a missing fact is undecidable, not absent | `foundry_delegation.invoke_edges` | `test_callee_without_a_scope_is_undecidable`, `test_no_connection_recorded_is_undecidable` |

Reintroducing any clause's defect fails at least one of its tests. This was checked by
mutation rather than assumed: each fix was reverted in turn and the suite was re-run.

## 10. Divergence from v0

| v0 said | v1 says | Why |
|---|---|---|
| a `propagate` edge carries an execution context between agents | there is no `propagate`. Identity acquisition is `delegate`, agent-to-agent calling is `handoff` | one edge was carrying two different relations, and the implementation never built it |
| delegation means `iam:PassRole` or `sts:AssumeRole` | eight mechanisms, section 3 | the benchmark exercises all eight |
| condition keys are not evaluated | decided in one direction, section 6 | treating conditions as absent produced a false positive the benchmark author designed to catch exactly that |
| `eff` is reach through agent hops | `eff` is reach through obtained identities, and agent hops are one way to obtain one | the agent hop is not what grants the permission; the identity it runs as is |
| the worked instance is computed by `extract_poc.py` | `extract_graph.py` and `report.py` | the PoC was replaced |
| soundness is an open item | stated in section 6, with the recovery assumptions | it was the open item behind most of the defects found |

## 11. Open items for v2

- Foundry: the OBO versus managed-identity choice decides which identity an action
  runs under, and the two are modelled alike today. Either unify them or record the
  divergence as an explicit caveat, with the Foundry extractor measured the same way
  the AWS one is.
- Hand-offs declared in container code rather than in Terraform.
- Composing resource-based policies with identity policies.
- Cross-account delegation.

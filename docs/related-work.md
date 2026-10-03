# Related Work

Competitive landscape as of September 2026. Each entry states the prior work's contribution, what it leaves unaddressed, and how AgentPathTriage relates to it. Positioning notes and a suggested ordering for the report's related-work section follow the tables.

---

## A. Industry - AgentCore empirical findings (AWS)

These publicly documented AWS Bedrock AgentCore escalation paths are used as an **external oracle (E1)** for validating automated recovery from configuration. They are reproduced, not claimed as novel discovery.

| Work | Contribution | Not addressed | Relation to AgentPathTriage |
|---|---|---|---|
| Unit 42, *Agent God Mode* (2026) | Default starter-toolkit IAM role over-permissioning; a single agent can read/poison any other agent's memory and escalate account-wide | Single provider; hand-found; no model, automation, or prevalence | E1 oracle; recovered automatically from configuration and generalised cross-provider |
| Mitigant, *AgentCore or AgentSore* (Jun 2026) | Validates four escalation paths from the over-privileged execution role as a repeatable chain, with telemetry and countermeasures | As above | E1 oracle (four of the five documented paths) |
| Sonrai (Jul/Sep 2025) | Code Interpreter executes under the agent's role rather than the caller's, enabling escalation; proposes SCP-based fixes | Single component; no model | Reproduced and formalised as a substrate/tool primitive |
| BeyondTrust, *Mapping Every Privilege-Escalation Path in AgentCore* (2026) | Comprehensive map of AgentCore paths across Runtime, Harness, Code Interpreter, and Custom Browser | AWS only; hand-mapped; no formal model, automation, prevalence, or Foundry | Strongest E1 oracle; establishes that AWS empirical discovery is not this project's novelty |
| Cloud Security Alliance, *AgentCore Execution Boundary* research note (Mar 2026) | Analysis of the Code Interpreter privilege-escalation and execution-boundary problem | Analysis note; no tool, model, or measurement | Cited as corroboration of the empirical surface |
| Software Secured, *AWS Privilege Escalation: IAM, Service & AI-driven AgentCore Vectors* (2026) | Frames AgentCore escalation as "modern" vs "classic" IAM abuse; names `iam:PassRole`, `lambda:UpdateFunctionCode`, `CreateCodeInterpreter` as steps, and lists classic paths (`CreatePolicyVersion`, `AttachUserPolicy`, `UpdateAssumeRolePolicy`) - the same classic paths catalogued in PathTriage | Narrative/lab article; no formal model, automated extraction, cross-provider analysis, or prevalence | Directly bridges PathTriage's classic paths to AgentCore's agent paths in prose; AgentPathTriage formalises and automates that bridge and measures its prevalence. Cite to differentiate |

## B. Academic - LLM-agent and multi-agent privilege escalation

Framework-level work; not grounded in cloud IAM evaluation.

| Work | Contribution | Not addressed | Relation to AgentPathTriage |
|---|---|---|---|
| Ji et al., *SEAgent* (arXiv 2601.11893, Jan 2026) | Formal model of LLM-agent systems; identifies multi-agent confused-deputy escalation; MAC/ABAC runtime defence over an information-flow graph | Framework-level (AutoGen/AIOS); no cloud-identity semantics; not static analysis of deployed configuration; runtime rather than static | Cloud-IAM-grounded; static analysis of deployed configuration; cross-provider; prevalence measurement |
| *Security Considerations for Multi-Agent Systems* (arXiv 2603.09002) | Threat taxonomy including cross-agent delegation privilege escalation | Taxonomy only; no formal cloud model, tool, or measurement | Concrete cloud instantiation with a tool and prevalence measurement |
| *A Framework for Formalizing LLM Agent Security* (arXiv 2603.19469) | Formal confused-deputy predicate over user/agent/resource relations | Abstract relation left uninstantiated; no mapping to real IAM evaluation; no tool | Instantiates the predicate against real AWS/Entra policy evaluation, with a tool |
| Embrace The Red, *Cross-Agent Privilege Escalation* (2025) | Agent-rewrites-agent-config escalation loop in developer coding agents | Local developer tooling; prompt-injection-driven; not managed cloud IAM | Managed cloud IAM; prompt injection treated only as a trigger |
| **SoK: When Safe Agents Fail Together** (arXiv 2609.00595, JHU/NTU, Sep 2026) | Systematization of 197 works; A-I-R framework with the end-to-end execution path as the unit of analysis; names interface **"authority transfer and action"**, risk **"transitive authorization failure"**, and attack path **"delegation and authority escalation"**; audits 44 benchmarks | A synthesis, not an artefact; finds direct evidence for control-plane / authority attacks is limited, and that the field lacks matched single-principal baselines, comparable metrics, and provenance graphs | **The field map this project is positioned inside.** Our work supplies the missing artefact for the authority-transfer cell: real-cloud reproduction, a single-hop-vs-multi-hop counterfactual, external-ground-truth metrics, and a delegation provenance graph. Adopt its five-part defense contract for RQ5 |
| Trust propagation and structural containment in Multi-Agent LLM pipelines (arXiv 2609.17648, Sep 2026) | Low-privilege agent influencing a higher-privilege one; structural containment | Abstract pipelines; not cloud IAM execution identity; no real-platform reproduction | Concurrent; ours is real IAM execution-identity change on managed platforms |
| The Stochastic Deputy (arXiv 2609.14780, Sep 2026) | Confused-deputy via tenant-id passed into tool calls; structural tenant isolation | Tool-call / tenant-selection layer, not STS/Entra execution roles | Concurrent confused-deputy work at the tool layer; ours is at the cloud IAM layer |

## C. Academic - cloud IAM privilege-escalation formalisation & detection

The closest formalisation precedents; cited prominently and differentiated.

| Work | Contribution | Not addressed | Relation to AgentPathTriage |
|---|---|---|---|
| **TAC** (arXiv 2304.14540, v8, Mar 2026) | First hybrid IAM PE detector (AWS); formalises permission *propagation* as permission flows over a Permission Flow Graph with fixed-point analysis; 219 templates from 14k+ operations; whitebox and greybox | Static human/service IAM only; no agent nodes, invocation edges, or inter-agent credential propagation; single provider; cannot express agent-platform primitives (shared memory, substrate reuse) | Extends graph-based formalisation to the **agent-delegation layer** (agent/tool nodes, `invoke`/`propagate` edges), instantiates it for agent platforms, and adds a second provider (Entra). Positioned as an extension of TAC, not as a first graph formalisation of IAM PE |
| **NEO** (arXiv 2605.15569) | Agentic program analysis (LLM + CodeQL) for microservice privilege escalation; 24 zero-days; 81% precision / 85% recall on ground truth over 25 applications | Microservice **code** analysis, not IAM configuration; not agent-platform IAM; not cross-provider | Operates on cloud IAM **configuration** rather than code; targets managed agent platforms; measures prevalence over deployment templates. Also a reference point for evaluation rigour |
| **Overlaying Governance** (arXiv 2606.03518, Huawei, Jun 2026) | Compositional authorization overlay for agentic delegation/scope on ReBAC (OpenFGA/Zanzibar); authorization graph `G=(V,E)`, recursive delegation, soundness proofs, synthetic benchmarks | A governance framework over ReBAC, not real cloud IAM; no reproduction on Bedrock/Foundry, no automated extraction from deployed config, no prevalence. Confirms delegation-graph formalisation is now occupied, so our novelty is not there |
| **Capability Gates Are Not Authorization / ScopeGate** (arXiv 2606.28679, Jun 2026) | Audits LangChain/LlamaIndex/Stripe Toolkit for missing per-call authorization; reproduces a confused-deputy payout; proposes ScopeGate, a fail-closed runtime gate; measures deployment-tier ASR (3.2x) | Framework and tool-call layer (e.g. Stripe refund), not cloud IAM (STS/Entra roles); a runtime defense, not a cloud-config attack surface. A defense we can validate against our attacks (RQ5), not a competitor at the IAM layer |
| **Authorization Propagation in MAS** (arXiv 2605.05440, 2026) | Identity governance as infrastructure for authorization propagation across agents | Infrastructure/identity-governance framing; no real-platform reproduction, no prevalence | Real-platform reproduction and prevalence, at the cloud IAM layer |
| **On the Effectiveness of Kernel-Level Evidence for Agent Security** (arXiv 2609.28915, UGA + AWS, Sep 2026) | Argues application-telemetry detection is insufficient for agent security and that kernel-level evidence is needed | Host/kernel evidence layer; not IAM authority-transfer at the control plane | Our detection is control-plane (CloudTrail); we position it as the sufficient layer for the authority-transfer class and mark where kernel evidence is additionally required |

## D. Prior work (author)

| Work | Contribution | Not addressed | Relation to AgentPathTriage |
|---|---|---|---|
| PathTriage (COMP9301) | IAM attack-path discovery and exploitability ranking (AWS + Azure; 16 paths → 5 primitives) | Static human/service IAM; no agent invocation edges or runtime credential propagation | Extended to the agent-delegation layer; the lab harness is reused for infrastructure only, while the delegation-edge semantics are new |

## E. Proposed defenses - validation targets for RQ5

A wave of 2026 work proposes defenses for cross-agent delegation, but each is evaluated on abstract frameworks or toy systems, not on real managed cloud platforms. Holding a reproduced attack catalogue, RQ5 measures which of these actually close which primitives on live Bedrock/Foundry, scored against the SoK five-part defense contract (path protected / observed / when intervened / trusted components / recovery). New defense papers become additional test targets rather than competitors.

| Work | Proposed defense | Not validated on | RQ5 use |
|---|---|---|---|
| SEAgent (arXiv 2601.11893) | MAC/ABAC runtime enforcement over an information-flow graph | Real cloud IAM; managed platforms | Apply its policy model to our labs; measure closure per primitive |
| CAPMAS (arXiv 2609.06500) | Capability-based delegation of privileges across agents | Real cloud IAM; Bedrock/Foundry | Test whether capability scoping closes CP-1/CP-2/CP-4 |
| Bounded Agents (arXiv 2608.15888) | Per-request dynamic re-evaluation of static session permissions | Real managed platforms | Test against the PassRole/AssumeRole two-hop and delegation chains |
| AgentFlow (arXiv 2608.22868) | Flow-centric policy language for agent systems | Real cloud IAM | Express our primitives as flows; measure enforceable coverage |
| Delegation Without Trust (arXiv 2609.00267) | Runtime governance for identity/authorization across sub-agents | Real cloud IAM reproduction | Runtime-governance closure vs static control-plane closure |
| ScopeGate (arXiv 2606.28679) | Fail-closed per-call authorization gate | Cloud IAM (tool-call layer only) | Validate as a mitigation against reproduced attacks |

---

## Positioning

1. **Industry AgentCore findings (Group A) serve as the external oracle (E1), not as novelty.** The contribution over this line of work is automated recovery from configuration, cross-provider generalisation, and quantitative measurement - not the discovery of individual AWS paths.
2. **The formalisation is positioned as an extension of TAC** to the agent-delegation layer, instantiated against real IAM evaluation and validated across two providers - not as a first graph-based formalisation of IAM privilege escalation.
3. **The novelty rests on three pillars:** (i) cross-provider coverage including Microsoft Foundry; (ii) prevalence measurement over public agent deployment templates (RQ4); and (iii) automated extraction of the delegation graph from deployed configuration (RQ3).
4. **Formalisation is occupied, so novelty sits elsewhere.** Delegation-as-graph and confused-deputy predicates now appear in TAC, Overlaying Governance (2606.03518), and 2603.19469. We therefore do not claim formalisation novelty; our formal model is an instantiation of these ideas against real provider IAM. The contribution is empirical.
5. **Defense validation (RQ5) is the strongest open lane.** The 2026 literature keeps *proposing* defenses (SEAgent, CAPMAS, Bounded Agents, AgentFlow, Delegation Without Trust, ScopeGate) but none validates them against reproduced cross-agent attacks on real managed platforms. Holding an attack catalogue, we measure which defenses actually close which primitives, scored against the SoK five-part defense contract. This makes the paper the empirical arbiter of the defense literature; each new defense paper is another test target, not a competitor (Group E).
6. **Position inside the SoK (2609.00595).** Use its A-I-R vocabulary: our work occupies interface "authority transfer and action", risk "transitive authorization failure", attack path "delegation and authority escalation". The SoK reports this cell is under-evidenced and that the field lacks (i) matched single-principal baselines, (ii) comparable metrics, (iii) provenance graphs, and (iv) real/open-system benchmarks. We supply all four for the IAM authority layer: `check` (single-hop) vs `propagate` (multi-hop) is the counterfactual; recall/precision on external ground truth (IAM Vulnerable, disclosures) are comparable metrics; the delegation graph plus witness path is a provenance graph; real Bedrock/Foundry plus template prevalence is the real-system evidence.
7. **Evaluation-rigour context:** TAC (219 templates) and NEO (24 zero-days) indicate the bar for a full conference paper; this project targets a workshop-scale contribution.

## Suggested ordering for the report's related-work section

Field map (SoK 2609.00595, locate our cell) → static IAM PE (TAC) → agent-level privilege escalation (SEAgent; arXiv 2603.19469; multi-agent considerations; Stochastic Deputy; Trust propagation) → agent-platform empirical findings (Unit 42; Mitigant; BeyondTrust; CSA) → proposed defenses we validate (SEAgent; CAPMAS; Bounded Agents; AgentFlow; Delegation Without Trust; ScopeGate) → the unoccupied cell this project targets (cloud-native × cross-provider × automated × prevalence × validated defense).

# Related Work

Competitive landscape as of September 2026. Each entry states the prior work's contribution, what it leaves unaddressed, and how AgentPathTriage relates to it. Positioning notes and a suggested ordering for the report's related-work section follow the tables.

---

## A. Industry — AgentCore empirical findings (AWS)

These publicly documented AWS Bedrock AgentCore escalation paths are used as an **external oracle (E1)** for validating automated recovery from configuration. They are reproduced, not claimed as novel discovery.

| Work | Contribution | Not addressed | Relation to AgentPathTriage |
|---|---|---|---|
| Unit 42, *Agent God Mode* (2026) | Default starter-toolkit IAM role over-permissioning; a single agent can read/poison any other agent's memory and escalate account-wide | Single provider; hand-found; no model, automation, or prevalence | E1 oracle; recovered automatically from configuration and generalised cross-provider |
| Mitigant, *AgentCore or AgentSore* (Jun 2026) | Validates four escalation paths from the over-privileged execution role as a repeatable chain, with telemetry and countermeasures | As above | E1 oracle (four of the five documented paths) |
| Sonrai (Jul/Sep 2025) | Code Interpreter executes under the agent's role rather than the caller's, enabling escalation; proposes SCP-based fixes | Single component; no model | Reproduced and formalised as a substrate/tool primitive |
| BeyondTrust, *Mapping Every Privilege-Escalation Path in AgentCore* (2026) | Comprehensive map of AgentCore paths across Runtime, Harness, Code Interpreter, and Custom Browser | AWS only; hand-mapped; no formal model, automation, prevalence, or Foundry | Strongest E1 oracle; establishes that AWS empirical discovery is not this project's novelty |
| Cloud Security Alliance, *AgentCore Execution Boundary* research note (Mar 2026) | Analysis of the Code Interpreter privilege-escalation and execution-boundary problem | Analysis note; no tool, model, or measurement | Cited as corroboration of the empirical surface |
| Software Secured, *AWS Privilege Escalation: IAM, Service & AI-driven AgentCore Vectors* (2026) | Frames AgentCore escalation as "modern" vs "classic" IAM abuse; names `iam:PassRole`, `lambda:UpdateFunctionCode`, `CreateCodeInterpreter` as steps, and lists classic paths (`CreatePolicyVersion`, `AttachUserPolicy`, `UpdateAssumeRolePolicy`) — the same classic paths catalogued in PathTriage | Narrative/lab article; no formal model, automated extraction, cross-provider analysis, or prevalence | Directly bridges PathTriage's classic paths to AgentCore's agent paths in prose; AgentPathTriage formalises and automates that bridge and measures its prevalence. Cite to differentiate |

## B. Academic — LLM-agent and multi-agent privilege escalation

Framework-level work; not grounded in cloud IAM evaluation.

| Work | Contribution | Not addressed | Relation to AgentPathTriage |
|---|---|---|---|
| Ji et al., *SEAgent* (arXiv 2601.11893, Jan 2026) | Formal model of LLM-agent systems; identifies multi-agent confused-deputy escalation; MAC/ABAC runtime defence over an information-flow graph | Framework-level (AutoGen/AIOS); no cloud-identity semantics; not static analysis of deployed configuration; runtime rather than static | Cloud-IAM-grounded; static analysis of deployed configuration; cross-provider; prevalence measurement |
| *Security Considerations for Multi-Agent Systems* (arXiv 2603.09002) | Threat taxonomy including cross-agent delegation privilege escalation | Taxonomy only; no formal cloud model, tool, or measurement | Concrete cloud instantiation with a tool and prevalence measurement |
| *A Framework for Formalizing LLM Agent Security* (arXiv 2603.19469) | Formal confused-deputy predicate over user/agent/resource relations | Abstract relation left uninstantiated; no mapping to real IAM evaluation; no tool | Instantiates the predicate against real AWS/Entra policy evaluation, with a tool |
| Embrace The Red, *Cross-Agent Privilege Escalation* (2025) | Agent-rewrites-agent-config escalation loop in developer coding agents | Local developer tooling; prompt-injection-driven; not managed cloud IAM | Managed cloud IAM; prompt injection treated only as a trigger |

## C. Academic — cloud IAM privilege-escalation formalisation & detection

The closest formalisation precedents; cited prominently and differentiated.

| Work | Contribution | Not addressed | Relation to AgentPathTriage |
|---|---|---|---|
| **TAC** (arXiv 2304.14540, v8, Mar 2026) | First hybrid IAM PE detector (AWS); formalises permission *propagation* as permission flows over a Permission Flow Graph with fixed-point analysis; 219 templates from 14k+ operations; whitebox and greybox | Static human/service IAM only; no agent nodes, invocation edges, or inter-agent credential propagation; single provider; cannot express agent-platform primitives (shared memory, substrate reuse) | Extends graph-based formalisation to the **agent-delegation layer** (agent/tool nodes, `invoke`/`propagate` edges), instantiates it for agent platforms, and adds a second provider (Entra). Positioned as an extension of TAC, not as a first graph formalisation of IAM PE |
| **NEO** (arXiv 2605.15569) | Agentic program analysis (LLM + CodeQL) for microservice privilege escalation; 24 zero-days; 81% precision / 85% recall on ground truth over 25 applications | Microservice **code** analysis, not IAM configuration; not agent-platform IAM; not cross-provider | Operates on cloud IAM **configuration** rather than code; targets managed agent platforms; measures prevalence over deployment templates. Also a reference point for evaluation rigour |

## D. Prior work (author)

| Work | Contribution | Not addressed | Relation to AgentPathTriage |
|---|---|---|---|
| PathTriage (COMP9301) | IAM attack-path discovery and exploitability ranking (AWS + Azure; 16 paths → 5 primitives) | Static human/service IAM; no agent invocation edges or runtime credential propagation | Extended to the agent-delegation layer; the lab harness is reused for infrastructure only, while the delegation-edge semantics are new |

---

## Positioning

1. **Industry AgentCore findings (Group A) serve as the external oracle (E1), not as novelty.** The contribution over this line of work is automated recovery from configuration, cross-provider generalisation, and quantitative measurement — not the discovery of individual AWS paths.
2. **The formalisation is positioned as an extension of TAC** to the agent-delegation layer, instantiated against real IAM evaluation and validated across two providers — not as a first graph-based formalisation of IAM privilege escalation.
3. **The novelty rests on three pillars:** (i) cross-provider coverage including Microsoft Foundry; (ii) prevalence measurement over public agent deployment templates (RQ4); and (iii) automated extraction of the delegation graph from deployed configuration (RQ3).
4. **Evaluation-rigour context:** TAC (219 permission-flow templates) and NEO (24 zero-days; 81/85 precision/recall) indicate the bar for a full conference paper; this project targets a workshop-scale contribution.

## Suggested ordering for the report's related-work section

Static IAM PE (TAC) → agent-level privilege escalation (SEAgent; arXiv 2603.19469; multi-agent considerations) → agent-platform empirical findings (Unit 42; Mitigant; BeyondTrust; CSA) → the unoccupied cell this project targets (cloud-native × cross-provider × automated × prevalence).

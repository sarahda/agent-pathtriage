# E2 — How We Collect the Public Config Sample (v0)

For the prevalence question (how often do public agent setups ship an exploitable
primitive?), we need a clear, fixed way to pick which public repos/templates go in.
This note fixes it before term so the sample isn't cherry-picked later.

## Where we look (S1 candidate sources)

- GitHub search for agent deployment configs: IaC (Terraform / CDK / CloudFormation)
  and agent definitions that set up Bedrock AgentCore or Microsoft Foundry agents.
- Starter templates, sample repos, and "getting started" projects that ship a
  ready-to-deploy agent + its IAM role / identity.
- Search terms to log (so the search is repeatable): e.g. `bedrock-agentcore`,
  `AgentCore runtime`, `agent execution role`, `foundry agent` + `bicep`/`terraform`.

*(This is the candidate list; the exact repos and counts are recorded when the search runs.)*

## What goes IN

- It defines at least one agent **and** the IAM role / identity that agent runs as
  (we need the role to judge reach).
- The config is complete enough to read the role's permissions from the files alone.
- It targets AWS Bedrock AgentCore or Microsoft Foundry.

## What stays OUT

- No IAM role / identity in the repo (nothing for `act` to read).
- Only app code, no deployment config (we can't see the permissions).
- Duplicates / forks of a repo already in the sample (count the original once).
- Toy snippets that don't actually deploy an agent.

## How we report it (so it's honest, not cherry-picked)

- Target size: **n ≥ 100** (stretch 150–200). If we can't reach 100, we report it as a
  smaller qualitative sample and say so — we don't pad it.
- Report: how many of the n show **at least one** primitive, and the spread across the
  five primitives (CP-1..CP-5).
- **False positives:** hand-check a random ~30 of the flagged ones and report how many
  the tool got wrong. This keeps the prevalence number honest.
- Every included repo is analysed **statically, from its published files only** — no
  live system is touched (see RESPONSIBLE_USE.md).

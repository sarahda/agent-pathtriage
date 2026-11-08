# E2 prevalence - S1 (vendor-official) pilot

Static scan of vendor-official reference IaC, to establish the S1 floor before the
Tier-2 community corpus. No deployment: `extract_static` (python-hcl2) reads raw
`.tf`. Run 2026-10-03.

## Corpus (S1 = vendor-official)

Shallow-cloned, public, vendor/official sources containing Terraform:

| Repo | tf templates | note |
|---|---|---|
| awslabs/amazon-bedrock-agentcore-samples | 15 | AWS Labs - AgentCore IaC + blueprints |
| aws-ia/terraform-aws-bedrock | 11 | AWS Integration & Automation module |
| aws-samples/aws-generative-ai-terraform-samples | 4 | AWS samples |
| azure-ai-foundry/foundry-samples | 32 | Microsoft Foundry samples |
| Azure/terraform-azurerm-avm-res-cognitiveservices-account | 10 | Azure Verified Module |
| Azure-Samples/AI-Gateway | 1 | Azure samples |
| **total** | **73** | 62 root modules + 11 submodules |

Unit of analysis = a Terraform directory (≥1 `.tf`), scored on its own files only.
Submodules under `modules/` are counted and flagged so the count is not inflated
silently. Bicep (317 files) and CloudFormation (78) in these repos are **out of
this pilot's scope** - the static scanner parses HCL only; the HCL→Bicep/CFN
extension is the Wk5 engineering item. S1 numbers below are the Terraform slice.

## Result

| Signal | S1 (n=73) |
|---|---|
| identity-side delegation (PassRole/AssumeRole) | **0 (0.0%)** |
| over-privilege, classic (`*`/`iam:*`/`sts:*` on `*`) | 0 (0.0%) |
| over-privilege, agentic (`bedrock-agentcore:*`/`bedrock:*`/`sagemaker:*` on `*`) | 0 (0.0%) |
| **chainable (delegation + over-privilege)** | **0 (0.0%)** |
| wildcard PassRole | 0 (0.0%) |
| parse errors (fail-closed) | 0 |

**Vendor-official reference Terraform is clean of the chainable pattern.** All 23
`sts:AssumeRole` occurrences in the corpus are **trust policies** - role
`assume_role_policy` blocks with a `Principal { Service = … }` (e.g.
`bedrock-agentcore.amazonaws.com`, `codebuild.amazonaws.com`), the legitimate way a
service assumes an execution role - not identity-side grants that let one principal
assume another. There are zero `iam:PassRole` grants. Permissions are scoped; no
admin or agentic service-wildcard sits on a wildcard resource.

This is a meaningful floor, not a null result: the escalation pattern this project
targets is **absent from the baselines AWS and Microsoft publish**. If it appears,
it appears in community / third-party IaC - which is exactly what the Tier-2 corpus
tests. S1 sets the reference point that Tier-2 is measured against.

## Why the first run's numbers were discarded (precision fix)

The initial scan reported 2 chainable (2.7%). Hand-verification killed both - they
were false positives, and the fix is logged here so the final numbers are trusted:

1. **Over-privilege FP.** The admin-action regex `"(\*|iam:\*|sts:\*|\*:\*)"`
   matched the `"*"` of a **`Resource": "*"`**, so any scoped action on a wildcard
   resource (e.g. `bedrock:ListFoundationModels` on `*`) was mislabelled
   over-privileged. Fixed: `"*"` is now admin only in **Action** position;
   service-wildcards `iam:*`/`sts:*`/`*:*` match anywhere (they are never
   Resources).
2. **Trust-vs-identity FP.** Every `aws_iam_policy_document` was treated as an
   identity policy, so trust policies (`sts:AssumeRole` with a service principal)
   counted as delegation. Fixed: data-source policies are now judged
   per-statement from parsed structure; a statement with `principals` and no
   `resources` is trust-side and skipped.

## Scanner validation (known-ground-truth)

The fixed scanner was run against templates with known answers, and each lands in
the correct tier - so the S1 zeros are a true negative, not a broken detector:

| Template | delegation | chainable_classic | chainable_agentic |
|---|---|---|---|
| lab `passrole.tf` (RoleA→RoleC, `bedrock-agentcore:*`) | yes | 0 | **1** ✓ |
| BishopFox IAM-Vulnerable (classic privesc modules) | yes | **2** ✓ | 0 |

The lab's own two-hop pattern - the one reproduced live on AWS - is recovered by the
**agentic** tier; IAM-Vulnerable's classic privesc by the **classic** tier. The two
tiers separate cleanly, and the agentic tier is the paper's headline (it matches the
deployed escalation).

## Reproduce

```bash
# clone the S1 corpus (vendor-official)
bash evaluation/benchmark/collect_corpus_s1.sh      # -> corpus_s1/
# scan (tiered)
python3 evaluation/benchmark/scan_s1.py --root corpus_s1 --json s1_prevalence.json
# validate the scanner on known ground truth
python3 evaluation/benchmark/scan_s1.py --root known_pos --json known_pos.json
```

## Next (Tier-2)

S1 = clean floor. Tier-2 (community/third-party agent-adjacent IaC, sized by
`count_corpus.sh`) is where the chainable rate, if any, will show. The headline
metric there is **chainable_agentic**, with classic reported alongside.

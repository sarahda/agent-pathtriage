#!/usr/bin/env bash
# sparse_patterns.sh - the one definition of which paths a sparse clone keeps.
#
# This used to be written out twice, once in collect_corpus_v3.sh and once in
# verify_sparse_equiv.sh, with a comment in the second saying it must stay
# identical to the first. It had already drifted: the collector carried
# *.bicep and *.bicepparam and the verifier did not, so the verifier was
# checking a pattern set the collector does not use. Both now source this.
#
# What the analysers read, and so what has to survive a sparse clone:
#   *.tf *.tf.json *.tfvars *.hcl   tf_to_state, gap, topology,
#                                   corpus_population, scan_s1
#   *.py                            codereq, codecolo_check, and CDK in Python
#   *.yaml *.yml *.json             CloudFormation templates, and ARM
#   *.ts                            CDK in TypeScript
#   *.bicep *.bicepparam            Azure deployments
#   *.toml Dockerfile* requirements*.txt pyproject.toml
#                                   build context the code checks read
#
# *.json and *.ts were added on 2026-11-02, when the CloudFormation and CDK
# population was collected. Without them a sparse clone of that population
# drops the CloudFormation JSON templates and every TypeScript CDK app, which
# is most of what the queries match, and the scan returns a near zero that
# looks like a result.
#
# No negative patterns. Excluding noise such as package-lock.json would shrink
# the clones, but the equivalence check compares the file set of a sparse clone
# against a full one, and an exclusion makes that comparison fail by design.
# A smaller clone is not worth losing the check that the clone is complete.

SPARSE_PATTERNS=(
  '*.tf' '*.tf.json' '*.tfvars' '*.hcl'
  '*.py' 'requirements*.txt' 'pyproject.toml'
  '*.yaml' '*.yml' '*.json' '*.ts'
  '*.toml' 'Dockerfile*'
  '*.bicep' '*.bicepparam'
)

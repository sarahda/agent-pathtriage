# infra/aws/shared_role.tf
#
# The shared execution role cell.
#
# The rest of this lab gives each agent its own role, which is the control.
# This file adds the treatment: both runtimes under ONE execution role. That is
# the pattern measured in the corpus (5 templates sharing one execution role)
# and the pattern in all five responsible disclosure reports, where two agents
# are declared with the same role_arn.
#
# Turn it on with:
#   terraform apply -var shared_execution_role=true
# and off again by dropping the flag. Nothing else changes, so the two states
# differ in one variable, which is what makes the pair a control and a
# treatment rather than two different labs.
#
# This role is intentionally the composition of what both agents need. It is
# insecure by construction and exists only in a researcher-controlled account.
# See ../RESPONSIBLE_USE.md.

variable "shared_execution_role" {
  description = <<-EOT
    false: each runtime keeps its own role (control).
    true:  both runtimes run under one role carrying the union of what either
           needs (treatment). The escalation under test is that the agent with
           the smaller job can reach the other agent's resources, and that the
           access logs cannot tell the two apart because both calls carry the
           same role.
  EOT
  type        = bool
  default     = false
}

variable "agent_a_scoped" {
  description = <<-EOT
    The control for the SHARING experiment, as opposed to the over-permissioning
    one the rest of this lab runs.

    false (default): agent A runs under RoleA, which holds the four disclosed
      wildcards. That is the original lab and it answers a different question.
    true: agent A runs under a role scoped to its own memory store and its own
      image, mirroring RoleB. Neither agent can reach the other.

    The sharing pair is:
      terraform apply -var agent_a_scoped=true            # control, blocked
      terraform apply -var shared_execution_role=true     # treatment, reaches

    Keeping them apart matters. With RoleA in the control, agent A already
    holds bedrock-agentcore:* on memory/*, so it reaches the other agent's
    store whether or not a role is shared, and the pair would not isolate
    sharing as the cause.
  EOT
  type        = bool
  default     = false
}

locals {
  # Which role each runtime actually runs as. agents.tf reads these, so the
  # switch is in one place and the runtime declarations do not branch.
  shared_role_arn = var.shared_execution_role ? aws_iam_role.shared_agent_execution[0].arn : null
  agent_a_base_arn = var.agent_a_scoped ? aws_iam_role.agent_a_scoped[0].arn : aws_iam_role.agent_a.arn
  agent_a_role_arn = coalesce(local.shared_role_arn, local.agent_a_base_arn)
  agent_b_role_arn = coalesce(local.shared_role_arn, aws_iam_role.agent_b.arn)
}

# Mirror of RoleB, for agent A. Same shape, its own resources. This exists so
# the sharing experiment has a control in which neither agent is over
# permissioned, and the only thing that differs between the two states is
# whether one role is used for both runtimes.
resource "aws_iam_role" "agent_a_scoped" {
  count              = var.agent_a_scoped ? 1 : 0
  name               = "${var.name_prefix}-roleA-scoped"
  assume_role_policy = data.aws_iam_policy_document.agentcore_assume.json
  description        = "Correctly-scoped role for agent A. The control for the sharing experiment."
}

variable "falsify_direct_grant" {
  description = <<-EOT
    The falsification cell. Requires agent_a_scoped.

    Agent A keeps its own role, so the runtimes do NOT share one, and that role
    is granted agent B's memory store directly. Agent A then reaches agent B's
    memory exactly as it does in the treatment, and the request, the response
    and the log record are the same. What differs is that the access is
    authorised, so the predicate does not fire.

    This is the cell that stops "reached" from being read as "escalated". It is
    the AWS counterpart of the Foundry falsification cell, where the caller was
    given the index role directly and the trace stayed identical.

      terraform apply -var agent_a_scoped=true -var falsify_direct_grant=true
  EOT
  type        = bool
  default     = false
}

locals {
  # eff(agent A) is the same in the control, the treatment and the
  # falsification: it reaches agent B's memory in two of the three. What moves
  # is auth(agent A). Writing the two lists out separately is the point of the
  # cell, so they are named here rather than inlined.
  agent_a_own_memory = [aws_bedrockagentcore_memory.agent_a.arn]
  agent_a_granted_memory = var.falsify_direct_grant ? concat(
    local.agent_a_own_memory, [aws_bedrockagentcore_memory.agent_b.arn]
  ) : local.agent_a_own_memory
}

data "aws_iam_policy_document" "agent_a_scoped" {
  statement {
    sid       = "OwnMemoryOnly"
    effect    = "Allow"
    actions   = ["bedrock-agentcore:GetMemory", "bedrock-agentcore:ListEvents",
                 "bedrock-agentcore:CreateEvent", "bedrock-agentcore:RetrieveMemoryRecords"]
    resources = local.agent_a_granted_memory
  }
  statement {
    sid       = "EcrAuthToken"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid       = "OwnImagePull"
    effect    = "Allow"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = [aws_ecr_repository.agent_a.arn]
  }
}

resource "aws_iam_role_policy" "agent_a_scoped" {
  count  = var.agent_a_scoped ? 1 : 0
  name   = "scoped-inline"
  role   = aws_iam_role.agent_a_scoped[0].id
  policy = data.aws_iam_policy_document.agent_a_scoped.json
}

resource "aws_iam_role" "shared_agent_execution" {
  count              = var.shared_execution_role ? 1 : 0
  name               = "${var.name_prefix}-agent-execution"
  assume_role_policy = data.aws_iam_policy_document.agentcore_assume.json
  description        = "One execution role for both agents. Reproduces the shared-role pattern found in public AgentCore Terraform. Research only."
}

# The baseline here is the execution role AWS publishes in
# "IAM Permissions for AgentCore Runtime", not a policy invented for the lab,
# so that what the cell demonstrates is a property of the documented pattern
# rather than of a strawman.
#
# Two departures from that template, both forced by sharing, both recorded
# because they are part of the finding:
#
#  1. The published template scopes the log-group statement to
#     /aws/bedrock-agentcore/runtimes/agentName-*, and the page says to decide
#     the agent name before creating the role. A role shared by two agents
#     cannot carry one agent's name, so the scope has to widen. Sharing an
#     execution role is therefore not only a convenience: it requires widening
#     a resource scope the vendor wrote narrowly.
#
#  2. The template grants GetWorkloadAccessToken, GetWorkloadAccessTokenForJWT
#     and GetWorkloadAccessTokenForUserId together, while the prose on the same
#     page says production deployments should explicitly deny
#     GetWorkloadAccessTokenForUserId and grant only the JWT form. The template
#     is reproduced as published, contradiction included, because the question
#     is what happens to someone who follows it.
data "aws_iam_policy_document" "shared_agent_execution" {
  statement {
    sid       = "EcrImageAccess"
    effect    = "Allow"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = ["arn:aws:ecr:${local.region}:${local.account_id}:repository/*"]
  }
  statement {
    sid       = "EcrTokenAccess"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["logs:DescribeLogStreams", "logs:CreateLogGroup"]
    resources = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/bedrock-agentcore/runtimes/*"]
  }
  statement {
    sid       = "WidenedForSharing"
    effect    = "Allow"
    actions   = ["logs:PutResourcePolicy"]
    # Published template: .../runtimes/agentName-*  (one agent per role).
    resources = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/bedrock-agentcore/runtimes/*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*"]
  }
  statement {
    effect  = "Allow"
    actions = ["xray:PutTraceSegments", "xray:PutTelemetryRecords",
    "xray:GetSamplingRules", "xray:GetSamplingTargets"]
    resources = ["*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["bedrock-agentcore"]
    }
  }
  statement {
    sid    = "GetAgentAccessToken"
    effect = "Allow"
    actions = ["bedrock-agentcore:GetWorkloadAccessToken",
      "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
    "bedrock-agentcore:GetWorkloadAccessTokenForUserId"]
    resources = ["*"]
  }

  # The union. This is the cell. Neither agent needs the other's memory store,
  # and under one role each one holds both. The witness for the exploit is that
  # the agent whose job is only its own store reads the other's.
  statement {
    sid    = "UnionOfBothAgentsMemory"
    effect = "Allow"
    actions = ["bedrock-agentcore:GetMemory", "bedrock-agentcore:ListEvents",
    "bedrock-agentcore:CreateEvent", "bedrock-agentcore:RetrieveMemoryRecords"]
    resources = [
      aws_bedrockagentcore_memory.agent_a.arn,
      aws_bedrockagentcore_memory.agent_b.arn,
    ]
  }
}

resource "aws_iam_role_policy" "shared_agent_execution" {
  count  = var.shared_execution_role ? 1 : 0
  name   = "shared-execution-inline"
  role   = aws_iam_role.shared_agent_execution[0].id
  policy = data.aws_iam_policy_document.shared_agent_execution.json
}

output "shared_execution_role_arn" {
  description = "Null when the control is deployed, the one role when the treatment is."
  value       = local.shared_role_arn
}

output "execution_roles_in_use" {
  description = "What each runtime actually runs as, so a run cannot be mislabelled."
  value = {
    agent_a        = local.agent_a_role_arn
    agent_b        = local.agent_b_role_arn
    shared         = var.shared_execution_role
    agent_a_scoped = var.agent_a_scoped
    falsify_direct_grant = var.falsify_direct_grant
    cell = (var.shared_execution_role ? "sharing treatment"
      : var.agent_a_scoped && var.falsify_direct_grant ? "falsification, agent A authorised directly"
      : var.agent_a_scoped ? "sharing control, neither agent over permissioned"
    : "original over-permissioning lab, not a sharing cell")
  }
}

# infra/aws/iam.tf
#
# RoleA: the over-privileged AgentCore execution role, reproduced from the
#        Mitigant / Unit 42 "starter toolkit" disclosure. The four wildcard
#        statements are what create cross-agent reach (the CP primitives).
# RoleB: a correctly-scoped victim role, for contrast.
#
# NOTE: this over-privileged role is intentionally insecure. It exists only in
#       a researcher-controlled account for this study. See RESPONSIBLE_USE.md.

# --- Trust policy: AgentCore may assume these roles ---
data "aws_iam_policy_document" "agentcore_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock-agentcore.amazonaws.com"]
    }
  }
}

# =========================================================================
# RoleA: OVER-PRIVILEGED (attacker agent). The four disclosed wildcards.
# =========================================================================
resource "aws_iam_role" "agent_a" {
  name               = "${var.name_prefix}-roleA-overprivileged"
  assume_role_policy = data.aws_iam_policy_document.agentcore_assume.json
  description        = "Over-permissioned AgentCore role (reproduced disclosure). Research only."
}

data "aws_iam_policy_document" "agent_a_overprivileged" {
  # (1) ECR wildcard -> pull ANY agent's container image  [CP-1 / CP-5]
  statement {
    sid       = "EcrWildcard"
    effect    = "Allow"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  # (2) Memory wildcard -> read/write ANY agent's memory store  [CP-3]
  statement {
    sid       = "MemoryWildcard"
    effect    = "Allow"
    actions   = ["bedrock-agentcore:*"]
    resources = ["arn:aws:bedrock-agentcore:${local.region}:${local.account_id}:memory/*"]
  }
  # (3) Code interpreter wildcard -> run in ANY interpreter  [CP-5]
  statement {
    sid       = "CodeInterpreterWildcard"
    effect    = "Allow"
    actions   = ["bedrock-agentcore:InvokeCodeInterpreter"]
    resources = ["*"]
  }
  # (4) Runtime wildcard -> invoke ANY agent runtime  [CP-2]
  statement {
    sid       = "RuntimeWildcard"
    effect    = "Allow"
    actions   = ["bedrock-agentcore:InvokeAgentRuntime"]
    resources = ["arn:aws:bedrock-agentcore:${local.region}:${local.account_id}:runtime/*"]
  }
}

resource "aws_iam_role_policy" "agent_a" {
  name   = "overprivileged-inline"
  role   = aws_iam_role.agent_a.id
  policy = data.aws_iam_policy_document.agent_a_overprivileged.json
}

# =========================================================================
# RoleB: CORRECTLY-SCOPED (victim agent). Only its OWN resources.
# =========================================================================
resource "aws_iam_role" "agent_b" {
  name               = "${var.name_prefix}-roleB-scoped"
  assume_role_policy = data.aws_iam_policy_document.agentcore_assume.json
  description        = "Correctly-scoped victim AgentCore role, for contrast with RoleA."
}

data "aws_iam_policy_document" "agent_b_scoped" {
  # RoleB can only touch its own memory store (scoped by ARN), not memory/*
  statement {
    sid       = "OwnMemoryOnly"
    effect    = "Allow"
    actions   = ["bedrock-agentcore:GetMemory", "bedrock-agentcore:ListEvents", "bedrock-agentcore:CreateEvent"]
    resources = [aws_bedrockagentcore_memory.agent_b.arn]
  }
  statement {
    sid       = "OwnImagePull"
    effect    = "Allow"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:GetAuthorizationToken"]
    resources = [aws_ecr_repository.agent_b.arn]
  }
}

resource "aws_iam_role_policy" "agent_b" {
  name   = "scoped-inline"
  role   = aws_iam_role.agent_b.id
  policy = data.aws_iam_policy_document.agent_b_scoped.json
}

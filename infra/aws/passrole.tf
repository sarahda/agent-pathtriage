# passrole.tf
# ---------------------------------------------------------------------------
# Two-hop PassRole escalation scenario.
#
# The point of this file is to build a principal that a SINGLE-HOP analyser
# calls "safe", but that is actually over-privileged once you follow the
# delegation chain. This is the exact case mutation testing flagged as a
# false negative (hard_passrole_two_hop) and is what `propagate` must catch.
#
#   RoleA_thin  --iam:PassRole-->  RoleC (over-privileged)  --act-->  AgentB resources
#
# RoleA_thin holds NO direct resource permissions. Its only powers are
# iam:PassRole and sts:AssumeRole, both scoped to RoleC. So a tool that only
# looks at RoleA_thin's own action/resource pairs sees nothing dangerous.
# The escalation lives in the fact that RoleC is over-privileged and
# RoleA_thin can hand execution to it.
#
# Nothing here hardcodes an "escalation = true" outcome. The privilege comes
# entirely from real IAM policy documents evaluated by AWS / by our tool.
# ---------------------------------------------------------------------------

# --- RoleC: the over-privileged target of the PassRole -----------------------

resource "aws_iam_role" "role_c_overprivileged" {
  name = "${var.name_prefix}-roleC-overprivileged"

  # Who is allowed to assume / be passed RoleC:
  #  - the AgentCore runtime service (so it can actually run as this role)
  #  - the operator identity (so we can drive the PoC ourselves)
  #  - RoleA_thin (so the two-hop delegation is real, not simulated)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "bedrock-agentcore.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
      {
        Effect    = "Allow"
        Principal = { AWS = data.aws_caller_identity.current.arn }
        Action    = "sts:AssumeRole"
      },
      {
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.role_a_thin.arn }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Project  = var.name_prefix
    Scenario = "passrole-two-hop"
    Note     = "intentionally-overprivileged-research-only"
  }
}

# RoleC's permissions: the same wildcard over-privilege shape as RoleA in the
# single-hop scenario. This is what makes the *chain* dangerous.
resource "aws_iam_role_policy" "role_c_policy" {
  name = "${var.name_prefix}-roleC-inline"
  role = aws_iam_role.role_c_overprivileged.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "MemoryFullWildcard"
        Effect   = "Allow"
        Action   = "bedrock-agentcore:*"
        Resource = "arn:aws:bedrock-agentcore:*:${data.aws_caller_identity.current.account_id}:memory/*"
      },
      {
        Sid      = "InvokeAnyRuntime"
        Effect   = "Allow"
        Action   = "bedrock-agentcore:InvokeAgentRuntime"
        Resource = "arn:aws:bedrock-agentcore:*:${data.aws_caller_identity.current.account_id}:runtime/*"
      },
      {
        Sid      = "CodeInterpreterWildcard"
        Effect   = "Allow"
        Action   = "bedrock-agentcore:InvokeCodeInterpreter"
        Resource = "*"
      }
    ]
  })
}

# --- RoleA_thin: looks harmless on its own -----------------------------------

resource "aws_iam_role" "role_a_thin" {
  name = "${var.name_prefix}-roleA-thin"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "bedrock-agentcore.amazonaws.com" }
        Action    = "sts:AssumeRole"
      },
      {
        Effect    = "Allow"
        Principal = { AWS = data.aws_caller_identity.current.arn }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Project  = var.name_prefix
    Scenario = "passrole-two-hop"
    Note     = "thin-principal-no-direct-resource-access"
  }
}

# RoleA_thin's ONLY powers: pass RoleC to a service, and assume RoleC.
# No bedrock-agentcore resource actions at all. This is deliberate: a
# single-hop tool sees zero over-privileged action/resource pairs here.
resource "aws_iam_role_policy" "role_a_thin_policy" {
  name = "${var.name_prefix}-roleA-thin-inline"
  role = aws_iam_role.role_a_thin.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PassRoleCOnly"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = aws_iam_role.role_c_overprivileged.arn
      },
      {
        Sid      = "AssumeRoleCOnly"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.role_c_overprivileged.arn
      }
    ]
  })
}

# Two agents, one execution role.
#
# This is the finding the corpus measurement found in 5 of the 18 multi-agent
# templates it identified, and it is the one a policy linter cannot report.
# Read the role and its policy on their own and there is nothing wrong: one
# role, two services it may act for, a scoped grant on one table and one
# bucket. The defect is in the binding. Both agents run as this role, so each
# already holds everything the other holds, and anything that reaches the
# weaker agent is acting with the authority of the stronger one.
#
# Scan it with:
#
#     agentpathtriage scan examples/shared-role
#
# The fix is one role per agent, each with only what that agent needs.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

resource "aws_dynamodb_table" "tickets" {
  name         = "support-tickets"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_s3_bucket" "payouts" {
  bucket = "example-finance-payouts"
}

resource "aws_iam_role" "agents" {
  name = "agent-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "agents" {
  name = "agent-execution"
  role = aws_iam_role.agents.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"]
        Resource = aws_dynamodb_table.tickets.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.payouts.arn}/*"
      },
    ]
  })
}

# The agent a customer talks to. It needs the ticket table.
resource "aws_bedrockagentcore_agent_runtime" "support" {
  agent_runtime_name = "support-assistant"
  role_arn           = aws_iam_role.agents.arn
}

# The agent that moves money. It needs the payouts bucket.
# Sharing the role above gives the customer-facing agent the same reach.
resource "aws_bedrockagentcore_agent_runtime" "payouts" {
  agent_runtime_name = "payout-processor"
  role_arn           = aws_iam_role.agents.arn
}

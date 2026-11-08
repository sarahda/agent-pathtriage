# infra/aws/resources.tf
# AgentB's own resources. These are what RoleA's wildcards can reach across
# the agent boundary (the witnesses), and what RoleB is correctly scoped to.

# --- ECR repos (one per agent; RoleA can pull ANY of them) ---
resource "aws_ecr_repository" "agent_a" {
  name                 = "${var.name_prefix}/agent-a"
  image_tag_mutability = "MUTABLE"
  force_delete         = true # lab convenience: clean teardown
}

resource "aws_ecr_repository" "agent_b" {
  name                 = "${var.name_prefix}/agent-b"
  image_tag_mutability = "MUTABLE"
  force_delete         = true
}

# --- AgentB's memory store (RoleA's memory/* wildcard can read/poison this) ---
resource "aws_bedrockagentcore_memory" "agent_b" {
  name                  = "${replace(var.name_prefix, "-", "_")}_agentB_memory"
  description           = "Victim agent memory store; target of the CP-3 witness."
  event_expiry_duration = 30 # days; keep short for a lab
}

resource "aws_bedrockagentcore_memory" "agent_a" {
  name                  = "${replace(var.name_prefix, "-", "_")}_agentA_memory"
  description           = "AgentA's own memory store; RoleB must NOT be able to read this (control)."
  event_expiry_duration = 30
}

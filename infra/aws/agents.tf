# infra/aws/agents.tf
# Two agent runtimes. Both run the same minimal placeholder agent; what matters
# for this study is the IAM identity each runs under, not the agent logic.
#
# By default AgentA runs under the over-privileged RoleA and AgentB under the
# scoped RoleB. With -var shared_execution_role=true both run under one role
# instead; see shared_role.tf. The runtimes read a local rather than branching
# here, so the two states differ in one variable.

resource "aws_bedrockagentcore_agent_runtime" "agent_a" {
  agent_runtime_name = "${replace(var.name_prefix, "-", "_")}_agent_a"
  role_arn           = local.agent_a_role_arn
  description        = "Attacker agent, over-privileged role."

  agent_runtime_artifact {
    container_configuration {
      container_uri = "${aws_ecr_repository.agent_a.repository_url}:latest"
    }
  }
  network_configuration {
    network_mode = "PUBLIC"
  }
}

resource "aws_bedrockagentcore_agent_runtime" "agent_b" {
  agent_runtime_name = "${replace(var.name_prefix, "-", "_")}_agent_b"
  role_arn           = local.agent_b_role_arn
  description        = "Victim agent, correctly-scoped role."

  agent_runtime_artifact {
    container_configuration {
      container_uri = "${aws_ecr_repository.agent_b.repository_url}:latest"
    }
  }
  network_configuration {
    network_mode = "PUBLIC"
  }
}

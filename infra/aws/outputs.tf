# infra/aws/outputs.tf
# Everything `extract` needs to build the delegation graph, and the attacker
# starting point for the PoCs.

output "account_id" { value = local.account_id }
output "region"     { value = local.region }

output "role_a_arn" {
  description = "Over-privileged attacker role."
  value       = aws_iam_role.agent_a.arn
}
output "role_b_arn" {
  description = "Scoped victim role."
  value       = aws_iam_role.agent_b.arn
}
output "agent_a_arn" { value = aws_bedrockagentcore_agent_runtime.agent_a.agent_runtime_arn }
output "agent_b_arn" { value = aws_bedrockagentcore_agent_runtime.agent_b.agent_runtime_arn }
output "agent_b_memory_arn" { value = aws_bedrockagentcore_memory.agent_b.arn }
output "agent_a_ecr" { value = aws_ecr_repository.agent_a.repository_url }
output "agent_b_ecr" { value = aws_ecr_repository.agent_b.repository_url }

output "agent_a_memory_arn" { value = aws_bedrockagentcore_memory.agent_a.arn }

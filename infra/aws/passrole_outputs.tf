# passrole_outputs.tf
# Outputs for the two-hop PassRole scenario, consumed by the attack PoC and
# by `extract` / `propagate`.

output "role_c_arn" {
  description = "Over-privileged role reachable only via PassRole from RoleA_thin"
  value       = aws_iam_role.role_c_overprivileged.arn
}

output "role_a_thin_arn" {
  description = "Thin principal: only iam:PassRole + sts:AssumeRole on RoleC, no direct resource access"
  value       = aws_iam_role.role_a_thin.arn
}

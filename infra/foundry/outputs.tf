output "resource_group" { value = azurerm_resource_group.rg.name }
output "foundry_id" { value = azapi_resource.foundry.id }
output "projectA_id" { value = azapi_resource.projectA.id }
output "projectB_id" { value = azapi_resource.projectB.id }
output "agentA_principal_id" { value = azurerm_user_assigned_identity.agentA.principal_id }
output "agentB_principal_id" { value = azurerm_user_assigned_identity.agentB.principal_id }
output "key_vault_id" { value = azurerm_key_vault.kv.id }
output "secret_name" { value = azurerm_key_vault_secret.target.name }

output "connection_auth_type" {
  description = "AccountManagedIdentity = passthrough (escalation state); AAD = caller OBO (control state)"
  value       = coalesce(var.connection_auth_type,
    var.use_managed_identity_passthrough ? "AccountManagedIdentity" : "AgentUserImpersonation")
}

output "agentB_role_count" {
  description = "How many roles agentB holds. The dose in the dose-response run."
  value       = 1 + var.agentB_extra_roles
}

output "agentA_client_id" { value = azurerm_user_assigned_identity.agentA.client_id }
output "agentB_client_id" { value = azurerm_user_assigned_identity.agentB.client_id }

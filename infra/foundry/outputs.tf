output "resource_group" { value = azurerm_resource_group.rg.name }
output "foundry_id" { value = azapi_resource.foundry.id }
output "projectA_id" { value = azapi_resource.projectA.id }
output "projectB_id" { value = azapi_resource.projectB.id }
output "agentA_principal_id" { value = azurerm_user_assigned_identity.agentA.principal_id }
output "agentB_principal_id" { value = azurerm_user_assigned_identity.agentB.principal_id }
output "key_vault_id" { value = azurerm_key_vault.kv.id }
output "secret_name" { value = azurerm_key_vault_secret.target.name }

output "connection_auth_type" {
  description = "ProjectManagedIdentity = passthrough (escalation state); AAD = caller OBO (control state)"
  value       = var.use_managed_identity_passthrough ? "ProjectManagedIdentity" : "AAD"
}

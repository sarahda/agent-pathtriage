##########################################################################
# System-assigned identity, and why the lab needs one.
#
# The account and both projects were created with UserAssigned only, which
# left identity.principalId null. Two things broke because of that, both
# found by running the lab on 2026-10-25.
#
# 1. A connection that carries a secret could not be created at all:
#
#      Failed to add secrets: Foundry could not access your Azure Key Vault.
#      Make sure your Foundry resource's identity has the right permissions.
#      Forbidden. Caller is not authorized.
#
#    Foundry keeps connection secrets in its own managed Key Vault unless a
#    Key Vault connection exists, in which case it uses that one instead. This
#    lab declares one (azapi_resource.projectA_kv_connection), so the lab's
#    vault became Foundry's secret store, and Foundry's identity has no write
#    access to it. The vault was meant to be the target of the experiment and
#    became part of the platform's plumbing.
#
# 2. authType ProjectManagedIdentity resolves to the project's system-assigned
#    identity. With principalId null there was nothing to resolve to, so every
#    call through such a connection was refused no matter which principal held
#    the read role. Granting the role to the project user-assigned identity,
#    the other project's, and the agent's own instance identity all left the
#    refusal unchanged.
#
# Turning this off returns the account to the state those two failures were
# observed in, which is how the claim is re-checked.
##########################################################################

# Not a variable. The azapi provider refuses identity_ids when it cannot see
# at validation time that type includes UserAssigned, and a conditional makes
# the value unknown, so the identity type in main.tf is a literal. To return
# the account to the state the two failures were observed in, set those three
# identity blocks back to "UserAssigned" and re-apply.

# Foundry writes connection secrets with the account's identity, so this is
# write access, not read. Key Vault Secrets User would not be enough.
resource "azurerm_role_assignment" "foundry_kv_write" {
  count                = var.deploy_kv_connection ? 1 : 0
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = azapi_resource.foundry.identity[0].principal_id
}

# The principal a ProjectManagedIdentity connection on project A runs as.
resource "azurerm_role_assignment" "projectA_sa_search" {
  count                = var.deploy_search ? 1 : 0
  scope                = azurerm_search_service.idx[0].id
  role_definition_name = "Search Index Data Reader"
  principal_id         = azapi_resource.projectA.identity[0].principal_id
}

output "foundry_sa_principal_id" {
  value = azapi_resource.foundry.identity[0].principal_id
}

output "projectA_sa_principal_id" {
  value = azapi_resource.projectA.identity[0].principal_id
}

output "projectB_sa_principal_id" {
  value = azapi_resource.projectB.identity[0].principal_id
}

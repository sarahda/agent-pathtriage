##########################################################################
# AgentPathTriage - Microsoft Foundry cross-agent lab (infra/foundry)
#
# Confused deputy at the agent-identity layer. Two Foundry projects (Agent A,
# Agent B) under one account. Agent B's managed identity can read a Key Vault
# secret; Agent A's cannot. A connection/capability host configured with
# AccountManagedIdentity means a call routed A -> B runs under idB, so Agent A
# reaches the secret it was never granted. The var `use_managed_identity_
# passthrough` flips OBO vs managed-identity, which is the whole crux.
#
# Resource types + API versions are taken verbatim from azure-ai-foundry/
# foundry-samples (official), so this applies against a real subscription with
# the azapi + azurerm providers. The A->B connected-agent invocation itself is
# an agent-service runtime action, described in agents.json and reasoned over by
# foundry_cp.py (as the AWS lab's agent runtimes are separate from its IAM).
##########################################################################

data "azurerm_client_config" "current" {}

resource "random_string" "u" {
  length  = 4
  numeric = true
  lower   = true
  upper   = false
  special = false
}

resource "azurerm_resource_group" "rg" {
  name     = "rg-apt-foundry-${random_string.u.result}"
  location = var.location
}

# --- two agent identities: A (thin) and B (broad) ------------------------
resource "azurerm_user_assigned_identity" "agentA" {
  name                = "apt-agentA-thin"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_user_assigned_identity" "agentB" {
  name                = "apt-agentB-broad"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
}

# --- the sensitive resource: a Key Vault secret --------------------------
resource "azurerm_key_vault" "kv" {
  name                      = "aptkv${random_string.u.result}"
  location                  = var.location
  resource_group_name       = azurerm_resource_group.rg.name
  tenant_id                 = data.azurerm_client_config.current.tenant_id
  sku_name                  = "standard"
  rbac_authorization_enabled = true
}

resource "azurerm_key_vault_secret" "target" {
  name         = "agentB-managed-secret"
  value        = "apt-lab-sensitive-value"
  key_vault_id = azurerm_key_vault.kv.id
  # the deployer needs KV admin to write this seed secret:
  depends_on = [azurerm_role_assignment.deployer_kv_admin]
}

# The deployer needs a data-plane role on the account to create the agents.
# Which role is not obvious from the names, and this was established by
# testing the candidates on 2026-10-25:
#   Azure AI Developer                            does not grant the agents actions
#   Cognitive Services User                        excludes
#       .../agents/endpoints/UserIdentityImpersonation/action via notDataActions
#   Cognitive Services Data Contributor (Preview)  works
# The first build got this by hand at the console, so rebuilding from the
# configuration alone failed at create_agents.py with
#   does not have permissions for
#   Microsoft.CognitiveServices/accounts/AIServices/agents/read
# which is the reason to rebuild rather than repair: a grant that exists only
# in someone's shell history is not part of the lab.
resource "azurerm_role_assignment" "deployer_agents_data" {
  scope                = azapi_resource.foundry.id
  role_definition_name = "Cognitive Services Data Contributor (Preview)"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "deployer_kv_admin" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id
}

# --- the asymmetry: B can read the secret, A cannot ----------------------
resource "azurerm_role_assignment" "agentB_secret" {
  scope                            = azurerm_key_vault.kv.id
  role_definition_name             = "Key Vault Secrets User"
  principal_id                     = azurerm_user_assigned_identity.agentB.principal_id
  skip_service_principal_aad_check = true
}

# dose-response: extra roles for agentB, one per step. The scopes already exist,
# so a step costs nothing beyond the role assignment itself.
locals {
  agentB_extra = [
    { role = "Key Vault Crypto User", scope = azurerm_key_vault.kv.id },
    { role = "Reader", scope = azurerm_resource_group.rg.id },
  ]
}

resource "azurerm_role_assignment" "agentB_extra" {
  count                            = var.agentB_extra_roles
  scope                            = local.agentB_extra[count.index].scope
  role_definition_name             = local.agentB_extra[count.index].role
  principal_id                     = azurerm_user_assigned_identity.agentB.principal_id
  skip_service_principal_aad_check = true
}

# falsification control: only when explicitly asked, give A the role directly.
resource "azurerm_role_assignment" "agentA_secret" {
  count                            = var.grant_agentA_secret_access ? 1 : 0
  scope                            = azurerm_key_vault.kv.id
  role_definition_name             = "Key Vault Secrets User"
  principal_id                     = azurerm_user_assigned_identity.agentA.principal_id
  skip_service_principal_aad_check = true
}

# --- Foundry account + two projects --------------------------------------
resource "azapi_resource" "foundry" {
  type      = "Microsoft.CognitiveServices/accounts@2025-06-01"
  name      = "${var.ai_foundry_name}${random_string.u.result}"
  location  = var.location
  parent_id = azurerm_resource_group.rg.id

  identity {
    type         = "SystemAssigned, UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.agentA.id, azurerm_user_assigned_identity.agentB.id]
  }

  body = {
    kind = "AIServices"
    sku  = { name = "S0" }
    properties = {
      allowProjectManagement = true
      customSubDomainName    = "${var.ai_foundry_name}${random_string.u.result}"
      disableLocalAuth       = false
      publicNetworkAccess    = "Enabled"
    }
  }
}

resource "azapi_resource" "projectA" {
  type      = "Microsoft.CognitiveServices/accounts/projects@2025-06-01"
  name      = "agentA"
  location  = var.location
  parent_id = azapi_resource.foundry.id
  identity {
    type         = "SystemAssigned, UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.agentA.id]
  }
  body = { properties = {} }
}

# Serialised behind project A on purpose. The account takes one operation at a
# time, and Terraform creates both projects in parallel by default, which
# fails the second with
#   RESPONSE 409 RequestConflict
#   Another operation is in progress on the resource '.../accounts/<name>'
# Re-running apply clears it, but a reproduction recipe that sometimes needs a
# second run is not a reproduction recipe.
resource "azapi_resource" "projectB" {
  depends_on = [azapi_resource.projectA]

  type      = "Microsoft.CognitiveServices/accounts/projects@2025-06-01"
  name      = "agentB"
  location  = var.location
  parent_id = azapi_resource.foundry.id
  identity {
    type         = "SystemAssigned, UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.agentB.id]
  }
  body = { properties = {} }
}

# --- the connection on Agent A's project that routes execution ----------
# authType AccountManagedIdentity => calls run under the project managed
# identity, not the caller (this is the passthrough that enables the deputy).
# Off by default since 2026-10-25. Declaring a Key Vault connection makes
# Foundry store every connection secret in THIS vault instead of its own
# managed one, and Foundry's identity cannot write to it:
#   Failed to add secrets: Foundry could not access your Azure Key Vault.
# Granting Key Vault Secrets Officer to the account's system-assigned
# identity did not lift it. While this exists, no connection that carries a
# secret can be created at all, which is what blocked the ApiKey control.
#
# It was built as the lab's target. In Foundry it is not a target, it is
# platform plumbing. The target is now the search index in search.tf, and
# nothing in the experiment needs this connection. Set deploy_kv_connection
# to true to reproduce the failure.
variable "deploy_kv_connection" {
  type    = bool
  default = false
}

resource "azapi_resource" "projectA_kv_connection" {
  count                     = var.deploy_kv_connection ? 1 : 0
  type                      = "Microsoft.CognitiveServices/accounts/connections@2025-06-01"
  name                      = "agentA-kv-connection"
  parent_id = azapi_resource.foundry.id
  schema_validation_enabled = false

  body = {
    properties = {
      category      = "AzureKeyVault"
      target        = azurerm_key_vault.kv.vault_uri
      authType      = coalesce(var.connection_auth_type,
        var.use_managed_identity_passthrough ? "AccountManagedIdentity" : "AgentUserImpersonation")
      isSharedToAll = true
      metadata = {
        ResourceId = azurerm_key_vault.kv.id
        location   = var.location
      }
    }
  }
}

# optional model deployment (agents need a model to actually run)
resource "azapi_resource" "model" {
  count     = var.deploy_model ? 1 : 0
  type      = "Microsoft.CognitiveServices/accounts/deployments@2025-06-01"
  name      = var.model_name
  parent_id = azapi_resource.foundry.id
  body = {
    sku = { name = "GlobalStandard", capacity = var.model_capacity }
    properties = {
      model = { name = var.model_name, format = "OpenAI", version = var.model_version }
    }
  }
}

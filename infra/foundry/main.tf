##########################################################################
# AgentPathTriage - Microsoft Foundry cross-agent lab (infra/foundry)
#
# Confused deputy at the agent-identity layer. Two Foundry projects (Agent A,
# Agent B) under one account. Agent B's managed identity can read a Key Vault
# secret; Agent A's cannot. A connection/capability host configured with
# ProjectManagedIdentity means a call routed A -> B runs under idB, so Agent A
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
  enable_rbac_authorization = true
}

resource "azurerm_key_vault_secret" "target" {
  name         = "agentB-managed-secret"
  value        = "apt-lab-sensitive-value"
  key_vault_id = azurerm_key_vault.kv.id
  # the deployer needs KV admin to write this seed secret:
  depends_on = [azurerm_role_assignment.deployer_kv_admin]
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
    type         = "UserAssigned"
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
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.agentA.id]
  }
  body = { properties = {} }
}

resource "azapi_resource" "projectB" {
  type      = "Microsoft.CognitiveServices/accounts/projects@2025-06-01"
  name      = "agentB"
  location  = var.location
  parent_id = azapi_resource.foundry.id
  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.agentB.id]
  }
  body = { properties = {} }
}

# --- the connection on Agent A's project that routes execution ----------
# authType ProjectManagedIdentity => calls run under the project managed
# identity, not the caller (this is the passthrough that enables the deputy).
resource "azapi_resource" "projectA_kv_connection" {
  type                      = "Microsoft.CognitiveServices/accounts/projects/connections@2025-06-01"
  name                      = "agentA-kv-connection"
  parent_id                 = azapi_resource.projectA.id
  schema_validation_enabled = false

  body = {
    properties = {
      category      = "AzureKeyVault"
      target        = azurerm_key_vault.kv.vault_uri
      authType      = var.use_managed_identity_passthrough ? "ProjectManagedIdentity" : "AAD"
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
  name      = "gpt-4o-mini"
  parent_id = azapi_resource.foundry.id
  body = {
    sku = { name = "GlobalStandard", capacity = 10 }
    properties = {
      model = { name = "gpt-4o-mini", format = "OpenAI", version = "2024-07-18" }
    }
  }
}

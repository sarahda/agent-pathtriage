##########################################################################
# The reachable resource for the live observation.
#
# Key Vault cannot serve this role. A Foundry connection with category
# AzureKeyVault is the platform's own secret store, not something an agent
# tool can call: no tool in the SDK takes an AzureKeyVault connection. The
# Key Vault in main.tf stays as the static asymmetry the analyser reasons
# over. This file adds a resource an agent can actually reach.
#
# Azure AI Search also fixes the control cell. Key Vault Administrator carries
# dataActions, so the deployer could read the secret and the
# AgentUserImpersonation run would have come back "reached" for a reason that
# has nothing to do with the mechanism. Owner on a search service carries no
# dataActions, so the deployer has no data-plane access unless it is granted.
# Do not trust that sentence: _probe_search.py checks it before the run.
#
# Free tier is enough. The "Basic tier or higher" requirement in the Azure
# docs is about a search service holding its OWN managed identity for outbound
# calls. What this lab needs is inbound: the Foundry connection authenticating
# TO search as a managed identity, which is data-plane RBAC, and the enable
# roles page says any tier including free.
#
# The connection itself is not here. It is created by lab_search.py against
# the management API, because its body shape is still being established and a
# script costs seconds per iteration where an apply costs minutes.
##########################################################################

variable "deploy_search" {
  type        = bool
  default     = false
  description = "Bring up the search service and its role assignments."
}

variable "search_sku" {
  type        = string
  default     = "free"
  description = "free is enough for inbound RBAC. One free service per subscription."
}

# The identity the escalation runs under.
#
# CognitiveSearch connections do not accept AccountManagedIdentity. The
# accepted set, from the service's own rejection message on 2026-10-25, is
# AAD, UserEntraToken, ApiKey, ProjectManagedIdentity, AgentUserImpersonation,
# AgentOnBehalfOfUser, AgenticIdentityToken, AgenticUser. So the escalating
# level here is ProjectManagedIdentity, which runs the call as the PROJECT's
# managed identity rather than as the caller. Project A's identity is
# apt-agentA-thin, so that identity is the one that must hold the read role
# for there to be anything to gain.
# Off by default, and renamed, because the first version of this was wrong.
# It granted the role to project A's USER-assigned identity (apt-agentA-thin),
# on the assumption that that is what ProjectManagedIdentity resolves to. It
# is not: that authType resolves to the project's SYSTEM-assigned identity,
# which is why projectA_sa_search in system_identity.tf is the grant the
# experiment needs. Turning this on adds a second holder of the role and makes
# the result unattributable.
variable "grant_projectA_uai_search" {
  type    = bool
  default = false
}

# Falsification control. Give the DEPLOYER the read role and the
# AgentUserImpersonation run should flip from blocked to reached. That rules
# out the alternative explanation for a block, which is that the tool simply
# does not work under impersonation. Without this cell the observation is an
# anecdote.
variable "grant_deployer_search_read" {
  type    = bool
  default = false
}

resource "azurerm_search_service" "idx" {
  count               = var.deploy_search ? 1 : 0
  name                = "aptsearch${random_string.u.result}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = var.search_sku

  # aadOrApiKey. Keys stay on so the index can be seeded once without giving
  # the deployer a data-plane role assignment that would contaminate the
  # control cell. The agent path never presents a key: it goes through the
  # connection, whose authType decides the identity.
  local_authentication_enabled = true
  authentication_failure_mode  = "http403"
}

# The asymmetry: agentB's identity can read the index, agentA's cannot.
# Off by default. agentB's user-assigned identity plays no part in the search
# experiment: the executing principal under ProjectManagedIdentity is project
# A's system-assigned identity. While this is on, a reached result has two
# possible explanations and the cell proves nothing.
variable "grant_agentB_uai_search" {
  type    = bool
  default = false
}

resource "azurerm_role_assignment" "agentB_search" {
  count                            = var.deploy_search && var.grant_agentB_uai_search ? 1 : 0
  scope                            = azurerm_search_service.idx[0].id
  role_definition_name             = "Search Index Data Reader"
  principal_id                     = azurerm_user_assigned_identity.agentB.principal_id
  skip_service_principal_aad_check = true
}

resource "azurerm_role_assignment" "projectA_uai_search" {
  count                            = var.deploy_search && var.grant_projectA_uai_search ? 1 : 0
  scope                            = azurerm_search_service.idx[0].id
  role_definition_name             = "Search Index Data Reader"
  principal_id                     = azurerm_user_assigned_identity.agentA.principal_id
  skip_service_principal_aad_check = true
}

resource "azurerm_role_assignment" "deployer_search_read" {
  count                = var.deploy_search && var.grant_deployer_search_read ? 1 : 0
  scope                = azurerm_search_service.idx[0].id
  role_definition_name = "Search Index Data Reader"
  principal_id         = data.azurerm_client_config.current.object_id
}

output "search_endpoint" {
  value = var.deploy_search ? "https://${azurerm_search_service.idx[0].name}.search.windows.net" : null
}

output "search_id" {
  value = var.deploy_search ? azurerm_search_service.idx[0].id : null
}

output "search_name" {
  value = var.deploy_search ? azurerm_search_service.idx[0].name : null
}

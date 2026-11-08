variable "location" {
  type    = string
  default = "eastus"
}

variable "ai_foundry_name" {
  type    = string
  default = "aptfoundry"
}

# THE CONTROL KNOB - the confused-deputy crux.
# true  = the project/connection runs tool & connected-agent calls under the
#         project's MANAGED IDENTITY (idB), regardless of who the caller is.
#         Agent A's invocation of Agent B then executes with idB's permissions
#         -> cross-agent escalation is possible (the escalation state).
# false = calls run on-behalf-of the CALLER (OBO / delegated token), so Agent A's
#         own permissions gate the call -> no escalation (the control state).
variable "use_managed_identity_passthrough" {
  type    = bool
  default = true
}

# Give Agent A's identity the sensitive role directly. Falsification control:
# if A already has it, reaching the secret through B is not a gain.
variable "grant_agentA_secret_access" {
  type    = bool
  default = false
}

variable "deploy_model" {
  type    = bool
  default = false
}

# An explicit auth type, overriding the boolean above when set. The boolean
# covers the two levels this lab has confirmed against Azure. This lets the
# matrix add a level without a code change, so the set of levels is a run
# parameter rather than something baked into the configuration.
variable "connection_auth_type" {
  type        = string
  default     = null
  description = "Exact authType for the Agent A connection. Null uses the boolean."
}

# Dose-response. The binary flip shows that passthrough turns the escalation on.
# It does not show that the SIZE of what is gained tracks what the callee holds.
# Raising this from 0 to 2 gives agentB one, two, then three roles, and the
# gained set should grow with it under passthrough and stay empty under OBO.
# A proportional response is much harder to explain away as a setting artifact
# than a single on-off observation.
variable "agentB_extra_roles" {
  type        = number
  default     = 0
  description = "Extra roles for agentB beyond the Key Vault Secrets User baseline, 0 to 2."
  validation {
    condition     = var.agentB_extra_roles >= 0 && var.agentB_extra_roles <= 2
    error_message = "agentB_extra_roles must be 0, 1 or 2."
  }
}

# The model the agents run on. A version is refused for new deployments once its
# lifecycleStatus turns Deprecating, which is a different field from the
# deprecation dates the catalogue shows: gpt-4o-mini 2024-07-18 listed an
# inference date in 2027 and was already refused. Check before changing with
#   az cognitiveservices account list-models --name <account> -g <rg> -o json
# and take a name whose lifecycleStatus is GenerallyAvailable and whose
# capabilities include agentsV2.
variable "model_name" {
  type    = string
  default = "gpt-5.4-mini"
}

variable "model_version" {
  type    = string
  default = "2026-03-17"
}

variable "model_capacity" {
  type    = number
  default = 10
}

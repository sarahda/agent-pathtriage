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

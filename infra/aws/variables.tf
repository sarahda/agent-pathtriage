# infra/aws/variables.tf

variable "region" {
  description = "AgentCore is available in a limited set of regions; us-east-1 is safest."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for all lab resources, so everything is easy to find and tear down."
  type        = string
  default     = "apt-lab"
}

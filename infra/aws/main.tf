# infra/aws/main.tf
# Baseline: provider, region, account. AgentCore requires AWS provider >= 6.51.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.51"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project = "AgentPathTriage"
      Purpose = "research-lab-cross-agent-privesc"
      Owner   = "z5660470"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

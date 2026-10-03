provider "azurerm" {
  features {}
  # subscription_id / tenant_id come from `az login` or ARM_* env vars.
}

provider "azapi" {}

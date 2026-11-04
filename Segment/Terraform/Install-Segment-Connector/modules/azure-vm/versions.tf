# Which Terraform and provider versions this module needs.

terraform {
  # Modules need Terraform 1.5 or newer. The tests need 1.7 or newer
  # (they use mock providers).
  required_version = ">= 1.5.0"

  required_providers {
    # Azure provider. The argument names in main.tf match the 3.x line.
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0, < 4.0"
    }

    # Used only for a fixed timestamp that sets the SAS time window.
    time = {
      source  = "hashicorp/time"
      version = ">= 0.9.0"
    }
  }
}

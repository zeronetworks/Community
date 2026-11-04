# Installs the Segment Connector on a Linux VM that already exists in Azure.
# This example does not create or change the VM. It only adds the install extension.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# Azure access. Sign in with "az login", or set the ARM_ environment variables.
provider "azurerm" {
  features {}
}

# Look up the existing VM by its name and resource group.
data "azurerm_virtual_machine" "vm" {
  name                = var.vm_name
  resource_group_name = var.vm_resource_group_name
}

# Run the Segment Connector install on that VM.
module "segment_connector" {
  source = "../../modules/azure-vm"

  # The VM to install on. This module can take more than one VM.
  virtual_machine_ids = [data.azurerm_virtual_machine.vm.id]

  # The storage account and container that hold the zip and the script.
  # They must already exist.
  storage_account_name        = var.storage_account_name
  storage_resource_group_name = var.storage_resource_group_name
  storage_container_name      = var.storage_container_name

  # The installer zip on your computer, and the token from the portal.
  installer_zip_local_path = var.installer_zip_local_path
  token                    = var.token

  # Enrollment options. Leave them at the defaults for a host already in the portal.
  allow_create   = var.allow_create
  asset_fqdn     = var.asset_fqdn
  asset_name     = var.asset_name
  with_static_ip = var.with_static_ip

  # Other options.
  run_as            = var.run_as
  reinstall_trigger = var.reinstall_trigger
}

# Shows the command to view the extension output on the VM.
output "how_to_view_output" {
  description = "Command that shows the install output for this VM."
  value       = module.segment_connector.how_to_view_output
}

output "extension_ids" {
  description = "IDs of the VM extensions that run the install."
  value       = module.segment_connector.extension_ids
}

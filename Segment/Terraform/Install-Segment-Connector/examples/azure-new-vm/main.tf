# Creates a small test Linux VM in Azure, then installs the Segment Connector on it.
# It also creates the storage account the installer files are uploaded to.

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

# A resource group to hold everything in this example.
resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
}

# A virtual network and one subnet for the test VM.
resource "azurerm_virtual_network" "vnet" {
  name                = "${var.vm_name}-vnet"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  address_space       = ["10.20.0.0/16"]
}

resource "azurerm_subnet" "subnet" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.20.1.0/24"]
}

# A network card for the VM. It gets a private IP from the subnet.
resource "azurerm_network_interface" "nic" {
  name                = "${var.vm_name}-nic"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
  }
}

# The test VM: Ubuntu 22.04, with SSH key login only.
resource "azurerm_linux_virtual_machine" "vm" {
  name                = var.vm_name
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = var.vm_size
  admin_username      = var.admin_username

  network_interface_ids = [azurerm_network_interface.nic.id]

  # Log in with an SSH key. No password.
  disable_password_authentication = true
  admin_ssh_key {
    username   = var.admin_username
    public_key = file(var.ssh_public_key_path)
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}

# A storage account and a container. The installer zip and the script are uploaded here,
# and the VM downloads them from here.
resource "azurerm_storage_account" "sa" {
  name                     = var.storage_account_name
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}

resource "azurerm_storage_container" "container" {
  name                  = var.storage_container_name
  storage_account_name  = azurerm_storage_account.sa.name
  container_access_type = "private"
}

# Run the Segment Connector install on the test VM.
module "segment_connector" {
  source = "../../modules/azure-vm"

  virtual_machine_ids = [azurerm_linux_virtual_machine.vm.id]

  # The storage account and container created above.
  storage_account_name        = azurerm_storage_account.sa.name
  storage_resource_group_name = azurerm_resource_group.rg.name
  storage_container_name      = azurerm_storage_container.container.name

  # The installer zip on your computer, and the token from the portal.
  installer_zip_local_path = var.installer_zip_local_path
  token                    = var.token

  # Enrollment. A new VM is not in the portal yet, so it needs allow_create.
  allow_create   = var.allow_create
  asset_fqdn     = var.asset_fqdn
  asset_name     = var.asset_name
  with_static_ip = var.with_static_ip

  run_as            = var.run_as
  reinstall_trigger = var.reinstall_trigger

  # Install only after the VM and the storage container exist.
  depends_on = [azurerm_linux_virtual_machine.vm, azurerm_storage_container.container]
}

# Shows the command to view the extension output on the VM.
output "how_to_view_output" {
  description = "Command that shows the install output for the test VM."
  value       = module.segment_connector.how_to_view_output
}

output "vm_private_ip" {
  description = "Private IP of the test VM. This example gives the VM no public IP."
  value       = azurerm_network_interface.nic.private_ip_address
}

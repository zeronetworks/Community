# Settings for this example. Put the values in terraform.tfvars (copy from terraform.tfvars.example).

# Where the test VM and its network go.
variable "resource_group_name" {
  description = "Name of the resource group to create."
  type        = string
}

variable "location" {
  description = "Azure region, for example eastus."
  type        = string
}

# The test VM.
variable "vm_name" {
  description = "Name of the test VM. It is also used for the network names."
  type        = string
}

variable "vm_size" {
  description = "VM size. Standard_B1s is small and low cost."
  type        = string
  default     = "Standard_B1s"
}

variable "admin_username" {
  description = "Login name on the VM."
  type        = string
  default     = "azureuser"
}

variable "ssh_public_key_path" {
  description = "Path to your SSH public key file, for example ~/.ssh/id_ed25519.pub."
  type        = string
}

# Storage for the installer files. The name must be unique in Azure, 3 to 24 lowercase letters and digits.
variable "storage_account_name" {
  description = "Name of the storage account to create. Must be globally unique."
  type        = string
}

variable "storage_container_name" {
  description = "Name of the blob container to create."
  type        = string
  default     = "segment-connector"
}

# The installer zip on your computer, and the token from the portal.
variable "installer_zip_local_path" {
  description = "Path to the installer zip, for example ../../installer/segment-connector-linux-installer-X.Y.Z.W.zip."
  type        = string
}

variable "token" {
  description = "Installation token from the Zero Networks portal. Set it with TF_VAR_token, never in a tfvars file."
  type        = string
  sensitive   = true
}

# Enrollment options. A new VM is not in the portal yet, so allow_create is usually true.
variable "allow_create" {
  description = "Let the portal create a new asset for this VM."
  type        = bool
  default     = true
}

variable "asset_fqdn" {
  description = "FQDN for the new asset. Needs allow_create. Empty lets the portal choose."
  type        = string
  default     = ""
}

variable "asset_name" {
  description = "Display name for the new asset. Needs allow_create."
  type        = string
  default     = ""
}

variable "with_static_ip" {
  description = "Enroll with the source IP the portal sees. Needs allow_create and asset_name."
  type        = bool
  default     = false
}

# Other options.
variable "run_as" {
  description = "Account the connector runs as: zn-user or root."
  type        = string
  default     = "zn-user"
}

variable "reinstall_trigger" {
  description = "Change this value to rerun the install. Leave empty for a normal install."
  type        = string
  default     = ""
}

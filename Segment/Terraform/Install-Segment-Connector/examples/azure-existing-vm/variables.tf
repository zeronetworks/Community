# Settings for this example. Put the values in terraform.tfvars (copy from terraform.tfvars.example).

# The existing VM to install on.
variable "vm_name" {
  description = "Name of the existing Linux VM."
  type        = string
}

variable "vm_resource_group_name" {
  description = "Resource group that holds the VM."
  type        = string
}

# The storage account and container for the zip and the script. They must already exist.
variable "storage_account_name" {
  description = "Name of an existing storage account."
  type        = string
}

variable "storage_resource_group_name" {
  description = "Resource group of the storage account."
  type        = string
}

variable "storage_container_name" {
  description = "Name of an existing blob container in the storage account."
  type        = string
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

# Enrollment options. Leave them at the defaults for a host already in the portal.
variable "allow_create" {
  description = "Let the portal create a new asset for this VM if none matches."
  type        = bool
  default     = false
}

variable "asset_fqdn" {
  description = "FQDN for a new asset. Needs allow_create. Empty lets the portal choose."
  type        = string
  default     = ""
}

variable "asset_name" {
  description = "Display name for a new asset. Needs allow_create."
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

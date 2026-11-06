# Settings for this example. Put the values in terraform.tfvars (copy from terraform.tfvars.example).

variable "region" {
  description = "AWS region for the instance, for example us-east-1."
  type        = string
}

variable "instance_name" {
  description = "Name tag for the test instance."
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type. t3.micro is small and low cost."
  type        = string
  default     = "t3.micro"
}

# The installer zip must be downloadable by the instance without a login.
# A pre-signed S3 URL works, but it expires, so set a long enough expiry for first boot.
variable "installer_url" {
  description = "https:// link to the installer zip that the instance can download at first boot."
  type        = string

  validation {
    condition     = can(regex("^https://", var.installer_url))
    error_message = "installer_url must start with https://."
  }
}

variable "token" {
  description = "Installation token from the Zero Networks portal. Set it with TF_VAR_token, never in a tfvars file. It ends up in the user data."
  type        = string
  sensitive   = true
}

# Enrollment options. A new instance is not in the portal yet, so allow_create is usually true.
variable "allow_create" {
  description = "Let the portal create a new asset for this instance."
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

variable "run_as" {
  description = "Account the connector runs as: zn-user or root."
  type        = string
  default     = "zn-user"
}

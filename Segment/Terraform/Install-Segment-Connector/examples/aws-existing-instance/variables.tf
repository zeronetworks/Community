# Settings for this example. Put the values in terraform.tfvars (copy from terraform.tfvars.example).

variable "region" {
  description = "AWS region of the instance and the bucket, for example us-east-1."
  type        = string
}

# The existing instance to install on.
variable "instance_id" {
  description = "ID of the existing EC2 instance, for example i-0123456789abcdef0."
  type        = string
}

# The S3 bucket for the zip and the script. It must already exist.
variable "bucket_name" {
  description = "Name of an existing S3 bucket in the same region."
  type        = string
}

variable "kms_key_id" {
  description = "Optional KMS key ARN to encrypt the objects. Empty uses the bucket's default encryption."
  type        = string
  default     = ""
}

variable "instance_role_name" {
  description = "Name of the IAM role of the instance. Empty means you attach the read policy yourself."
  type        = string
  default     = ""
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
  description = "Let the portal create a new asset for this instance if none matches."
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

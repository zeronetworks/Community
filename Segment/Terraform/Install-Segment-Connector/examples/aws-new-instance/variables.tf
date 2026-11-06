# Settings for this example. Put the values in terraform.tfvars (copy from terraform.tfvars.example).

variable "region" {
  description = "AWS region for the instance and the bucket, for example us-east-1."
  type        = string
}

# The test instance.
variable "instance_name" {
  description = "Name tag for the test instance. Also used for the IAM role and profile names."
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type. t3.micro is small and low cost."
  type        = string
  default     = "t3.micro"
}

variable "subnet_id" {
  description = "Subnet for the instance. Null uses the default VPC's subnet."
  type        = string
  default     = null
}

# The S3 bucket for the installer files. The name must be unique in AWS.
variable "bucket_name" {
  description = "Name of the S3 bucket to create. Must be globally unique."
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

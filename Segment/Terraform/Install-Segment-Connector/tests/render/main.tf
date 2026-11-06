# Render root for the offline tests.
#
# This small configuration calls the core script module with test values and
# prints the install script and the uninstall script as outputs. The offline test
# runner (tests/run-offline-tests.sh) applies it once for each test variant and
# saves the two outputs as files in tests/build/<variant>/.
#
# No cloud account is needed, and no provider is used.
#
# Each variable below starts at the same value as the module default. The test
# runner overrides only the settings a variant needs (with -var).

terraform {
  required_version = ">= 1.7.0"
}

variable "token_source" {
  description = "Where the script reads the enrollment token from."
  type        = string
  default     = "env"
}

variable "token_file_path" {
  description = "Token file path, used when token_source is file."
  type        = string
  default     = "/opt/zn-segment-connector-setup/.token"
}

variable "reinstall" {
  description = "Run the installer even when the connector is already installed."
  type        = bool
  default     = false
}

variable "download_timeout" {
  description = "Installer package download timeout (seconds or a Go duration)."
  type        = string
  default     = ""
}

variable "allow_create" {
  description = "Let the installer create the portal asset."
  type        = bool
  default     = false
}

variable "asset_fqdn" {
  description = "FQDN used when the installer creates the portal asset."
  type        = string
  default     = ""
}

variable "asset_name" {
  description = "Display name used when the installer creates the portal asset."
  type        = string
  default     = ""
}

variable "with_static_ip" {
  description = "Enroll by static IP (needs asset_name and allow_create)."
  type        = bool
  default     = false
}

variable "asset_id" {
  description = "Existing portal asset ID for this host."
  type        = string
  default     = ""
}

variable "force" {
  description = "Pass -force to the installer."
  type        = bool
  default     = false
}

variable "verify_timeout" {
  description = "Seconds the script waits for the connector to connect."
  type        = number
  default     = 180
}

variable "verify_strict" {
  description = "Exit 2 when the connector is not connected."
  type        = bool
  default     = false
}

# The core module with the test values.
module "script" {
  source = "../../modules/segment-connector-script"

  token_source     = var.token_source
  token_file_path  = var.token_file_path
  reinstall        = var.reinstall
  download_timeout = var.download_timeout
  allow_create     = var.allow_create
  asset_fqdn       = var.asset_fqdn
  asset_name       = var.asset_name
  with_static_ip   = var.with_static_ip
  asset_id         = var.asset_id
  force            = var.force
  verify_timeout   = var.verify_timeout
  verify_strict    = var.verify_strict
}

# The install script, printed as plain text by "terraform output -raw".
output "install_script" {
  description = "The rendered install script."
  value       = module.script.install_script
  # Marked sensitive because the script may hold an embedded token.
  # "terraform output -raw" still prints it.
  sensitive = true
}

# The uninstall script, printed as plain text by "terraform output -raw".
output "uninstall_script" {
  description = "The rendered uninstall script."
  value       = module.script.uninstall_script
  sensitive   = true
}

# Inputs for the Azure VM module.
# Most of the options below are passed straight through to the core
# module (../segment-connector-script). Those have the same names and
# defaults as in the core module.

# ---------------------------------------------------------------
# Which VMs to install on, and where the files are stored
# ---------------------------------------------------------------

variable "virtual_machine_ids" {
  description = "Full Azure resource IDs of the Linux VMs to install the connector on. One CustomScript extension is created per ID."
  type        = set(string)
}

variable "storage_account_name" {
  description = "Name of the existing storage account that holds the installer zip and the script."
  type        = string
}

variable "storage_resource_group_name" {
  description = "Resource group of the existing storage account."
  type        = string
}

variable "storage_container_name" {
  description = "Name of the existing blob container in the storage account. Terraform does not create it."
  type        = string
}

variable "installer_zip_local_path" {
  description = "Path on this computer to the Segment Connector Linux installer zip. Terraform uploads it to the blob container."
  type        = string
}

# ---------------------------------------------------------------
# How the VM gets the files and the token
# ---------------------------------------------------------------

variable "token_delivery" {
  description = "How the enrollment token reaches the VM. \"protected_settings\" puts it in the encrypted extension settings (set var.token). \"key_vault\" makes the VM read it from an Azure Key Vault secret, so it is never in Terraform state."
  type        = string
  default     = "protected_settings"

  validation {
    condition     = contains(["protected_settings", "key_vault"], var.token_delivery)
    error_message = "token_delivery must be \"protected_settings\" or \"key_vault\"."
  }
}

variable "blob_download" {
  description = "How the VM downloads the zip and script. \"sas\" puts a short-lived read-only link in the settings. \"managed_identity\" lets the VM's identity read the blobs, so no link is needed."
  type        = string
  default     = "sas"

  validation {
    condition     = contains(["sas", "managed_identity"], var.blob_download)
    error_message = "blob_download must be \"sas\" or \"managed_identity\"."
  }
}

variable "managed_identity_client_id" {
  description = "Client ID of the user-assigned identity the VM uses to read the blobs (blob_download = \"managed_identity\"). Leave empty to use the VM's system-assigned identity."
  type        = string
  default     = ""
}

variable "sas_hours" {
  description = "How many hours the download link (SAS) stays valid. Only used when blob_download = \"sas\"."
  type        = number
  default     = 4

  validation {
    condition     = var.sas_hours >= 1
    error_message = "sas_hours must be at least 1."
  }
}

variable "token" {
  description = "Enrollment token. Only used when token_delivery = \"protected_settings\". Never written to a file that is not encrypted by Azure."
  type        = string
  default     = ""
  sensitive   = true
}

variable "azure_key_vault_name" {
  description = "Key Vault name the VM reads the token from. Required when token_delivery = \"key_vault\"."
  type        = string
  default     = ""
}

variable "azure_key_vault_secret_name" {
  description = "Name of the Key Vault secret that holds the token. Required when token_delivery = \"key_vault\"."
  type        = string
  default     = ""
}

variable "azure_managed_identity_client_id" {
  description = "Client ID of the VM identity used to read the Key Vault secret (IMDS). Empty means the system-assigned identity. Only used when token_delivery = \"key_vault\"."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------
# Extension settings
# ---------------------------------------------------------------

variable "extension_name" {
  description = "Name of the VM extension. Azure allows only one CustomScript extension per VM, so pick a name that does not clash with another one."
  type        = string
  default     = "zn-segment-connector"
}

variable "timeout_minutes" {
  description = "How long Terraform waits for the extension to finish creating."
  type        = number
  default     = 30
}

variable "reinstall_trigger" {
  description = "Any text. Change it to run the install again on every VM. Empty means no forced reinstall."
  type        = string
  default     = ""
}

# ---------------------------------------------------------------
# Options passed to the core script module (same names as core)
# ---------------------------------------------------------------

variable "action" {
  description = "\"install\" or \"uninstall\"."
  type        = string
  default     = "install"

  validation {
    condition     = contains(["install", "uninstall"], var.action)
    error_message = "action must be \"install\" or \"uninstall\"."
  }
}

variable "installer_url" {
  description = "Optional HTTPS URL to download the installer from instead of the zip in storage. Empty means use the uploaded zip."
  type        = string
  default     = ""
}

variable "staging_dir" {
  description = "Folder on the VM where the installer is unpacked."
  type        = string
  default     = "/opt/zn-segment-connector-setup"
}

variable "identity_file" {
  description = "File that shows the connector is already enrolled. If it exists, the script skips the install."
  type        = string
  default     = "/var/zeronetworks/.zn-internal/identity.json"
}

variable "run_as" {
  description = "Account the connector runs as: \"zn-user\" or \"root\"."
  type        = string
  default     = "zn-user"
}

variable "force" {
  description = "Pass -force to the installer."
  type        = bool
  default     = false
}

variable "asset_id" {
  description = "Existing asset ID to attach the connector to."
  type        = string
  default     = ""
}

variable "asset_fqdn" {
  description = "Fully qualified name for a new asset. Needs allow_create = true."
  type        = string
  default     = ""
}

variable "asset_name" {
  description = "Name for a new asset. Needs allow_create = true."
  type        = string
  default     = ""
}

variable "allow_create" {
  description = "Let the installer create a new asset."
  type        = bool
  default     = false
}

variable "with_static_ip" {
  description = "Create the asset with a static IP. Needs allow_create = true and asset_name set."
  type        = bool
  default     = false
}

variable "installer_env" {
  description = "Extra environment variables for the installer. Keys must be valid shell names."
  type        = map(string)
  default     = {}
}

variable "download_timeout" {
  description = "How long the installer may take to download. A number is in seconds. A Go duration such as \"5m\" also works. Empty means the default."
  type        = string
  default     = ""
}

variable "trace" {
  description = "Turn on installer tracing."
  type        = bool
  default     = false
}

variable "log_to_console" {
  description = "Print installer logs to the console as well."
  type        = bool
  default     = false
}

variable "report_version" {
  description = "Print the installer version before installing."
  type        = bool
  default     = true
}

variable "verify_connection" {
  description = "After install, wait for the connector to report it is connected."
  type        = bool
  default     = true
}

variable "verify_timeout" {
  description = "Seconds to wait for the connection check. Whole number, at least 10."
  type        = number
  default     = 180
}

variable "verify_strict" {
  description = "Fail the script (exit 2) if the connection check fails. If false, it only prints a warning."
  type        = bool
  default     = false
}

variable "log_file" {
  description = "Log file on the VM for the script."
  type        = string
  default     = "/var/log/zn-segment-connector-terraform.log"
}

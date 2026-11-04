# Inputs for the Segment Connector install script.
# Each input has a plain-English description. The Ansible setting it replaces
# is named in the description where one exists.

variable "action" {
  description = "What the script does: \"install\" to install or reinstall the connector, or \"uninstall\" to remove it."
  type        = string
  default     = "install"

  validation {
    condition     = contains(["install", "uninstall"], var.action)
    error_message = "action must be \"install\" or \"uninstall\"."
  }
}

variable "token_source" {
  description = <<-EOT
    Where the script gets the enrollment token from on the host:
    "env"              an environment variable named ZN_SEGMENT_CONNECTOR_TOKEN_B64 or ZN_SEGMENT_CONNECTOR_TOKEN is set when the script runs.
    "file"             a file at token_file_path is read, then deleted.
    "azure_key_vault"  the token is read from an Azure Key Vault secret.
    "embedded"         the token is written into the script itself (use "token" below). The script is then secret.
  EOT
  type        = string
  default     = "env"

  validation {
    condition     = contains(["env", "file", "azure_key_vault", "embedded"], var.token_source)
    error_message = "token_source must be \"env\", \"file\", \"azure_key_vault\" or \"embedded\"."
  }
}

variable "token" {
  description = "The installation token from the Zero Networks portal. Only used when token_source is \"embedded\". Never commit a real value."
  type        = string
  default     = ""
  sensitive   = true
}

variable "token_file_path" {
  description = "Path on the host of the token file. Only used when token_source is \"file\". The script deletes the file after reading it."
  type        = string
  default     = "/opt/zn-segment-connector-setup/.token"

  validation {
    condition     = !strcontains(var.token_file_path, "'")
    error_message = "token_file_path must not contain a single quote (')."
  }
}

variable "azure_key_vault_name" {
  description = "Name of the Azure Key Vault that holds the token. Required when token_source is \"azure_key_vault\"."
  type        = string
  default     = ""

  validation {
    condition     = !strcontains(var.azure_key_vault_name, "'")
    error_message = "azure_key_vault_name must not contain a single quote (')."
  }
}

variable "azure_key_vault_secret_name" {
  description = "Name of the Key Vault secret that holds the token. Required when token_source is \"azure_key_vault\"."
  type        = string
  default     = ""

  validation {
    condition     = !strcontains(var.azure_key_vault_secret_name, "'")
    error_message = "azure_key_vault_secret_name must not contain a single quote (')."
  }
}

variable "azure_managed_identity_client_id" {
  description = "Client ID of the user-assigned managed identity the host uses to read the Key Vault secret. Leave empty to use the host's default identity."
  type        = string
  default     = ""

  validation {
    condition     = !strcontains(var.azure_managed_identity_client_id, "'")
    error_message = "azure_managed_identity_client_id must not contain a single quote (')."
  }
}

variable "installer_zip_path" {
  description = "Path to the installer zip. A relative path is read from the folder that holds the script. Used when installer_url is empty."
  type        = string
  default     = "segment-connector-linux-installer.zip"

  validation {
    condition     = !strcontains(var.installer_zip_path, "'")
    error_message = "installer_zip_path must not contain a single quote (')."
  }
}

variable "installer_url" {
  description = "HTTPS link the host downloads the installer zip from. Leave empty to use installer_zip_path instead."
  type        = string
  default     = ""

  validation {
    condition     = var.installer_url == "" || (can(regex("^https://", var.installer_url)) && !strcontains(var.installer_url, "'"))
    error_message = "installer_url must be empty or start with https://, and must not contain a single quote (')."
  }
}

variable "staging_dir" {
  description = "Folder on the host where the installer zip is unpacked and the installer runs from."
  type        = string
  default     = "/opt/zn-segment-connector-setup"

  validation {
    condition     = !strcontains(var.staging_dir, "'")
    error_message = "staging_dir must not contain a single quote (')."
  }
}

variable "identity_file" {
  description = "File the installer writes on a successful install. If it exists, the install is skipped (unless reinstall is true)."
  type        = string
  default     = "/var/zeronetworks/.zn-internal/identity.json"

  validation {
    condition     = !strcontains(var.identity_file, "'")
    error_message = "identity_file must not contain a single quote (')."
  }
}

variable "run_as" {
  description = "Local user the connector runs as: \"zn-user\" (default) or \"root\". Matches Ansible segment_connector_run_as."
  type        = string
  default     = "zn-user"

  validation {
    condition     = contains(["zn-user", "root"], var.run_as)
    error_message = "run_as must be \"zn-user\" or \"root\"."
  }
}

variable "force" {
  description = "Pass -force to the installer. Used to replace an existing asset ID, and on uninstall. Matches Ansible segment_connector_force."
  type        = bool
  default     = false
}

variable "reinstall" {
  description = "Run the installer again even when the connector is already installed. Matches Ansible segment_connector_reinstall."
  type        = bool
  default     = false
}

variable "asset_id" {
  description = "Existing portal asset ID to attach this host to (passed as -assetId). Optional."
  type        = string
  default     = ""
}

variable "asset_fqdn" {
  description = <<-EOT
    Fully qualified name for a NEW portal asset (passed as -asset-fqdn). Needs allow_create = true.
    Must contain a dot. IP addresses are not accepted. Cannot be used with with_static_ip.
  EOT
  type        = string
  default     = ""

  validation {
    condition = var.asset_fqdn == "" || (
      can(regex("^[A-Za-z0-9-]+([.][A-Za-z0-9-]+)+$", var.asset_fqdn)) &&
      !can(regex("^[0-9.]+$", var.asset_fqdn))
    )
    error_message = "asset_fqdn must be a name with a dot, like connector01.example.com. IP addresses are not accepted."
  }
}

variable "asset_name" {
  description = "Display name for a NEW portal asset (passed as -name). Needs allow_create = true. Required when with_static_ip is true."
  type        = string
  default     = ""
}

variable "allow_create" {
  description = "Create a NEW portal asset for this host (passes -allow-create). Only for hosts that are not yet in the portal. Matches Ansible segment_connector_allow_create."
  type        = bool
  default     = false
}

variable "with_static_ip" {
  description = "Enroll the new asset by static IP instead of FQDN (passes -with-static-ip). Needs allow_create = true and asset_name. Cannot be combined with asset_fqdn."
  type        = bool
  default     = false
}

variable "installer_env" {
  description = <<-EOT
    Extra environment variables for every installer run, as a map of name to text value.
    Entries with empty or null values are dropped. A named setting that is switched on
    (download_timeout, trace, log_to_console) overrides the same name in this map.
  EOT
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for name in keys(var.installer_env) : can(regex("^[A-Za-z_][A-Za-z0-9_]*$", name))])
    error_message = "Every installer_env name must start with a letter or underscore and contain only letters, digits and underscores."
  }
}

variable "download_timeout" {
  description = <<-EOT
    How long the installer may take to download its package. Accepts a Go duration such as
    "10m" or "90s", or a plain number of seconds such as "600" (sent as "600s").
    Leave empty to use the installer default.
  EOT
  type        = string
  default     = ""

  validation {
    condition = var.download_timeout == "" || (
      can(regex("^[0-9]+$", var.download_timeout)) ||
      can(regex("^([0-9]+([.][0-9]+)?(ns|us|ms|s|m|h))+$", var.download_timeout))
    )
    error_message = "download_timeout must be empty, a number of seconds (600), or a Go duration (10m, 90s, 1h30m)."
  }
}

variable "trace" {
  description = "Turn on installer trace logging (sets ZN_AGENT_INSTALLER_TRACE_ENABLED=true). Matches Ansible segment_connector_trace."
  type        = bool
  default     = false
}

variable "log_to_console" {
  description = "Print installer log lines to the console (sets ZN_AGENT_INSTALLER_LOG_PRINT_TO_CONSOLE=true). Output is not hidden in Terraform or cloud job logs."
  type        = bool
  default     = false
}

variable "report_version" {
  description = "Print the installer version before running. Matches Ansible segment_connector_report_version."
  type        = bool
  default     = true
}

variable "verify_connection" {
  description = "After an install, check the connector log for a connection to a segment server. Matches Ansible segment_connector_verify_connection."
  type        = bool
  default     = true
}

variable "verify_timeout" {
  description = "Seconds to wait for the connection check after an install. A whole number, at least 10. Matches Ansible segment_connector_verify_timeout."
  type        = number
  default     = 180

  validation {
    condition     = var.verify_timeout >= 10 && floor(var.verify_timeout) == var.verify_timeout
    error_message = "verify_timeout must be a whole number of seconds, at least 10."
  }
}

variable "verify_strict" {
  description = "Make the script exit with an error when the connector does not connect. When false, the script only prints a warning. Matches Ansible segment_connector_verify_strict."
  type        = bool
  default     = false
}

variable "log_file" {
  description = "File on the host where the script writes its own log lines."
  type        = string
  default     = "/var/log/zn-segment-connector-terraform.log"

  validation {
    condition     = !strcontains(var.log_file, "'")
    error_message = "log_file must not contain a single quote (')."
  }
}

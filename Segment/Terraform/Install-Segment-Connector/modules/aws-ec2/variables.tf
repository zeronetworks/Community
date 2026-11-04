# These are the inputs for the AWS EC2 module.
# Most of them are passed straight through to the shared script module.
# The defaults match the shared script module, so you only set what you need.

# ----- AWS-specific inputs -----------------------------------------------

variable "instance_ids" {
  description = "The EC2 instance IDs to install or remove the connector on. Each instance needs SSM Agent and an instance profile that allows SSM."
  type        = list(string)

  validation {
    condition     = length(var.instance_ids) > 0
    error_message = "Set at least one EC2 instance ID in instance_ids."
  }
}

variable "bucket_name" {
  description = "The S3 bucket where Terraform puts the installer zip, the script and the token. The instances download from this bucket."
  type        = string
}

variable "key_prefix" {
  description = "A folder-style prefix for the S3 files. Must end with a slash, for example zn-segment-connector/. Only letters, numbers, dot, dash, underscore and slash are allowed."
  type        = string
  default     = "zn-segment-connector/"

  validation {
    condition     = var.key_prefix == "" || (endswith(var.key_prefix, "/") && can(regex("^[A-Za-z0-9._/-]+$", var.key_prefix)))
    error_message = "key_prefix must be empty or end with a slash, and may only use letters, numbers, dot, dash, underscore and slash."
  }
}

variable "token_s3_key" {
  description = "Optional. The S3 key of a token file you uploaded yourself, outside Terraform. When set, Terraform does not create or store the token. This is the safer option. Leave empty to let Terraform upload the token from the token variable."
  type        = string
  default     = ""
}

variable "kms_key_id" {
  description = "Optional. The ARN of a KMS key. When set, the S3 files are encrypted with this key, and the instance role needs kms:Decrypt on it. Leave empty to use S3's default encryption (AES256)."
  type        = string
  default     = ""
}

variable "instance_role_name" {
  description = "Optional. The name of the IAM role that the instances use. When set, Terraform adds a policy that lets that role read only the connector files. Leave empty to manage that policy yourself."
  type        = string
  default     = ""
}

variable "execution_timeout_seconds" {
  description = "How many seconds each step of the SSM document may run before SSM stops it."
  type        = number
  default     = 1800

  validation {
    condition     = var.execution_timeout_seconds >= 1
    error_message = "execution_timeout_seconds must be at least 1."
  }
}

variable "wait_for_success_timeout_seconds" {
  description = "How many seconds Terraform waits for the SSM association to report success. If it does not, the apply fails."
  type        = number
  default     = 1200

  validation {
    condition     = var.wait_for_success_timeout_seconds >= 0
    error_message = "wait_for_success_timeout_seconds must be 0 or more."
  }
}

variable "output_s3_key_prefix" {
  description = "Optional. An S3 folder prefix in the same bucket where SSM saves the command output. Leave empty to keep output only in the SSM console."
  type        = string
  default     = ""
}

variable "document_name" {
  description = "The name of the SSM document. Must be unique in the AWS account and region. Change it if you deploy this module twice in the same account."
  type        = string
  default     = "zn-segment-connector-install"
}

variable "installer_zip_local_path" {
  description = "The path on your computer to the Segment Connector Linux installer zip. Terraform uploads this file to S3."
  type        = string
}

variable "token" {
  description = "The enrollment token. Only used when token_s3_key is empty. It is stored in the Terraform state, so keep the state private."
  type        = string
  default     = ""
  sensitive   = true
}

variable "reinstall_trigger" {
  description = "Optional. Any non-empty text. Changing this value makes the instances run the installer again, even if the connector is already installed."
  type        = string
  default     = ""
}

# ----- Shared script inputs (same names and defaults as the core module) -----

variable "action" {
  description = "Install the connector (install) or remove it (uninstall)."
  type        = string
  default     = "install"

  validation {
    condition     = contains(["install", "uninstall"], var.action)
    error_message = "action must be install or uninstall."
  }
}

variable "staging_dir" {
  description = "The folder on the instance where the downloaded files and the installer are put. Use an absolute path with no trailing slash."
  type        = string
  default     = "/opt/zn-segment-connector-setup"

  validation {
    condition     = startswith(var.staging_dir, "/") && !endswith(var.staging_dir, "/")
    error_message = "staging_dir must be an absolute path with no trailing slash."
  }
}

variable "identity_file" {
  description = "The file on the instance that shows the connector is already installed."
  type        = string
  default     = "/var/zeronetworks/.zn-internal/identity.json"
}

variable "run_as" {
  description = "The user the connector runs as: zn-user or root."
  type        = string
  default     = "zn-user"

  validation {
    condition     = contains(["zn-user", "root"], var.run_as)
    error_message = "run_as must be zn-user or root."
  }
}

variable "force" {
  description = "Pass the force flag to the installer."
  type        = bool
  default     = false
}

variable "installer_url" {
  description = "Optional. An https:// address to download the installer from. If set, the instance uses this address instead of the copy in S3. Leave empty to use the S3 copy."
  type        = string
  default     = ""

  validation {
    condition     = var.installer_url == "" || can(regex("^https://", var.installer_url))
    error_message = "installer_url must be empty or start with https://."
  }
}

variable "asset_id" {
  description = "Optional. The ID of the asset to attach the connector to."
  type        = string
  default     = ""
}

variable "asset_fqdn" {
  description = "Optional. The fully qualified domain name to use for a new asset. Needs allow_create = true."
  type        = string
  default     = ""

  validation {
    condition     = var.asset_fqdn == "" || (can(regex("^[A-Za-z0-9-]+([.][A-Za-z0-9-]+)+$", var.asset_fqdn)) && !can(regex("^[0-9.]+$", var.asset_fqdn)))
    error_message = "asset_fqdn must look like a domain name (for example host.example.com) and must not be only numbers and dots."
  }
}

variable "asset_name" {
  description = "Optional. The display name for a new asset. Needs allow_create = true."
  type        = string
  default     = ""
}

variable "allow_create" {
  description = "Let the installer create a new asset in Zero Networks."
  type        = bool
  default     = false
}

variable "with_static_ip" {
  description = "Tell the installer the asset has a static IP. Needs allow_create = true. Cannot be used with asset_fqdn."
  type        = bool
  default     = false
}

variable "installer_env" {
  description = "Extra environment variables for the installer. Keys must be valid shell names. A null or empty value is left out."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k in keys(var.installer_env) : can(regex("^[A-Za-z_][A-Za-z0-9_]*$", k))])
    error_message = "Every key in installer_env must be a valid shell variable name."
  }
}

variable "download_timeout" {
  description = "Optional. How long the installer may spend downloading. A bare number means seconds (for example 300), or use a Go duration (for example 5m)."
  type        = string
  default     = ""

  validation {
    condition     = var.download_timeout == "" || can(regex("^[0-9]+$", var.download_timeout)) || can(regex("^([0-9]+([.][0-9]+)?(ns|us|ms|s|m|h))+$", var.download_timeout))
    error_message = "download_timeout must be empty, a whole number of seconds, or a Go duration such as 5m."
  }
}

variable "trace" {
  description = "Turn on extra installer tracing."
  type        = bool
  default     = false
}

variable "log_to_console" {
  description = "Also print installer logs to the console."
  type        = bool
  default     = false
}

variable "report_version" {
  description = "Print the installer version into the log before installing."
  type        = bool
  default     = true
}

variable "verify_connection" {
  description = "After installing, check that the connector is connected."
  type        = bool
  default     = true
}

variable "verify_timeout" {
  description = "How many seconds the connection check may wait. Whole number, at least 10."
  type        = number
  default     = 180

  validation {
    condition     = var.verify_timeout >= 10 && floor(var.verify_timeout) == var.verify_timeout
    error_message = "verify_timeout must be a whole number of at least 10."
  }
}

variable "verify_strict" {
  description = "If the connection check fails, make the script exit with an error. When false, it only prints a warning."
  type        = bool
  default     = false
}

variable "log_file" {
  description = "The log file on the instance where the script writes its messages."
  type        = string
  default     = "/var/log/zn-segment-connector-terraform.log"
}

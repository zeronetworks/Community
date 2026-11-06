# Results of this module. The cloud modules read these values.
# Checks that depend on several inputs together are "preconditions" on install_script.
# If a check fails, the plan stops with the message written in that check.

# Terraform needs the "sensitive" flag to be a fixed true or false, not a choice made from
# an input. So the install script is always marked sensitive. It is only truly secret when
# token_source is "embedded", but marking it always is the safe choice.
output "install_script" {
  description = "The bash script that installs the Segment Connector. Always marked sensitive (hidden in plan output), because with token_source \"embedded\" it contains the token."
  value       = local.install_script
  sensitive   = true

  # Enrollment options (FQDN, name, static IP) are only for hosts not yet in the portal.
  precondition {
    condition     = !(var.asset_fqdn != "" || var.asset_name != "" || var.with_static_ip) || var.allow_create
    error_message = "asset_fqdn, asset_name and with_static_ip need allow_create = true. Enrollment options are only for hosts not yet in the portal."
  }

  # A static IP enrollment cannot also use an FQDN.
  precondition {
    condition     = !(var.with_static_ip && var.asset_fqdn != "")
    error_message = "with_static_ip cannot be combined with asset_fqdn. Use one or the other."
  }

  # A static IP enrollment needs a display name.
  precondition {
    condition     = !(var.with_static_ip && var.asset_name == "")
    error_message = "with_static_ip needs asset_name (the display name for the new asset)."
  }

  # The Key Vault source needs both the vault name and the secret name.
  precondition {
    condition     = var.token_source != "azure_key_vault" || (var.azure_key_vault_name != "" && var.azure_key_vault_secret_name != "")
    error_message = "token_source \"azure_key_vault\" needs azure_key_vault_name and azure_key_vault_secret_name."
  }

  # The embedded source needs a token to embed.
  precondition {
    condition     = var.token_source != "embedded" || trimspace(var.token) != ""
    error_message = "token_source \"embedded\" needs a non-empty token."
  }
}

output "uninstall_script" {
  description = "The bash script that removes the Segment Connector. It never contains the token."
  value       = local.uninstall_script
}

output "user_data" {
  description = "The script chosen by the action input (install_script by default, uninstall_script when action is \"uninstall\"), for use as cloud-init user data. Always marked sensitive."
  value       = var.action == "uninstall" ? local.uninstall_script : local.install_script
  sensitive   = true
}

output "install_args" {
  description = "The arguments passed to the installer on install, before quoting. Never contains the token."
  value       = local.install_args
}

output "script_sha256" {
  description = "SHA-256 of install_script. Changes when the script changes, so cloud modules can detect a new script. Always marked sensitive, because it is derived from install_script."
  value       = sha256(local.install_script)
  sensitive   = true
}

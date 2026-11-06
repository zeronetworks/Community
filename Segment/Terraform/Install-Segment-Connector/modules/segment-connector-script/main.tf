# Builds the Segment Connector install (or uninstall) shell script as text.
# Nothing is created in the cloud here. The cloud modules take the text and run it on hosts.

locals {
  # Step 1: copy the extra environment variables, dropping any that are empty or null.
  clean_env = { for name, value in var.installer_env : name => value if value != null && value != "" }

  # Step 2: named settings that switch on an environment variable.
  # A plain number of seconds is turned into a Go duration by adding "s" (600 becomes 600s).
  timeout_env = var.download_timeout == "" ? tomap({}) : tomap({
    ZN_SEGMENT_CONNECTOR_INSTALL_GET_PKG_TIMEOUT = can(regex("^[0-9]+$", var.download_timeout)) ? "${var.download_timeout}s" : var.download_timeout
  })
  trace_env   = var.trace ? tomap({ ZN_AGENT_INSTALLER_TRACE_ENABLED = "true" }) : tomap({})
  console_env = var.log_to_console ? tomap({ ZN_AGENT_INSTALLER_LOG_PRINT_TO_CONSOLE = "true" }) : tomap({})

  # Step 3: merge everything. Later entries win, so the named settings override installer_env.
  env = merge(local.clean_env, local.timeout_env, local.trace_env, local.console_env)

  # Lines the script runs to set each environment variable.
  # Each value is wrapped in single quotes. A single quote inside a value is written as '\''.
  env_lines = [
    for name in sort(keys(local.env)) :
    "export ${name}='${replace(local.env[name], "'", "'\\''")}'"
  ]

  # Arguments for the install run. The installer always gets -run-as.
  # Enrollment flags are only added when allow_create is true.
  enroll_args = var.allow_create ? concat(
    ["-allow-create"],
    var.with_static_ip ? ["-with-static-ip"] : (var.asset_fqdn == "" ? [] : ["-asset-fqdn", var.asset_fqdn]),
    var.asset_name == "" ? [] : ["-name", var.asset_name],
  ) : []

  install_args = concat(
    ["-run-as", var.run_as],
    var.force ? ["-force"] : [],
    var.asset_id == "" ? [] : ["-assetId", var.asset_id],
    local.enroll_args,
  )

  # Arguments for the uninstall run. Only -force is used.
  uninstall_args = var.force ? ["-force"] : []

  # Wrap each argument in single quotes so the shell reads it as one word.
  q_install_args   = [for arg in local.install_args : "'${replace(arg, "'", "'\\''")}'"]
  q_uninstall_args = [for arg in local.uninstall_args : "'${replace(arg, "'", "'\\''")}'"]

  # The token is only put into the script when token_source is "embedded".
  # The uninstall script never gets the token.
  token_b64 = var.token_source == "embedded" ? base64encode(var.token) : ""

  # Values the script template needs. Booleans are turned into the text "true" or "false".
  # The action is added per script below.
  common_vars = {
    staging_dir        = var.staging_dir
    identity_file      = var.identity_file
    installer_url      = var.installer_url
    installer_zip_path = var.installer_zip_path
    token_source       = var.token_source
    token_file_path    = var.token_file_path
    kv_name            = var.azure_key_vault_name
    kv_secret          = var.azure_key_vault_secret_name
    mi_client_id       = var.azure_managed_identity_client_id
    reinstall          = tostring(var.reinstall)
    q_install_args     = local.q_install_args
    q_uninstall_args   = local.q_uninstall_args
    env_lines          = local.env_lines
    report_version     = tostring(var.report_version)
    verify_connection  = tostring(var.verify_connection)
    verify_timeout     = var.verify_timeout
    verify_strict      = tostring(var.verify_strict)
    log_file           = var.log_file
  }

  # The full install script. It holds the token only when token_source is "embedded".
  install_script = templatefile("${path.module}/templates/segment-connector.sh.tftpl",
    merge(local.common_vars, { action = "install", token_b64 = local.token_b64 })
  )

  # The full uninstall script. It never holds the token.
  uninstall_script = templatefile("${path.module}/templates/segment-connector.sh.tftpl",
    merge(local.common_vars, { action = "uninstall", token_b64 = "" })
  )
}

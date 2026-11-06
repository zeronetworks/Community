# Installs the Segment Connector on Azure Linux VMs.
#
# What this file does, in order:
#   1. Builds the install script with the core module.
#   2. Uploads the installer zip and the script to a blob container.
#   3. Makes a short-lived read-only link (SAS) to that container.
#   4. Adds a CustomScript extension to each VM. The VM downloads the
#      two files and runs the script.

# ---------------------------------------------------------------
# Local values: names, the token setting, and the re-run number
# ---------------------------------------------------------------

locals {
  # Names of the two files in the blob container.
  script_blob_name = "segment-connector.sh"
  zip_blob_name    = basename(var.installer_zip_local_path)

  # The core script reads the token from an environment variable
  # (token_source "env") or from Key Vault (token_source "azure_key_vault").
  token_source = var.token_delivery == "key_vault" ? "azure_key_vault" : "env"

  # Fingerprint of the zip file. Used to decide when to re-run.
  zip_md5 = filemd5(var.installer_zip_local_path)

  # Text of the install script, from the core module.
  script_content = module.script.install_script

  # Number that changes when a re-run should happen. The extension sees
  # the change in its settings and runs the script again.
  # The number is taken from the first 7 hex digits of a SHA-1 hash, so it
  # always fits in a 32-bit integer.
  rerun_timestamp = parseint(substr(sha1(join("|", [
    sha1(local.script_content),
    local.zip_md5,
    var.reinstall_trigger,
    var.action,
  ])), 0, 7), 16)

  # Shell command the extension runs. The token goes in front as an
  # environment variable, but only when it is delivered this way.
  # Base64 keeps the token safe to put in a command line.
  token_prefix = var.token_delivery == "protected_settings" ? "ZN_SEGMENT_CONNECTOR_TOKEN_B64=${base64encode(var.token)} " : ""
  command      = "${local.token_prefix}/bin/bash ${local.script_blob_name}"

  # Managed identity settings for the extension. An empty client ID means
  # the VM's system-assigned identity is used.
  managed_identity = var.managed_identity_client_id == "" ? tomap({}) : tomap({
    clientId = var.managed_identity_client_id
  })

  # Read-only link suffix (starts with "?"). Empty in managed_identity mode,
  # where the VM reads the blobs with its own identity.
  sas_token = try(data.azurerm_storage_account_blob_container_sas.this[0].sas, "")

  # Download links the VM fetches. In SAS mode each link ends with the
  # suffix; in managed identity mode the suffix is empty.
  file_uris = [
    "${azurerm_storage_blob.script.url}${local.sas_token}",
    "${azurerm_storage_blob.installer.url}${local.sas_token}",
  ]
}

# ---------------------------------------------------------------
# Core module: builds the install script text
# ---------------------------------------------------------------

module "script" {
  source = "../segment-connector-script"

  action                           = var.action
  token_source                     = local.token_source
  azure_key_vault_name             = var.azure_key_vault_name
  azure_key_vault_secret_name      = var.azure_key_vault_secret_name
  azure_managed_identity_client_id = var.azure_managed_identity_client_id

  # The zip sits next to the script on the VM, so the script finds it
  # by its file name alone.
  installer_zip_path = local.zip_blob_name
  installer_url      = var.installer_url

  staging_dir   = var.staging_dir
  identity_file = var.identity_file
  run_as        = var.run_as
  force         = var.force

  # Any non-empty reinstall_trigger forces the install to run again.
  reinstall = var.reinstall_trigger != ""

  asset_id       = var.asset_id
  asset_fqdn     = var.asset_fqdn
  asset_name     = var.asset_name
  allow_create   = var.allow_create
  with_static_ip = var.with_static_ip
  installer_env  = var.installer_env

  download_timeout = var.download_timeout
  trace            = var.trace
  log_to_console   = var.log_to_console

  report_version    = var.report_version
  verify_connection = var.verify_connection
  verify_timeout    = var.verify_timeout
  verify_strict     = var.verify_strict
  log_file          = var.log_file
}

# ---------------------------------------------------------------
# Storage: the zip and the script go into an existing container
# ---------------------------------------------------------------

# The storage account must already exist. This data source looks it up.
data "azurerm_storage_account" "this" {
  name                = var.storage_account_name
  resource_group_name = var.storage_resource_group_name
}

# The installer zip. Terraform uploads it from the local file.
resource "azurerm_storage_blob" "installer" {
  name                   = local.zip_blob_name
  storage_account_name   = var.storage_account_name
  storage_container_name = var.storage_container_name
  type                   = "Block"
  source                 = var.installer_zip_local_path

  # A checksum of the file, so Azure can check the upload.
  content_md5 = local.zip_md5
}

# The install script. Terraform uploads the text from the core module.
resource "azurerm_storage_blob" "script" {
  name                   = local.script_blob_name
  storage_account_name   = var.storage_account_name
  storage_container_name = var.storage_container_name
  type                   = "Block"
  source_content         = local.script_content
}

# ---------------------------------------------------------------
# Download link (SAS): a time-limited, read-only key for the container
# ---------------------------------------------------------------

# A fixed time point. It is set when Terraform first creates it and is
# only renewed when the re-run trigger or the link lifetime changes. This
# keeps the plan steady between runs.
resource "time_static" "sas" {
  triggers = {
    reinstall_trigger = var.reinstall_trigger
    sas_hours         = tostring(var.sas_hours)
  }
}

# The read-only link for the container. The "sas" value starts with "?".
# Only created when blob_download = "sas".
data "azurerm_storage_account_blob_container_sas" "this" {
  count = var.blob_download == "sas" ? 1 : 0

  connection_string = data.azurerm_storage_account.this.primary_connection_string
  container_name    = var.storage_container_name

  # Start 15 minutes early, so a VM whose clock is a little behind still
  # gets a valid link.
  start  = timeadd(time_static.sas.rfc3339, "-15m")
  expiry = timeadd(time_static.sas.rfc3339, "${var.sas_hours}h")

  # The provider needs every permission listed. Only read is allowed,
  # which is all the VM needs to download the files.
  permissions {
    read   = true
    add    = false
    create = false
    write  = false
    delete = false
    list   = false
  }
}

# ---------------------------------------------------------------
# VM extension: runs the script on each VM
# ---------------------------------------------------------------

resource "azurerm_virtual_machine_extension" "script" {
  # One extension per VM. The key is the VM's resource ID.
  for_each = var.virtual_machine_ids

  name               = var.extension_name
  virtual_machine_id = each.value

  # Azure's own CustomScript extension for Linux, version 2.1.
  publisher            = "Microsoft.Azure.Extensions"
  type                 = "CustomScript"
  type_handler_version = "2.1"

  # Public settings. Only the re-run number goes here, because public
  # settings are not encrypted. The token must never go in this block.
  settings = jsonencode({
    timestamp = local.rerun_timestamp
  })

  # Protected settings are encrypted in transit and on the VM. The file
  # links, the command, and the managed identity go here.
  # Azure does not allow a managed identity together with a storage key or
  # link, so the two modes build different settings.
  protected_settings = var.blob_download == "managed_identity" ? jsonencode({
    fileUris         = local.file_uris
    commandToExecute = local.command
    managedIdentity  = local.managed_identity
    }) : jsonencode({
    fileUris         = local.file_uris
    commandToExecute = local.command
  })

  timeouts {
    create = "${var.timeout_minutes}m"
  }

  lifecycle {
    # With token_delivery = "protected_settings", a token must be given.
    precondition {
      condition     = var.token_delivery != "protected_settings" || var.token != ""
      error_message = "token must be set when token_delivery is \"protected_settings\"."
    }
  }
}

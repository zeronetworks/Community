# This file builds the AWS side of the connector install.
#
# How it works, in plain steps:
# 1. Terraform uploads three files to S3: the installer zip, a shell script and the token.
# 2. Terraform creates an SSM "document". A document is a list of steps that SSM runs on each instance.
# 3. Terraform creates an SSM "association". It tells SSM to run the document on the listed instances.
# 4. On each instance, the steps download the three files, then run the script.
#    The token is kept in an encrypted S3 file, not in the document, because SSM documents
#    cannot read SecureString parameters.

# Looks up the AWS region. Used to build the S3 web address the instances download from.
data "aws_region" "current" {}

# Looks up the AWS partition (for example "aws" or "aws-us-gov"). Used to build ARNs.
data "aws_partition" "current" {}

locals {
  # ----- S3 file locations -----

  # The S3 keys (paths inside the bucket) for each file.
  installer_key = "${var.key_prefix}segment-connector-linux-installer.zip"
  script_key    = "${var.key_prefix}segment-connector.sh"
  token_key     = var.token_s3_key != "" ? var.token_s3_key : "${var.key_prefix}enrollment.dat"

  # Only the file names, without the folders. These are the names used on the instance.
  installer_file = basename(local.installer_key)
  script_file    = basename(local.script_key)
  token_file     = basename(local.token_key)

  # The full paths of the files on the instance.
  installer_path = "${var.staging_dir}/${local.installer_file}"
  script_path    = "${var.staging_dir}/${local.script_file}"
  token_path     = "${var.staging_dir}/${local.token_file}"

  # The web addresses the instances download the files from.
  installer_s3_url = "https://${var.bucket_name}.s3.${data.aws_region.current.name}.amazonaws.com/${local.installer_key}"
  script_s3_url    = "https://${var.bucket_name}.s3.${data.aws_region.current.name}.amazonaws.com/${local.script_key}"
  token_s3_url     = "https://${var.bucket_name}.s3.${data.aws_region.current.name}.amazonaws.com/${local.token_key}"

  # ----- Encryption settings for the S3 uploads -----

  # Use the KMS key if one is set. Otherwise use S3's default encryption.
  s3_encryption = var.kms_key_id == "" ? "AES256" : "aws:kms"
  s3_kms_key    = var.kms_key_id == "" ? null : var.kms_key_id

  # ----- The script the instances run -----

  # Pick the install or uninstall version of the script from the shared module.
  chosen_script = var.action == "uninstall" ? module.script.uninstall_script : module.script.install_script

  # A fingerprint of the token. Used to detect token changes without storing the token itself.
  # It is only a fingerprint, so changing the token value forces a new run.
  token_version = var.token_s3_key != "" ? "external:${var.token_s3_key}" : nonsensitive(sha256(var.token))

  # ----- The SSM document steps -----

  # Step 1: make the staging folder, and make it readable only by root.
  step_prepare = {
    action = "aws:runShellScript"
    name   = "prepareStagingFolder"
    inputs = {
      runCommand = [
        "set -eu",
        "umask 077",
        "mkdir -p '${var.staging_dir}'",
        "chmod 0700 '${var.staging_dir}'",
      ]
    }
  }

  # Step 2: download the installer zip from S3.
  # The sourceInfo field is a JSON text that holds the S3 web address.
  step_download_installer = {
    action         = "aws:downloadContent"
    name           = "downloadInstallerZip"
    timeoutSeconds = var.execution_timeout_seconds
    onFailure      = "Abort"
    inputs = {
      sourceType      = "S3"
      sourceInfo      = jsonencode({ path = local.installer_s3_url })
      destinationPath = var.staging_dir
    }
  }

  # Step 3: download the script from S3.
  step_download_script = {
    action         = "aws:downloadContent"
    name           = "downloadScript"
    timeoutSeconds = var.execution_timeout_seconds
    onFailure      = "Abort"
    inputs = {
      sourceType      = "S3"
      sourceInfo      = jsonencode({ path = local.script_s3_url })
      destinationPath = var.staging_dir
    }
  }

  # Step 4: download the encrypted token file from S3.
  step_download_token = {
    action         = "aws:downloadContent"
    name           = "downloadToken"
    timeoutSeconds = var.execution_timeout_seconds
    onFailure      = "Abort"
    inputs = {
      sourceType      = "S3"
      sourceInfo      = jsonencode({ path = local.token_s3_url })
      destinationPath = var.staging_dir
    }
  }

  # Step 5: check the three files are there, lock down the token file, then run the script.
  # The script reads the token and deletes the token file when it is done.
  step_run_script = {
    action         = "aws:runShellScript"
    name           = "runInstallerScript"
    timeoutSeconds = var.execution_timeout_seconds
    onFailure      = "Abort"
    inputs = {
      runCommand = [
        "set -eu",
        "umask 077",
        "test -f '${local.installer_path}'",
        "test -f '${local.script_path}'",
        "test -f '${local.token_path}'",
        "chmod 0600 '${local.token_path}'",
        "bash '${local.script_path}'",
      ]
    }
  }

  # ----- IAM policy for the instance role -----

  s3_arn_prefix = "arn:${data.aws_partition.current.partition}:s3:::${var.bucket_name}"

  # The instances may read the files under the key prefix.
  # If the token was uploaded outside Terraform, its exact key is allowed too.
  read_resources = concat(
    ["${local.s3_arn_prefix}/${var.key_prefix}*"],
    var.token_s3_key == "" ? [] : ["${local.s3_arn_prefix}/${var.token_s3_key}"],
  )

  policy_statements = concat(
    [
      {
        Sid      = "ReadConnectorFiles"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = local.read_resources
      },
    ],
    var.kms_key_id == "" ? [] : [
      {
        Sid      = "DecryptConnectorFiles"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.kms_key_id]
      },
    ],
    var.output_s3_key_prefix == "" ? [] : [
      {
        Sid      = "WriteCommandOutput"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${local.s3_arn_prefix}/${var.output_s3_key_prefix}*"]
      },
    ],
  )
}

# ----- Shared script module -----

# This module builds the bash script text. It does not create any AWS resources.
module "script" {
  source = "../segment-connector-script"

  # The token is read from a file on the instance, so token_source is "file".
  token_source    = "file"
  token_file_path = local.token_path

  # The installer zip sits in the same folder as the script.
  installer_zip_path = local.installer_file

  # Shared options, passed straight through.
  action            = var.action
  staging_dir       = var.staging_dir
  identity_file     = var.identity_file
  run_as            = var.run_as
  force             = var.force
  installer_url     = var.installer_url
  asset_id          = var.asset_id
  asset_fqdn        = var.asset_fqdn
  asset_name        = var.asset_name
  allow_create      = var.allow_create
  with_static_ip    = var.with_static_ip
  installer_env     = var.installer_env
  download_timeout  = var.download_timeout
  trace             = var.trace
  log_to_console    = var.log_to_console
  report_version    = var.report_version
  verify_connection = var.verify_connection
  verify_timeout    = var.verify_timeout
  verify_strict     = var.verify_strict
  log_file          = var.log_file

  # Any non-empty reinstall trigger means "reinstall".
  reinstall = var.reinstall_trigger != ""
}

# ----- S3 uploads -----

# The installer zip. The instances download this file.
resource "aws_s3_object" "installer" {
  bucket                 = var.bucket_name
  key                    = local.installer_key
  source                 = var.installer_zip_local_path
  source_hash            = filemd5(var.installer_zip_local_path)
  server_side_encryption = local.s3_encryption
  kms_key_id             = local.s3_kms_key
}

# The script text. The instances download this file.
resource "aws_s3_object" "script" {
  bucket                 = var.bucket_name
  key                    = local.script_key
  content                = local.chosen_script
  server_side_encryption = local.s3_encryption
  kms_key_id             = local.s3_kms_key
}

# The token, uploaded by Terraform. Only created when token_s3_key is empty.
resource "aws_s3_object" "token" {
  count = var.token_s3_key == "" ? 1 : 0

  bucket                 = var.bucket_name
  key                    = local.token_key
  content                = var.token
  server_side_encryption = local.s3_encryption
  kms_key_id             = local.s3_kms_key

  lifecycle {
    # Stop with a clear message if no token was given.
    precondition {
      condition     = var.token != ""
      error_message = "Set the token variable, or set token_s3_key to a token file you uploaded yourself."
    }
  }
}

# ----- SSM document -----

# The SSM document: the list of steps that SSM runs on each instance.
# It contains no secrets and no parameters.
resource "aws_ssm_document" "install" {
  name            = var.document_name
  document_type   = "Command"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Downloads and runs the Zero Networks Segment Connector installer from S3."
    mainSteps = [
      local.step_prepare,
      local.step_download_installer,
      local.step_download_script,
      local.step_download_token,
      local.step_run_script,
    ]
  })
}

# ----- Rerun trigger -----

# A value that changes whenever something that matters changes.
# When it changes, the association below is replaced, so SSM runs the document again.
resource "terraform_data" "rerun" {
  input = sha1(join("|", [
    local.chosen_script,
    filemd5(var.installer_zip_local_path),
    local.token_version,
    var.reinstall_trigger,
    var.action,
    aws_ssm_document.install.latest_version,
  ]))
}

# ----- SSM association -----

# Tells SSM to run the document on the listed instances.
resource "aws_ssm_association" "install" {
  name             = aws_ssm_document.install.name
  document_version = aws_ssm_document.install.latest_version

  targets {
    key    = "InstanceIds"
    values = var.instance_ids
  }

  # Wait this long for SSM to report success, then fail the apply if it did not.
  wait_for_success_timeout_seconds = var.wait_for_success_timeout_seconds

  # Optional: save the command output to S3.
  dynamic "output_location" {
    for_each = var.output_s3_key_prefix == "" ? [] : [1]
    content {
      s3_bucket_name = var.bucket_name
      s3_key_prefix  = var.output_s3_key_prefix
    }
  }

  # When the rerun value changes, replace the association so SSM runs it again.
  lifecycle {
    replace_triggered_by = [terraform_data.rerun.output]
  }
}

# ----- IAM policy for the instance role (optional) -----

# The policy text. Only the connector files and (if set) the KMS key are allowed.
# Created even when no role name is given, so you can attach it yourself.
locals {
  instance_read_policy_json = jsonencode({
    Version   = "2012-10-17"
    Statement = local.policy_statements
  })
}

# Attaches the policy to the instance role. Only created when instance_role_name is set.
resource "aws_iam_role_policy" "instance_read" {
  count = var.instance_role_name == "" ? 0 : 1

  name   = "zn-segment-connector-read"
  role   = var.instance_role_name
  policy = local.instance_read_policy_json
}

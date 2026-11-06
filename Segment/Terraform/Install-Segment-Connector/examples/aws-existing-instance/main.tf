# Installs the Segment Connector on an EC2 instance that already exists.
# This example does not create or change the instance. It only adds the SSM document and association.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# AWS access. Set AWS_PROFILE or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or use "aws configure".
provider "aws" {
  region = var.region
}

# Look up the existing instance by its ID.
data "aws_instance" "vm" {
  instance_id = var.instance_id
}

# Run the Segment Connector install on that instance through SSM.
module "segment_connector" {
  source = "../../modules/aws-ec2"

  # The instance to install on. This module can take more than one instance.
  instance_ids = [data.aws_instance.vm.id]

  # The S3 bucket that holds the zip and the script. The instance reads them from here.
  bucket_name = var.bucket_name
  kms_key_id  = var.kms_key_id

  # The role of the instance. Terraform adds the read policy to it when this is set.
  # If the role is in another account, leave it empty and attach the instance_read_policy_json output yourself.
  instance_role_name = var.instance_role_name

  # The installer zip on your computer, and the token from the portal.
  installer_zip_local_path = var.installer_zip_local_path
  token                    = var.token

  # Enrollment options. Leave them at the defaults for a host already in the portal.
  allow_create   = var.allow_create
  asset_fqdn     = var.asset_fqdn
  asset_name     = var.asset_name
  with_static_ip = var.with_static_ip

  # Other options.
  run_as            = var.run_as
  reinstall_trigger = var.reinstall_trigger
}

# Shows the command to view the SSM output for this instance.
output "how_to_view_output" {
  description = "Command that shows the install output for this instance."
  value       = module.segment_connector.how_to_view_output
}

output "association_id" {
  description = "ID of the SSM association that runs the install."
  value       = module.segment_connector.association_id
}

output "instance_read_policy_json" {
  description = "IAM policy the instance role needs to read the zip and the script. Attach it yourself if instance_role_name was left empty."
  value       = module.segment_connector.instance_read_policy_json
}

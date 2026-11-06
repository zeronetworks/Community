# WARNING: NOT RECOMMENDED FOR PRODUCTION.
# This example puts the token into the EC2 instance's user data, in plain text.
# Anyone who can read the instance's attributes can read the token.
# The script runs only once, at first boot. A later reinstall needs another path (Azure or SSM).
# Use it only for short-lived test machines, and rotate the token afterwards.

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

# Find the latest Ubuntu 22.04 image from Canonical.
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Build the install script with the core module. It does not talk to AWS.
# The token is embedded in the script, and the script downloads the zip from installer_url.
module "script" {
  source = "../../modules/segment-connector-script"

  action        = "install"
  token_source  = "embedded"
  token         = var.token
  installer_url = var.installer_url

  allow_create   = var.allow_create
  asset_fqdn     = var.asset_fqdn
  asset_name     = var.asset_name
  with_static_ip = var.with_static_ip
  run_as         = var.run_as
}

# The test instance. Cloud-init runs the script once, at first boot.
resource "aws_instance" "vm" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type

  # The script with the token inside it. Anyone who can read the instance's user data can read the token.
  user_data = module.script.user_data

  tags = {
    Name = var.instance_name
  }
}

output "instance_id" {
  description = "ID of the test instance."
  value       = aws_instance.vm.id
}

# Creates a small test EC2 instance with the right IAM role, then installs the Segment Connector on it through SSM.
# It also creates the S3 bucket the installer files are uploaded to.

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

# The S3 bucket for the installer zip and the script. Public access is blocked.
resource "aws_s3_bucket" "bucket" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_public_access_block" "bucket" {
  bucket                  = aws_s3_bucket.bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# An IAM role the instance uses. It lets the instance talk to SSM.
resource "aws_iam_role" "ssm" {
  name = "${var.instance_name}-ssm-role"

  # Only EC2 can use this role.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# The standard AWS policy that lets an instance register with SSM.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# The instance profile is the wrapper that lets EC2 attach the role to an instance.
resource "aws_iam_instance_profile" "ssm" {
  name = "${var.instance_name}-ssm-profile"
  role = aws_iam_role.ssm.name
}

# The test instance. It uses the default VPC unless you set subnet_id.
resource "aws_instance" "vm" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = var.instance_type
  subnet_id            = var.subnet_id
  iam_instance_profile = aws_iam_instance_profile.ssm.name

  tags = {
    Name = var.instance_name
  }
}

# Run the Segment Connector install on the test instance through SSM.
module "segment_connector" {
  source = "../../modules/aws-ec2"

  instance_ids = [aws_instance.vm.id]

  # The bucket created above, and the role that the instance uses.
  bucket_name        = aws_s3_bucket.bucket.bucket
  instance_role_name = aws_iam_role.ssm.name

  # The installer zip on your computer, and the token from the portal.
  installer_zip_local_path = var.installer_zip_local_path
  token                    = var.token

  # Enrollment. A new instance is not in the portal yet, so it needs allow_create.
  allow_create   = var.allow_create
  asset_fqdn     = var.asset_fqdn
  asset_name     = var.asset_name
  with_static_ip = var.with_static_ip

  run_as            = var.run_as
  reinstall_trigger = var.reinstall_trigger

  # Install only after the instance exists and its SSM permissions are in place.
  depends_on = [aws_instance.vm, aws_iam_role_policy_attachment.ssm, aws_s3_bucket_public_access_block.bucket]
}

# Shows the command to view the SSM output for the test instance.
output "how_to_view_output" {
  description = "Command that shows the install output for the test instance."
  value       = module.segment_connector.how_to_view_output
}

output "instance_id" {
  description = "ID of the test instance."
  value       = aws_instance.vm.id
}

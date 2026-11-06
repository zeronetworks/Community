# This file says which Terraform and provider versions this module needs.

terraform {
  # Modules need Terraform 1.5 or newer. The tests need 1.7 or newer.
  required_version = ">= 1.5.0"

  required_providers {
    # The AWS provider creates the S3 files, the SSM document and the SSM association.
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

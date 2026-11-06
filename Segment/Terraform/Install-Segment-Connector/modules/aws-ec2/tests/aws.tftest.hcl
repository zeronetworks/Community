# Plan-only tests for the AWS EC2 module.
# They use a fake AWS provider, so no AWS account or credentials are needed.
# Run them with: terraform test   (needs Terraform 1.7 or newer)

# A fake AWS provider. It returns fixed values for the region and partition
# so the expected ARNs and URLs can be checked exactly.
mock_provider "aws" {
  mock_data "aws_region" {
    defaults = {
      name = "us-east-1"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }
}

# Values used by every test run unless a run overrides them.
variables {
  instance_ids             = ["i-0123456789abcdef0"]
  bucket_name              = "example-bucket"
  token                    = "TEST-ONLY-TOKEN-VALUE-0001"
  installer_zip_local_path = "tests/fixtures/placeholder-installer.bin"
}

# Test 1: the default setup (token uploaded by Terraform, no KMS key).
run "default_install_plan" {
  command = plan

  # The document steps must run in this exact order.
  assert {
    condition = jsonencode([
      for s in jsondecode(aws_ssm_document.install.content).mainSteps : s.action
      ]) == jsonencode([
      "aws:runShellScript",
      "aws:downloadContent",
      "aws:downloadContent",
      "aws:downloadContent",
      "aws:runShellScript",
    ])
    error_message = "The SSM document steps are not in the expected order."
  }

  # The download steps must name the S3 files and use the S3 source type.
  assert {
    condition = alltrue([
      for s in jsondecode(aws_ssm_document.install.content).mainSteps :
      jsondecode(s.inputs.sourceInfo).path != null && s.inputs.sourceType == "S3"
      if s.action == "aws:downloadContent"
    ])
    error_message = "Every download step must use sourceType S3 and a sourceInfo JSON with a path."
  }

  # The download addresses must point at the right keys in the bucket.
  assert {
    condition = jsondecode(
      [for s in jsondecode(aws_ssm_document.install.content).mainSteps : s.inputs.sourceInfo if s.name == "downloadToken"][0]
    ).path == "https://example-bucket.s3.us-east-1.amazonaws.com/zn-segment-connector/enrollment.dat"
    error_message = "The token download address is wrong."
  }

  # The association must target the instance IDs we passed in.
  assert {
    condition     = aws_ssm_association.install.targets[0].key == "InstanceIds"
    error_message = "The association must target InstanceIds."
  }

  assert {
    condition     = jsonencode(aws_ssm_association.install.targets[0].values) == jsonencode(tolist(["i-0123456789abcdef0"]))
    error_message = "The association must target the instance IDs given in instance_ids."
  }

  assert {
    condition     = aws_ssm_association.install.wait_for_success_timeout_seconds == 1200
    error_message = "The association must wait 1200 seconds for success by default."
  }

  # The token file must be uploaded with S3's default encryption.
  assert {
    condition     = aws_s3_object.token[0].server_side_encryption == "AES256"
    error_message = "The token object must be encrypted (AES256 by default)."
  }

  # The token must not appear in the SSM document, in the script, or in the policy.
  assert {
    condition     = !strcontains(aws_ssm_document.install.content, "TEST-ONLY-TOKEN-VALUE-0001")
    error_message = "The token must not appear in the SSM document content."
  }

  assert {
    condition     = !strcontains(aws_s3_object.script.content, "TEST-ONLY-TOKEN-VALUE-0001")
    error_message = "The token must not appear in the script text."
  }

  assert {
    condition     = !strcontains(output.instance_read_policy_json, "TEST-ONLY-TOKEN-VALUE-0001")
    error_message = "The token must not appear in the IAM policy."
  }

  # The document must not contain "{{", which SSM would read as a parameter.
  assert {
    condition     = !strcontains(aws_ssm_document.install.content, "{{")
    error_message = "The SSM document must not contain {{ ."
  }

  # The document must not declare any parameters.
  assert {
    condition     = !contains(keys(jsondecode(aws_ssm_document.install.content)), "parameters")
    error_message = "The SSM document must not declare parameters."
  }

  # The instance read policy must only allow reading under the key prefix.
  assert {
    condition     = jsonencode(jsondecode(output.instance_read_policy_json).Statement[0].Resource) == jsonencode(tolist(["arn:aws:s3:::example-bucket/zn-segment-connector/*"]))
    error_message = "The read policy must be limited to the zn-segment-connector/ key prefix."
  }

  assert {
    condition     = jsonencode(jsondecode(output.instance_read_policy_json).Statement[0].Action) == jsonencode(tolist(["s3:GetObject"]))
    error_message = "The read policy must only allow s3:GetObject."
  }

  # Without a KMS key, the policy must not mention KMS.
  assert {
    condition     = length(jsondecode(output.instance_read_policy_json).Statement) == 1
    error_message = "Without a KMS key the policy should have only the S3 read statement."
  }
}

# Test 2: a KMS key is set, so the files and the policy must use it.
run "kms_encrypted_plan" {
  command = plan

  variables {
    kms_key_id = "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555"
  }

  assert {
    condition     = aws_s3_object.token[0].server_side_encryption == "aws:kms"
    error_message = "With a KMS key the token object must use aws:kms encryption."
  }

  assert {
    condition     = aws_s3_object.script.kms_key_id == "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555"
    error_message = "The script object must use the KMS key."
  }

  assert {
    condition     = jsonencode(jsondecode(output.instance_read_policy_json).Statement[1].Action) == jsonencode(tolist(["kms:Decrypt"]))
    error_message = "With a KMS key the policy must allow kms:Decrypt on that key."
  }
}

# Test 3: the token was uploaded outside Terraform. Terraform must not create or store it.
run "external_token_plan" {
  command = plan

  variables {
    token        = ""
    token_s3_key = "outside/enrollment.dat"
  }

  assert {
    condition     = length(aws_s3_object.token) == 0
    error_message = "With token_s3_key set, Terraform must not create the token object."
  }

  # The external token's exact key must be allowed in the read policy.
  assert {
    condition     = contains(jsondecode(output.instance_read_policy_json).Statement[0].Resource, "arn:aws:s3:::example-bucket/outside/enrollment.dat")
    error_message = "The read policy must allow the external token key."
  }

  # The token download must use the external key.
  assert {
    condition = jsondecode(
      [for s in jsondecode(aws_ssm_document.install.content).mainSteps : s.inputs.sourceInfo if s.name == "downloadToken"][0]
    ).path == "https://example-bucket.s3.us-east-1.amazonaws.com/outside/enrollment.dat"
    error_message = "The token download must use token_s3_key."
  }
}

# Test 4: no token and no external key must fail with a clear error.
run "missing_token_fails" {
  command = plan

  variables {
    token = ""
  }

  expect_failures = [
    aws_s3_object.token,
  ]
}

# Test 5: uninstall keeps the same document and association, with a different action.
run "uninstall_plan" {
  command = plan

  variables {
    action = "uninstall"
  }

  assert {
    condition     = aws_ssm_association.install.targets[0].key == "InstanceIds"
    error_message = "Uninstall must still target InstanceIds."
  }
}

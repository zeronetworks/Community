# Example: install on an existing EC2 instance

Installs the Segment Connector on an EC2 instance that already exists. It uses AWS Systems Manager (SSM) to run the install script on the instance. It does not create or change the instance.

Read the [project README](../../README.md) first. It explains Terraform basics, the token handling and the security notes.

## What it creates

- An S3 object for the installer zip and one for the script, in the bucket you name. The token is uploaded as its own encrypted object unless you set `token_s3_key` in the module.
- An SSM document that runs the script, and an SSM association that runs the document on the instance.
- An IAM policy that lets the instance read the S3 objects, attached to `instance_role_name` if you set it.

## Before you start

- The instance must be managed by SSM. It needs SSM Agent running, and an instance profile with the `AmazonSSMManagedInstanceCore` policy.
- The instance needs outbound access to SSM and S3 in its region.
- The bucket must already exist, in the same region as the instance.

## Steps

1. Put the installer zip in the project's `installer/` folder.
2. Copy the settings file and fill it in:

   ```sh
   cp terraform.tfvars.example terraform.tfvars
   ```

3. Set the token in your shell. Do not put it in `terraform.tfvars`:

   ```sh
   export TF_VAR_token='<paste token from the portal>'
   ```

4. Run the commands:

   ```sh
   terraform init
   terraform plan
   terraform apply
   ```

5. Check the output. The `how_to_view_output` value shows the command to run. Or run:

   ```sh
   aws ssm list-command-invocations --details --instance-id <instance-id>
   ```

   The status should be `Success`. The output includes the script's own output.

## Notes

- If `instance_role_name` is empty, attach the `instance_read_policy_json` output to the instance's role yourself. Without it, the instance cannot read the files and the install fails.
- Changing the script or the zip and running `apply` again should rerun the SSM association. This has not been checked yet (see the [caveats](../../README.md#caveats-and-testing-status)).
- Nothing in this example has been run against a real AWS account yet.

# Example: create a test EC2 instance and install the Segment Connector

Creates a small Ubuntu 22.04 EC2 instance, an IAM role for SSM, and an S3 bucket. Then it installs the Segment Connector on the instance through SSM. Use it to try the AWS path on a test account.

Read the [project README](../../README.md) first. It explains Terraform basics, the token handling and the security notes.

## What it creates

- An S3 bucket with public access blocked.
- An IAM role with the `AmazonSSMManagedInstanceCore` policy, and an instance profile for it.
- A `t3.micro` Ubuntu 22.04 instance in the default VPC (or the subnet you set).
- The S3 objects for the zip and the script, the SSM document and association, and the read policy on the role.

## Steps

1. Put the installer zip in the project's `installer/` folder.
2. Copy the settings file and fill it in. Pick a bucket name that is unique in AWS:

   ```sh
   cp terraform.tfvars.example terraform.tfvars
   ```

3. Set the token in your shell. Do not put it in `terraform.tfvars`:

   ```sh
   export TF_VAR_token='<paste token from the portal>'
   ```

4. Run the commands. The install waits for the instance, the role and the bucket settings (`depends_on`):

   ```sh
   terraform init
   terraform plan
   terraform apply
   ```

5. Check the output with the `how_to_view_output` command, or:

   ```sh
   aws ssm list-command-invocations --details --instance-id <instance-id>
   ```

## Notes

- The instance needs a few minutes to boot and register with SSM. The association may need a short wait before it runs. The timing on a first boot has not been checked.
- The default VPC must have outbound access to SSM and S3. If you use a custom subnet, check its routes.
- Remove the test resources when you finish. `terraform destroy` removes the instance, but it does **not** uninstall the agent first. Run the uninstall action before you destroy, if you want a clean removal from the portal too.
- Nothing in this example has been run against a real AWS account yet. See the [caveats](../../README.md#caveats-and-testing-status).

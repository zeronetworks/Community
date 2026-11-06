# Example: install through EC2 user data (not recommended)

Creates an EC2 instance whose first-boot script (user data) installs the Segment Connector. It uses the core module directly, with `token_source = "embedded"`. The script downloads the zip from `installer_url`.

> **Not recommended for production.** The token is written into the instance's user data in plain text.
> Anyone who can read the instance attributes can read it, and it is also in the Terraform state.
> The script runs once, at first boot. Changing the script later does not reinstall the agent, and this example has no reinstall path.
> Use it only for short-lived test machines. Rotate the token afterwards. Prefer the Azure or SSM examples.

Read the [project README](../../README.md) first. It explains Terraform basics and the security notes.

## What it creates

- One `t3.micro` Ubuntu 22.04 EC2 instance in the default VPC, with the install script as its user data.

It creates no IAM role and no S3 bucket. The zip is fetched from `installer_url` instead.

## Steps

1. Put the installer zip somewhere the instance can download it over `https://` without a login. A pre-signed S3 URL works. Set the expiry long enough to cover the first boot.
2. Copy the settings file and fill it in, including `installer_url`:

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

5. Wait a few minutes for the first boot. Then check the log on the instance, `/var/log/zn-segment-connector-terraform.log`, or the installer logs described in the [project README](../../README.md#troubleshooting).

## Notes

- Cloud-init runs the script once, at first boot. If it fails, you cannot re-run it from Terraform. Connect to the instance and run the script again by hand, or replace the instance.
- The user data has a size limit (16 KB for EC2). The rendered script is close to that limit. If `apply` says the user data is too large, use the SSM example instead.
- Terraform stores the user data, including the token, in the state. Protect the state (see the [project README](../../README.md#security-notes)).
- Nothing in this example has been run against a real AWS account yet. See the [caveats](../../README.md#caveats-and-testing-status).

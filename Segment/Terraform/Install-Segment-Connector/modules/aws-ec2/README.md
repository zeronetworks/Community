# AWS EC2 module

This module installs the Zero Networks Segment Connector on Linux EC2 instances.
It uses AWS Systems Manager (SSM). You do not need SSH access to the instances.

## What it creates

1. Three files in an S3 bucket:
   - the installer zip,
   - a shell script that runs the installer,
   - the enrollment token (encrypted).
2. An SSM **document**. This is a list of steps that SSM runs on each instance.
3. An SSM **association**. This tells SSM to run the document on your instances.

On each instance, the steps do this in order:

1. Make a private staging folder (readable by root only).
2. Download the installer zip from S3.
3. Download the script from S3.
4. Download the token file from S3.
5. Check the three files are there, lock the token file, and run the script.

The token is never written into the SSM document. SSM documents cannot read
SecureString parameters, so the token travels in an encrypted S3 file instead.

## Before you start

- Each instance needs **SSM Agent** running.
- Each instance needs an **IAM instance profile** with the managed policy
  `AmazonSSMManagedInstanceCore` attached.
- The instances need outbound network access to the SSM endpoints and to S3.
- You need the Segment Connector Linux installer zip on your computer.
- You need an enrollment token from the Zero Networks portal.

## Example

```hcl
module "connector" {
  source = "./modules/aws-ec2"

  instance_ids             = ["i-0123456789abcdef0"]
  bucket_name              = "my-connector-bucket"
  installer_zip_local_path = "/path/to/segment-connector-linux-installer.zip"

  # Safer option: upload the token file yourself, then point to it.
  token_s3_key = "zn-segment-connector/enrollment.dat"

  # Optional: let the instance role read the files.
  instance_role_name = "my-ec2-instance-role"
}
```

To keep the token in Terraform instead, leave `token_s3_key` empty and set
`token` (for example from a `TF_VAR_token` environment variable or a
`*.tfvars` file that is not committed).

Example token file setup, before the first apply (only with `token_s3_key`):

```bash
aws s3 cp enrollment.dat s3://my-connector-bucket/zn-segment-connector/enrollment.dat \
  --sse AES256
```

## Inputs

### AWS-specific

| Name | What it does | Default |
| --- | --- | --- |
| `instance_ids` | EC2 instance IDs to install on. **Required.** | - |
| `bucket_name` | S3 bucket for the files. **Required.** | - |
| `installer_zip_local_path` | Path on your computer to the installer zip. **Required.** | - |
| `token` | Enrollment token. Sensitive. Used only when `token_s3_key` is empty. | `""` |
| `token_s3_key` | S3 key of a token file you uploaded yourself. Terraform then does not store the token. | `""` |
| `key_prefix` | Folder prefix for the S3 files. Must end with `/`. | `zn-segment-connector/` |
| `kms_key_id` | KMS key ARN for encrypting the S3 files. Empty means AES256. | `""` |
| `instance_role_name` | IAM role to attach the read-only policy to. Empty means no attachment. | `""` |
| `document_name` | SSM document name. Must be unique per account and region. | `zn-segment-connector-install` |
| `execution_timeout_seconds` | Time limit for each SSM step. | `1800` |
| `wait_for_success_timeout_seconds` | How long Terraform waits for SSM success before failing. | `1200` |
| `output_s3_key_prefix` | Optional S3 folder in the same bucket for SSM command output. | `""` |
| `reinstall_trigger` | Any non-empty text forces the installer to run again. | `""` |

### Shared script options

These match the core script module. The defaults are the same.

| Name | What it does |
| --- | --- |
| `action` | `install` or `uninstall`. |
| `staging_dir` | Folder on the instance for the downloaded files. |
| `identity_file`, `log_file` | Files on the instance for the connector identity and the log. |
| `run_as` | `zn-user` or `root`. |
| `force` | Pass the force flag to the installer. |
| `installer_url` | Optional `https://` address. If set, the instance uses it instead of the S3 copy. |
| `asset_id`, `asset_fqdn`, `asset_name` | Asset details. `asset_fqdn` and `asset_name` need `allow_create`. |
| `allow_create`, `with_static_ip` | Asset creation options. |
| `installer_env` | Extra environment variables for the installer. |
| `download_timeout`, `trace`, `log_to_console` | Installer logging and download options. |
| `report_version` | Log the installer version first. |
| `verify_connection`, `verify_timeout`, `verify_strict` | Connection check after install. |

Not offered here: the Azure key vault options and the managed identity options.
They do not apply to SSM.

## Outputs

| Name | What it shows |
| --- | --- |
| `association_id` | The SSM association ID. |
| `document_name` | The SSM document name. |
| `script_sha256` | A fingerprint of the script text. |
| `instance_read_policy_json` | The read-only IAM policy, if you want to attach it yourself. |
| `how_to_view_output` | An AWS CLI command that lists the SSM runs. |

To see the results on the instances:

```bash
aws ssm list-command-invocations --details \
  --filters key=DocumentName,value=zn-segment-connector-install
```

## Security notes

- **The token is stored in the Terraform state** when `token_s3_key` is empty.
  Keep the state file private. Using `token_s3_key` avoids this.
- The token is encrypted in S3 (AES256, or your KMS key if you set `kms_key_id`).
- The token file is deleted by the script after it is read.
- The IAM policy only allows reading the connector files under `key_prefix`
  (and the token key, if you set `token_s3_key`).

## Limits and notes

- Changing `action`, `reinstall_trigger`, the token, the installer zip or the
  script causes SSM to run the document again on all listed instances.
- The SSM document name must be unique per account and region.
- If an instance is not managed by SSM, the association fails and the apply
  fails after `wait_for_success_timeout_seconds`.
- Uploading a KMS-encrypted output to S3 needs more permissions than this policy grants.
  Add them yourself if you use `output_s3_key_prefix` with a KMS bucket.

## Tests

The tests use a fake AWS provider, so no AWS account is needed. They check the
step order, the download addresses, the encryption, the association targets, that the
token is not in the document, and that the IAM policy is limited to the key prefix.

```bash
cd modules/aws-ec2
terraform init -backend=false
terraform test
```

Terraform 1.7 or newer is needed for the tests. The module itself needs Terraform 1.5 or newer.

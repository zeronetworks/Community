# Install the Zero Networks Segment Connector (Linux) with Terraform

Installs, reinstalls, and uninstalls the Zero Networks **Segment Connector** (the Linux lightweight agent) with Terraform.
It is a Terraform port of the [Ansible installer](../../Ansible/Install-Segment-Connector/README.md) in this repository.
It runs `segment-connector-linux-installer` from the installer zip you download from the Zero Networks portal.
Terraform does the work on each VM: it uploads the zip and a small bash script, then runs the script on the VM through Azure or AWS.

> **Read before you run.** This is a community example. Test it in a non-production environment first.
> Nothing in this project has run against a real Azure or AWS account yet. See [Caveats and testing status](#caveats-and-testing-status).

## Contents

```
Install-Segment-Connector/
├── README.md                              This file
├── .gitignore                             Keeps tokens, state, tfvars and installer zips out of git
├── installer/                             Put the installer zip here (zip files are not committed)
│   └── .gitkeep                           Keeps the empty folder in git
├── modules/
│   ├── segment-connector-script/          Core module: builds the install and uninstall scripts (no cloud access)
│   ├── azure-vm/                          Runs the script on Azure VMs (Custom Script Extension)
│   └── aws-ec2/                           Runs the script on EC2 instances (AWS Systems Manager)
├── templates/
│   └── segment-connector.sh.tftpl         The bash script that runs on the VM
├── examples/
│   ├── azure-existing-vm/                 Install on a VM that already exists in Azure
│   ├── azure-new-vm/                      Create a test Azure VM, then install
│   ├── aws-existing-instance/             Install on an EC2 instance that already exists
│   ├── aws-new-instance/                  Create a test EC2 instance, then install
│   └── user-data-only/                    Install at first boot through EC2 user data (not recommended)
└── tests/
    ├── run-offline-tests.sh               Runs all the free checks (needs Docker only for the install test)
    ├── docker/fake-installer/             Fake installer used by the Docker test
    └── build/                             Test output (ignored by git)
```

**On this page**

- [Terraform in 5 minutes](#terraform-in-5-minutes)
- [Which path to choose](#which-path-to-choose)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Adding it to existing Terraform](#adding-it-to-existing-terraform)
- [Common runs](#common-runs)
- [Variables](#variables)
- [How it works](#how-it-works)
- [Security notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Testing it yourself](#testing-it-yourself)
- [Caveats and testing status](#caveats-and-testing-status)
- [License](#license)

## Terraform in 5 minutes

Terraform reads `.tf` files and makes your cloud match them. You do not run commands on the VM yourself.

**Modules.** A module is a folder of `.tf` files that you call from another configuration. This project has three modules in `modules/`. The core module builds the script. The Azure and AWS modules run that script on your VMs. The examples in `examples/` call them with `source = "../../modules/<name>"`.

**The four commands.** Run them from the example folder you are using:

| Command | What it does |
|---|---|
| `terraform init` | Downloads the cloud provider plugins. Run it once, and again after you change providers. |
| `terraform plan` | Shows what would change. It changes nothing. Read it before you apply. |
| `terraform apply` | Makes the change. It asks you to type `yes`. |
| `terraform destroy` | Removes what Terraform created. It does **not** uninstall the Segment Connector from the VM. See [How it works](#how-it-works). |

**State.** Terraform keeps a record of what it made in a file called `terraform.tfstate`. This file can contain secrets, including the token, so:

- Do not commit it. The `.gitignore` covers it.
- For anything beyond a test, store it in an **encrypted remote backend** with limited access, such as an Azure Storage account with encryption and RBAC, or an S3 bucket with encryption, versioning and a bucket policy. Add a `backend` block to the example's `main.tf` (see the Terraform backend documentation for your cloud).

**Variables and environment variables.** A variable can be set in three ways. The first one wins:

1. `-var "name=value"` on the command line.
2. A `terraform.tfvars` file in the example folder. Copy `terraform.tfvars.example` to `terraform.tfvars` and edit it.
3. An environment variable named `TF_VAR_<name>`. This is the way to pass the token.

```sh
export TF_VAR_token='<paste token from the portal>'
```

The token is marked sensitive, so Terraform hides it in the plan output. It is still stored in the state (see [Security notes](#security-notes)).

## Which path to choose

Pick one path per VM. Each example in `examples/` is one path.

| Path | Use it when | How the script reaches the VM | Example |
|---|---|---|---|
| **Azure Custom Script Extension** | The VM runs in Azure. | Azure runs the script as the VM's `CustomScript` extension. | `azure-existing-vm`, `azure-new-vm` |
| **AWS Systems Manager (SSM)** | The instance runs in EC2, or the VM is a non-AWS machine enrolled as an SSM hybrid node. | SSM runs the script with `AWS-RunShellScript`-style commands. | `aws-existing-instance`, `aws-new-instance` |
| **User data (cloud-init)** | You are creating a new EC2 instance and cannot use SSM. | Runs once, at first boot, from the instance's user data. | `user-data-only` (**not recommended**) |

**User data is not recommended.** The token is written into the instance's user data in plain text. Anyone who can read the instance's attributes can read the token. The script also runs only at first boot, so a later reinstall needs another path. Use it only for short-lived test machines.

## Prerequisites

**Your computer (the Terraform controller)**

- Terraform **1.5 or later**. The module tests need 1.7 or later.
- Azure CLI (`az`) signed in with `az login`, or the `ARM_*` environment variables for Azure. The Azure module and examples use the azurerm **3.x** provider (`>= 3.0, < 4.0`). Set `ARM_SUBSCRIPTION_ID` if the provider cannot find your subscription.
- AWS credentials for the account, for example through `aws configure`, `AWS_PROFILE`, or environment variables.
- Docker, only if you want to run the [tests](#testing-it-yourself).

**Zero Networks portal**

1. Download the Segment Connector installer zip at **Settings > Segment > Segment Connector**. Put it in `installer/`.
2. Generate an installation token in the same place. Keep it in a password manager. You will paste it into `TF_VAR_token`.

**Cloud permissions**

- **Azure:** permission to read the VM, to create a VM extension on it, to read the storage account, and to upload blobs to the storage container. The default path creates a SAS token from the storage account key, so the signed-in identity needs to be able to list keys on that account.
- **AWS:** permission to upload to the S3 bucket, to create SSM documents and associations, and to create IAM policies on the instance role. The instance needs an instance profile with the `AmazonSSMManagedInstanceCore` policy, plus outbound access to SSM and S3.

**VM requirements**

- Use a Linux distribution from the supported list. The list and the runtime packages the agent needs are in the Ansible README: see [Supported platforms](../../Ansible/Install-Segment-Connector/README.md#supported-platforms) and [Target host requirements](../../Ansible/Install-Segment-Connector/README.md#target-host-requirements). The Terraform project does not install those packages for you.
- The VM runs as root or with `sudo`. The script checks that it runs as root.
- For AWS, SSM Agent must be installed and running on the instance. Most current Amazon and Ubuntu images include it.

**Network**

- **Outbound TCP 443** from the VM to the Zero Networks segment server. The installer registers with it and downloads the connector package from it.
- **DNS** that works from the VM. The VM must resolve the segment server's name. The connector also does DNS **TXT** lookups, so public DNS must be reachable (UDP and TCP 53).
- **Cloud endpoints:** for Azure, the VM needs to reach the storage account and the Azure instance metadata address (`169.254.169.254`). For AWS, the VM needs to reach the SSM and S3 endpoints in its region.

## Quick start

These two quick starts use the **existing VM** examples. They change only the VM's extension or SSM association. They do not create a VM.

### Azure: existing VM

1. Go to the example folder:

   ```sh
   cd examples/azure-existing-vm
   ```

2. Copy the example settings and fill them in: the VM name, its resource group, the storage account and container, and the zip file name.

   ```sh
   cp terraform.tfvars.example terraform.tfvars
   ```

   Put the zip in the project's `installer/` folder, as described in [Prerequisites](#prerequisites).

3. Set the token. Do not put it in `terraform.tfvars`:

   ```sh
   export TF_VAR_token='<paste token from the portal>'
   ```

4. Run the four commands:

   ```sh
   terraform init
   terraform plan
   terraform apply
   ```

   Read the plan first. It should show a storage blob, a few storage and script resources, and one `azurerm_virtual_machine_extension` for the VM.

5. See the result. The `apply` output shows `how_to_view_output`. Run the command it shows, or:

   ```sh
   az vm extension show --resource-group <vm-rg> --vm-name <vm-name> --name zn-segment-connector --instance-view
   ```

   The extension's `substatus` and `statuses` show whether the script finished. The script's own output is in the log file on the VM (see [Troubleshooting](#troubleshooting)).

### AWS: existing instance

1. Go to the example folder:

   ```sh
   cd examples/aws-existing-instance
   ```

2. Copy and fill in `terraform.tfvars.example`: the instance ID, the S3 bucket to use for the zip and script, and the zip file name. If the instance's role is in this account, set `instance_role_name` to that role's name so Terraform can attach the read policy for you.

   ```sh
   cp terraform.tfvars.example terraform.tfvars
   ```

3. Set the token:

   ```sh
   export TF_VAR_token='<paste token from the portal>'
   ```

4. Run the commands:

   ```sh
   terraform init
   terraform plan
   terraform apply
   ```

5. See the result. The `apply` output shows `how_to_view_output`. Run it, or:

   ```sh
   aws ssm list-command-invocations --details --instance-id <instance-id>
   ```

   The command output includes the script's output. Check its status is `Success`.

## Adding it to existing Terraform

Do not copy the example folder into your project. Call the module from your own configuration. Pass the VM's ID, and the module handles the rest.

**Azure VM you already manage in Terraform:**

```hcl
module "segment_connector" {
  source = "<path or git URL to>/modules/azure-vm"

  virtual_machine_ids = [azurerm_linux_virtual_machine.x.id]

  storage_account_name        = "<your storage account>"
  storage_resource_group_name = "<its resource group>"
  storage_container_name      = "<its container>"

  installer_zip_local_path = "<path to the zip>"
  token                    = var.segment_connector_token
}
```

**EC2 instance you already manage in Terraform:**

```hcl
module "segment_connector" {
  source = "<path or git URL to>/modules/aws-ec2"

  instance_ids = [aws_instance.x.id]
  bucket_name  = "<your S3 bucket>"

  installer_zip_local_path = "<path to the zip>"
  token                    = var.segment_connector_token
}
```

Add `depends_on` if the instance is created in the same configuration and the module must wait for it. The module already depends on the instance ID, so Terraform usually orders the work correctly without it.

## Common runs

These are the same options as the Ansible runs. The Ansible equivalent is in the [Variables](#variables) table. Set each option in `terraform.tfvars`, or add it to the module call.

| Task | Setting |
|---|---|
| Install | Nothing extra. |
| Auto-enroll a host that is not yet in the portal (the portal picks the FQDN) | `allow_create = true` |
| Enroll with an explicit FQDN | `allow_create = true` and `asset_fqdn = "connector01.example.com"` |
| Enroll with a static IP | `allow_create = true`, `with_static_ip = true`, `asset_name = "connector01"` |
| Slow download link (raise the package download timeout to 600 seconds) | `download_timeout = "600"` |
| Debugging (installer trace logging) | `trace = true` |
| Reinstall (the installer runs again) | `reinstall = true`, or change `reinstall_trigger` to a new value |
| Reinstall and force (replace a conflicting assetId) | `reinstall = true` and `force = true` |
| Run the connector as root instead of zn-user | `run_as = "root"` |
| Uninstall | Set `action = "uninstall"` and apply |
| Uninstall with force (if unregistration fails) | `action = "uninstall"` and `force = true` |

**Reinstall with `reinstall_trigger`.** On the cloud modules, `reinstall_trigger` is a string. When you change its value, Terraform reruns the install. It is the easiest way to force a reinstall without remembering the other settings. Use a new value each time, such as `"2026-11-04-a"`.

**Uninstall.** Set `action = "uninstall"` on the module and apply. The uninstall reuses the installer that the install left in the staging directory on the VM. If that directory is gone, the script downloads the zip again, so `installer_zip_local_path` or `installer_url` must still work.

## Variables

Set these in `terraform.tfvars`, in the module call, or with `TF_VAR_<name>`. The core module (`modules/segment-connector-script`) has all of them. The Azure and AWS modules pass them through with the same names, plus the extra inputs in the second table.

"Ansible name" is the matching Ansible variable, `segment_connector_<name>`. "Terraform only" means there is no Ansible equivalent.

| Variable | Required | Default | Ansible name | Description |
|---|---|---|---|---|
| **Required** | | | | |
| `token` | Yes | `""` (sensitive) | `segment_connector_token` | Installation token from the portal. Set it with `TF_VAR_token`. Never commit it. Used by the installer as `-token`. |
| `installer_zip_local_path` | Yes, unless `installer_url` is set | `"segment-connector-linux-installer.zip"` | `package_filename` / `package_path` | Path to the zip on your computer. A relative path is read from the folder you run Terraform in. The cloud modules use this name for the zip. |
| **What to run** | | | | |
| `action` | No | `"install"` | Playbook choice | `"install"` or `"uninstall"`. |
| `run_as` | No | `"zn-user"` | `segment_connector_run_as` | `zn-user` or `root`. Passed to the installer as `-run-as`. |
| `force` | No | `false` | `segment_connector_force` | Pass `-force` to the installer. On install, it replaces a conflicting assetId. On uninstall, it is used when unregistration fails. |
| `reinstall` | No | `false` | `segment_connector_reinstall` | Run the installer even when the connector is already installed. |
| `reinstall_trigger` | No | `""` | Terraform only | Cloud modules only. Any non-empty value turns on `reinstall`. Changing the value reruns the install. |
| **Package and paths** | | | | |
| `installer_url` | No | `""` | Terraform only | An `https://` link to the zip, for example a pre-signed URL. When set, the VM downloads the zip from here instead of using `installer_zip_local_path`. |
| `staging_dir` | No | `"/opt/zn-segment-connector-setup"` | `segment_connector_staging_dir` | Folder on the VM where the zip and installer are extracted. |
| `identity_file` | No | `"/var/zeronetworks/.zn-internal/identity.json"` | `segment_connector_identity_file` | File the installer writes on success. If it exists, the install is skipped unless `reinstall = true`. |
| `log_file` | No | `"/var/log/zn-segment-connector-terraform.log"` | Terraform only | Log file on the VM that the script writes to. |
| **Enrollment** | | | | |
| `asset_id` | No | `""` | `segment_connector_asset_id` | Existing asset ID to attach to (installer flag `-assetId`). Takes precedence over matching by FQDN. |
| `allow_create` | No | `false` | `segment_connector_allow_create` | Let the portal create a new asset when none matches (installer flag `-allow-create`). |
| `asset_fqdn` | No | `""` | `segment_connector_asset_fqdn` | FQDN for the new asset (installer flag `-asset-fqdn`). Must contain a dot and must not be an IP address. Requires `allow_create`. Cannot be combined with `with_static_ip`. |
| `asset_name` | No | `""` | `segment_connector_asset_name` | Display name for the new asset (installer flag `-name`). Requires `allow_create`. Required with `with_static_ip`. |
| `with_static_ip` | No | `false` | `segment_connector_with_static_ip` | Enroll using the source IP the portal sees (installer flag `-with-static-ip`). Requires `allow_create` and `asset_name`. Cannot be combined with `asset_fqdn`. |
| **Installer environment** | | | | |
| `installer_env` | No | `{}` | `segment_connector_installer_env` | Extra environment variables for every installer call. Keys must look like shell names (letters, digits, underscores). Null or empty values are dropped. |
| `download_timeout` | No | `""` | `segment_connector_download_timeout` | Package download timeout. A bare number such as `"600"` is seconds. Go durations such as `"10m"` also work. Empty uses the installer default. |
| `trace` | No | `false` | `segment_connector_trace` | Turn on installer trace logging. For debugging. |
| `log_to_console` | No | `false` | `segment_connector_log_to_console` | Print installer log lines in the Terraform or cloud output. The lines are not redacted. Leave it off unless you are debugging. |
| **Checks** | | | | |
| `report_version` | No | `true` | `segment_connector_report_version` | Run `<installer> -version` on the VM before install or uninstall, and print the result. Never fails the run. |
| `verify_connection` | No | `true` | `segment_connector_verify_connection` | Run the connection check after an install. Also runs as a health check when the install is skipped. |
| `verify_timeout` | No | `180` | `segment_connector_verify_timeout` | Seconds to wait for the connection after an install. Whole number, at least 10. |
| `verify_strict` | No | `false` | `segment_connector_verify_strict` | Fail the run instead of warning when the connector does not connect. |

### Extra inputs on the cloud modules

These apply to `modules/azure-vm` and `modules/aws-ec2`. The module's own README has the full list.

| Variable | Module | Default | Description |
|---|---|---|---|
| `virtual_machine_ids` | azure-vm | (required) | Set of VM resource IDs to install on. One script runs per VM. |
| `instance_ids` | aws-ec2 | (required) | List of EC2 instance IDs to install on. |
| `storage_account_name`, `storage_resource_group_name`, `storage_container_name` | azure-vm | (required) | Storage account and container that hold the zip and script for the VMs to download. |
| `bucket_name` | aws-ec2 | (required) | S3 bucket that holds the zip and script for the instances to download. |
| `token_delivery` | azure-vm | `"protected_settings"` | How the token reaches the VM. `"protected_settings"` puts it in the encrypted extension settings. `"key_vault"` reads it from Azure Key Vault on the VM. |
| `blob_download` | azure-vm | `"sas"` | How the VM downloads from the storage container. `"sas"` uses a short-lived SAS token. `"managed_identity"` uses the VM's identity. |
| `sas_hours` | azure-vm | `4` | How long the SAS token is valid. |
| `extension_name` | azure-vm | `"zn-segment-connector"` | Name of the VM extension. |
| `key_prefix` | aws-ec2 | `"zn-segment-connector/"` | Folder in the bucket for the zip and script. |
| `token_s3_key` | aws-ec2 | `""` | Stronger option: the S3 key of a token file that you upload outside Terraform. If set, Terraform does not store the token in the state. |
| `kms_key_id` | aws-ec2 | `""` | KMS key to encrypt the objects in the bucket. |
| `instance_role_name` | aws-ec2 | `""` | IAM role of the instance. Terraform adds the read policy to it. If empty, attach the `instance_read_policy_json` output yourself. |
| `execution_timeout_seconds`, `wait_for_success_timeout_seconds` | aws-ec2 | `1800`, `1200` | How long SSM may run the script, and how long Terraform waits for it to finish. |
| `output_s3_key_prefix` | aws-ec2 | `""` | Optional S3 folder where SSM stores the command output. |

### Enrollment rules

The core module checks these rules when you run `plan`. The installer checks them again on the VM.

- `asset_name` requires `allow_create = true`.
- `asset_fqdn` requires `allow_create = true`. It must contain a dot and must not be an IP address. It cannot be combined with `with_static_ip`.
- `with_static_ip = true` requires `allow_create = true` and a non-empty `asset_name`.
- `token_source = "azure_key_vault"` needs a Key Vault name and secret name. `token_source = "embedded"` needs a non-empty `token`.

## How it works

### Install, skip, or reinstall

The script on the VM first checks the identity file (`identity_file`, default `/var/zeronetworks/.zn-internal/identity.json`).

- **File exists, `reinstall` is false:** the connector is already installed. The script skips the installer and runs one health check. Re-running `apply` is therefore a quick check.
- **File missing, or `reinstall` is true:** the script gets the zip, extracts the installer, runs it with the token, and then checks the connection.

The host is matched to a portal asset in the same way as the Ansible installer. See the Ansible README for the full order: [How the host is matched to a portal asset](../../Ansible/Install-Segment-Connector/README.md#how-the-host-is-matched-to-a-portal-asset).

### Connection check

After an install, the script reads the connector's log on the VM and reports whether it reached the segment server. The states and the wait loop match the Ansible connection check. Full details: [Connection check](../../Ansible/Install-Segment-Connector/README.md#connection-check).

| State | Meaning |
|---|---|
| `operational` | Connected, and the segment server has told it to start collecting. |
| `connected` | Connected to the segment server. The collector can take about a minute to start. |
| `failing` | The last thing in the log is a connection error. |
| `not_started` | No new connector start and no connection result since the install began. |
| `unknown` | The log has no usable connection information. |

A warning with the state and the last error is printed if the connector is not connected in time. The run still succeeds unless `verify_strict = true`. The final line of the script is `ZN_SEGMENT_CONNECTOR_RESULT action=<action> state=<state> version=<version>`.

### Uninstall lifecycle

- **Uninstall is an action, not a destroy.** Set `action = "uninstall"` on the module and apply. The script unregisters the agent and removes the staging folder.
- **Removing the module does not uninstall the agent.** If you delete the module from your configuration, or run `terraform destroy`, Terraform removes its own resources (the extension, the SSM association, the uploaded files). The Segment Connector stays installed and running on the VM. Run the uninstall action first if you want it removed.
- **`terraform destroy` on the VM** removes the VM itself, which also removes the agent from that machine. The portal asset may still need to be removed in the portal.

## Security notes

- **The token is stored in the Terraform state in plain text.** Terraform stores every input it used, including the token, in the state file. Encrypt the state and limit who can read it. Use an encrypted remote backend with access control (see [Terraform in 5 minutes](#terraform-in-5-minutes)).
- **Azure `protected_settings`.** The token is sent in the VM extension's protected settings. Azure encrypts these settings at rest, and they are not shown in the normal extension output.
- **AWS encrypted S3 object.** The token file is uploaded to S3 with server-side encryption. The instance reads it with a policy that allows only that object. Set `kms_key_id` to use your own KMS key.
- **The token is visible briefly in process arguments.** The installer takes the token as a command-line argument (`-token`). For a short time, the token can be seen by other users on the VM with `ps`. This is how the installer works. The Ansible installer has the same behavior.
- **Stronger options.** Upload the token yourself to the bucket, outside Terraform, and set `token_s3_key`. Then Terraform never stores the token. For Azure, use `token_delivery = "key_vault"` and keep the token in Key Vault. The VM reads it with its managed identity.
- **User data is weak.** The user-data path puts the token in plain text in the instance's user data. Do not use it for production. See [Which path to choose](#which-path-to-choose).
- **Never commit `terraform.tfvars` or the token.** Commit only `*.tfvars.example`. Before each commit, run `git status` and check that no `.zip`, `.tfstate`, `.tfvars` or token file is listed. The `.gitignore` covers these, but it does not check for you.
- The script never turns on shell tracing (`set -x`), so the token is not printed to the log.

## Troubleshooting

The script writes its own log on the VM, and the installer writes its logs in `/var/zeronetworks/logs/`.

| Where | What it holds |
|---|---|
| `/var/log/zn-segment-connector-terraform.log` | The script's own log. Start here. It is the `log_file` variable. |
| `/var/zeronetworks/logs/installer.log` | The installer's log. When the installer fails, the script prints the last 50 lines and some hints. |
| `/var/zeronetworks/logs/install-script.log` | Written by the installer itself. Check it when `installer.log` does not explain the failure. |
| `/var/zeronetworks/logs/zn-segment-connector.log` | The connector's log. The connection check reads this file. |
| Azure: `/var/lib/waagent/custom-script/download/N/` | Where the Custom Script Extension keeps its stdout and stderr files (`N` is a number, and the highest one is the newest run). |
| AWS: SSM command output | `aws ssm list-command-invocations --details --instance-id <id>`, or the output location set by `output_s3_key_prefix`. |

Check the service on the VM with `systemctl status zn-segment-connector`.

For the hint text and the symptom table, see [Troubleshooting](../../Ansible/Install-Segment-Connector/README.md#troubleshooting). The script prints the same hints, using the Terraform variable names.

**Terraform errors** (these happen during `plan` or before the VM is touched):

| Message | Fix |
|---|---|
| `asset_fqdn must ...` or `asset_name requires allow_create` | Fix the enrollment settings. See [Enrollment rules](#enrollment-rules). |
| `token must be set` or `token is required for token_source=embedded` | Set `TF_VAR_token`. |
| `installer_zip_local_path` file not found | The zip is not in the path you gave. Check the path is relative to the folder you run Terraform from. |
| Provider or authentication errors | Check `az login`, `ARM_SUBSCRIPTION_ID`, or your AWS credentials. |

## Testing it yourself

The project has its own test script. You can run most of it for free, and only the install test needs Docker. Nothing needs a cloud account until the last two steps.

| Step | What it checks | Needs |
|---|---|---|
| T1 | `terraform fmt -check` and `terraform validate` for every module and example | Terraform |
| T2 | `tflint` for common mistakes | tflint |
| T3 | Core module tests with `terraform test` (Terraform 1.7 or later) | Terraform 1.7+ |
| T4 | Cloud module tests with mock providers (no cloud account) | Terraform 1.7+ |
| T5 | `shellcheck` on the rendered script | shellcheck |
| T6 | A fake installer run in Docker. Checks the install, skip, reinstall and uninstall paths, and the connection-check states. | Docker |
| T9 | Run the rendered script on an existing Linux VM you control. It uses the real installer. | A Linux test VM |
| T10 | Enroll a VM outside AWS as an SSM hybrid node, then run the AWS path on it. | A non-AWS test VM and an SSM hybrid activation |
| T11 | A real smoke test on a `t3.micro` or `B1s` VM. Costs under $1. | An AWS or Azure account |

Run the free checks (T1 to T6) with:

```sh
tests/run-offline-tests.sh
```

The script builds a fake installer zip in `tests/build/`, which is ignored by git. It never commits or copies a real installer.

The Docker test (T6) runs the script against the fake installer in a container. It records what the fake installer was called with, so you can check that the token and flags were passed correctly.

## Caveats and testing status

This is a community example. Test it in a non-production environment first. Confirm support with Zero Networks before you use it in production.

### Tested

Only the offline checks were run. They are the T1 to T6 steps above, run locally against the fake installer. Nothing has been run against a real Azure or AWS account.

### Not tested

- **Nothing has run against a real cloud yet.** No example has been applied to Azure or AWS. The Azure Custom Script Extension, the SSM document and association, and the S3 flow are all unverified in a live account.
- **Azure CSE `fileUris` with SAS and managed identity.** The download with a SAS token, and with the VM's managed identity, has not been run.
- **One extension per VM.** Azure allows only one `CustomScript` extension on a VM. If the VM already has one, the install fails. Remove the other extension first, or use a different VM.
- **SSM `downloadContent`.** The download of the zip from S3 through `aws:downloadContent` has not been run.
- **Association re-run.** Changing the script and running `apply` again should rerun the SSM association. This has not been checked.
- **Instance profile and KMS.** The instance role setup, and the `kms_key_id` option, have not been checked.
- **Key Vault and IMDS flow.** The `key_vault` token path, which reads the token on the VM with the managed identity, has not been run.
- **Proxies and private endpoints.** Not tested. A proxy or private endpoint between the VM and the segment server, SSM, S3 or Azure Storage may need extra setup.
- **The real installer.** Every test used a fake installer. The real `segment-connector-linux-installer` has not been run by this code, on any distribution. The connection check reads the connector's log, so it also depends on messages that were never seen from this code.
- **Other distributions.** The script ran against the fake installer in Rocky 9, Ubuntu 24.04, Debian 12 and Amazon Linux 2023 containers, without systemd. The examples use Ubuntu 22.04. See the supported list in the Ansible README.
- **Azure storage account settings.** The SAS link is built from the storage account connection string, so shared key access must be enabled on the storage account. This has not been checked against an account that has it disabled. The Azure module also needs the azurerm 3.x provider.
- **SSM document details.** The `destinationPath` of `aws:downloadContent` is treated as a folder, and `sourceInfo` is passed as a JSON string. The AWS docs are not explicit about either, and neither has been run. The document fails loudly if the downloaded file is missing.
- **The token in process arguments.** The installer receives the token as a command-line argument, so it is visible in the process list for the length of the run. The Ansible role behaves the same way. On Azure, `commandToExecute` also carries the token briefly.
- **Connector reaching the segment server from the cloud.** The VM's route to the segment server, and its DNS (including TXT lookups), have not been checked from a cloud network.
- **Destroy behaviour.** Removing the module or running `terraform destroy` does not uninstall the agent. The exact behaviour of each destroy step is not yet tested end to end.
- **Installer versions.** No installer version has been tested with this code. The Ansible project verified its connection check with installer 1.2.22.0 only.

## License

See the LICENSE file at the root of this repository.

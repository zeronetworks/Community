# Azure VM module

Installs the Zero Networks Segment Connector on existing Linux virtual machines
in Azure. The module uploads the installer and an install script to a blob
container, then adds one Azure **CustomScript** extension to each VM. The
extension downloads the two files and runs the script on the VM.

The install logic itself lives in the core module,
`../segment-connector-script`. This module only handles the Azure side.

## What you need before you start

- Terraform 1.5 or newer. Running the tests needs 1.7 or newer.
- An existing storage account and a blob container in it. The module does
  not create them.
- An existing Linux VM for each target. Each VM must be able to reach the
  storage account (or Key Vault) and the Zero Networks service.
- The installer zip on your computer, from the Zero Networks portal.
- The enrollment token from the Zero Networks portal. Keep it out of Git.
- Azure permissions to read the storage account keys and to write blobs.
- Azure allows only one CustomScript extension per VM. If a VM already has
  one, remove it or pick a different `extension_name` ahead of time.

## How to use it

Write a root module that calls this module:

```hcl
module "segment_connector" {
  source = "./modules/azure-vm"

  virtual_machine_ids         = ["/subscriptions/.../virtualMachines/vm-one"]
  storage_account_name        = "mystorageaccount"
  storage_resource_group_name = "rg-storage"
  storage_container_name      = "zn-installer"
  installer_zip_local_path    = "segment-connector-linux-installer.zip"

  token = var.zn_token   # set this in a .tfvars file or environment variable
}
```

Then run:

```sh
terraform init
terraform plan
terraform apply
```

Use `*.tfvars.example` as a template for your own `*.tfvars`. Do not commit a
real `*.tfvars` file, the installer zip, or the token.

## How the token is delivered

Two ways, set with `token_delivery`:

| Value | What happens | Where the token lives |
|---|---|---|
| `protected_settings` (default) | The token is part of the extension's protected settings. Azure encrypts them in transit and on the VM. | In the Terraform state file, in plain text. Keep the state file private. |
| `key_vault` | The VM reads the token from an Azure Key Vault secret at install time, using its managed identity. | Never in Terraform state. You create the secret yourself. |

For `key_vault`, set `azure_key_vault_name` and `azure_key_vault_secret_name`,
and give the VM's identity the "get secret" permission on the vault. Set
`azure_managed_identity_client_id` if the VM uses a user-assigned identity.

## How the VM downloads the files

Set with `blob_download`:

- `sas` (default): Terraform creates a read-only link to the container that
  lasts `sas_hours` (default 4). The VM uses that link. The link is stored in
  the extension's protected settings.
- `managed_identity`: the VM reads the blobs with its own identity. Give that
  identity the "Storage Blob Data Reader" role on the container. Set
  `managed_identity_client_id` for a user-assigned identity, or leave it empty
  for the system-assigned one.

## Re-running the install

- The script runs when the extension is first created.
- It runs again when the script, the installer zip, or `action` changes.
- To force a re-run on every VM, change `reinstall_trigger` to any new text.
- The script does nothing if the connector is already enrolled, unless a
  re-run is forced. A forced re-run sets the installer's reinstall flag.
- A new `reinstall_trigger` also renews the download link.

## Uninstalling

Set `action = "uninstall"` and apply. The same extension is updated with the
uninstall script, which removes the connector from the VM. Removing the
extension with `terraform destroy` does not uninstall the connector.

## Checking the result

Terraform prints the commands in the `how_to_view_output` output. Run one to
see what the script printed on that VM:

```sh
az vm extension show --resource-group <rg> --vm-name <vm> --name zn-segment-connector --instance-view
```

The script also writes a log file on the VM at `log_file`
(default `/var/log/zn-segment-connector-terraform.log`).

## Options

The main options are in `variables.tf`. Most of them are passed straight to the
core module with the same names. See `../segment-connector-script/README.md`
for what each one does. The ones specific to Azure are:

| Name | Default | What it does |
|---|---|---|
| `virtual_machine_ids` | (required) | Full resource IDs of the VMs. |
| `storage_account_name` | (required) | Existing storage account. |
| `storage_resource_group_name` | (required) | Resource group of that storage account. |
| `storage_container_name` | (required) | Existing blob container. |
| `installer_zip_local_path` | (required) | Local path to the installer zip. |
| `token` | `""` | Enrollment token. Needed for `protected_settings`. Sensitive. |
| `token_delivery` | `protected_settings` | `protected_settings` or `key_vault`. |
| `blob_download` | `sas` | `sas` or `managed_identity`. |
| `sas_hours` | `4` | How long the download link works. |
| `extension_name` | `zn-segment-connector` | Name of the VM extension. |
| `timeout_minutes` | `30` | How long to wait for each extension to finish. |
| `reinstall_trigger` | `""` | Change it to force a re-run. |

## Tests

```sh
cd modules/azure-vm
terraform init -backend=false
terraform test
```

The tests use mock providers, so they do not touch Azure. They check the
extension's publisher, type and version, that the token is only in the
protected settings, that each VM gets one extension, and that
`reinstall_trigger` changes the timestamp.

## Things to know

- The token sits in the command line of the extension while the script runs.
  Anyone on the VM with access to the process list can see it during that
  short window. `key_vault` avoids this.
- The module does not create the storage container or the Key Vault.
- Terraform only uploads the installer zip if you pass it in. If you use
  `installer_url` instead, the uploaded zip is not used.

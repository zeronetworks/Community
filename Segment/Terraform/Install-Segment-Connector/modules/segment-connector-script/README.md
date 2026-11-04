# segment-connector-script

This module builds a bash script that installs (or removes) the Zero Networks
Segment Connector on a Linux host. It is the shared core for the cloud modules.
The module itself creates nothing. It only produces text: a script, the installer
arguments, and a checksum. A cloud module (for example `azure-vm` or `aws-ec2`)
takes the script and runs it on the host.

It is a Terraform port of the Ansible role in `Segment/Ansible/Install-Segment-Connector`.
Each input is named after the Ansible setting it replaces (for example
`segment_connector_run_as` becomes `run_as`).

## What it needs

- Terraform 1.5 or newer. The tests need 1.7 or newer.
- No cloud provider. This module has no `provider` block.
- The installer zip from the Zero Networks portal (Settings > Segment > Segment Connector),
  either at a path you give (`installer_zip_path`) or at an HTTPS link (`installer_url`).
  The zip is never committed to git.
- An enrollment token from the portal. Keep it out of git.

## Basic use

```hcl
module "script" {
  source = "./modules/segment-connector-script"

  token_source       = "env"
  installer_zip_path = "segment-connector-linux-installer.zip"
}

output "script_text" {
  value     = module.script.install_script
  sensitive = true
}
```

The cloud modules call this module for you, so you normally do not call it directly.

## Enrollment (new hosts only)

Most hosts need no enrollment settings. Use these only for a host that is not yet in the portal.

| You want to                                 | Set                                                   |
|---------------------------------------------|-------------------------------------------------------|
| Attach to an existing portal asset          | `asset_id` (no `allow_create`)                        |
| Create a new asset, name from the cloud     | `allow_create = true`                                 |
| Create a new asset with an FQDN             | `allow_create = true` and `asset_fqdn`                |
| Create a new asset with a display name      | `allow_create = true` and `asset_name`                |
| Create a new asset by static IP             | `allow_create = true`, `with_static_ip = true`, `asset_name` |

Rules the module checks:

- `asset_fqdn`, `asset_name` and `with_static_ip` all need `allow_create = true`.
- `with_static_ip` needs an `asset_name`, and cannot be combined with `asset_fqdn`.
- `asset_fqdn` must contain a dot and cannot be an IP address.

## Token sources

`token_source` decides where the host gets the enrollment token from:

| Value             | How the token reaches the host                                              | Where the token is visible |
|-------------------|------------------------------------------------------------------------------|----------------------------|
| `env`             | The cloud module sets an environment variable when it runs the script         | Only in the cloud run command |
| `file`            | A file at `token_file_path` is read, then deleted                            | On the host, briefly       |
| `azure_key_vault` | The host reads a secret from `azure_key_vault_name` / `azure_key_vault_secret_name` | Not in the script      |
| `embedded`        | The token is written into the script (base64 encoded)                        | In the script and in Terraform state. Use only for testing. |

`install_script`, `user_data` and `script_sha256` are always marked sensitive (Terraform
does not allow this flag to depend on an input). The uninstall script never contains the token.

## Settings

Every setting has a description in `variables.tf`. The most used ones:

| Setting | Default | Meaning |
|---------|---------|---------|
| `action` | `install` | `install` or `uninstall`. Chooses which script the `user_data` output holds. |
| `run_as` | `zn-user` | `zn-user` or `root` |
| `force` | `false` | Pass `-force` to the installer |
| `reinstall` | `false` | Run the installer even if the connector is already installed |
| `download_timeout` | `""` | `600` (seconds) or a Go duration such as `10m` |
| `installer_env` | `{}` | Extra environment variables for the installer |
| `trace`, `log_to_console` | `false` | Installer logging switches |
| `verify_connection` | `true` | Check the connector log for a connection after install |
| `verify_timeout` | `180` | Seconds to wait for that check (whole number, at least 10) |
| `verify_strict` | `false` | Fail the script if the connector does not connect (otherwise only warn) |

`download_timeout` and the trace and console switches set environment variables.
If a switch is on, it wins over the same name in `installer_env`.

## Outputs

| Output | What it is |
|--------|------------|
| `install_script` | The full install script. Marked sensitive (see below) |
| `uninstall_script` | The full uninstall script. Never contains the token |
| `user_data` | The same text as `install_script`, for cloud-init. Marked sensitive |
| `install_args` | The installer arguments, before quoting. Never contains the token |
| `script_sha256` | Checksum of `install_script`. Changes when the script changes. Marked sensitive |

## Tests

The tests use `terraform test`. They only plan, so no cloud account or provider is needed.

```sh
cd modules/segment-connector-script
terraform init -backend=false
terraform validate
terraform test
```

The tests check: default arguments, each valid enrollment combination, each invalid
combination (which must fail), the download timeout, the order of environment
settings, shell quoting of values with a single quote, and that the token only
appears where the token source allows it.

## Security notes

- The `env` source is the simplest, but the cloud module puts the token in the command that
  starts the script. Anyone who can read that cloud command's settings can see the token.
  Prefer `azure_key_vault` (Azure) or the S3 token object (AWS) for production.
- The `file` source removes the token file after the script reads it.
- Do not commit a real token, an installer zip, or Terraform state.
- The state file records every input, including `token` when `token_source` is `embedded`.
  Store state somewhere private.

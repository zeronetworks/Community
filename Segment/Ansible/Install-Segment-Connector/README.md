# Install the Zero Networks Segment Connector (Linux) with Ansible

This Ansible project installs, reinstalls, and uninstalls the Zero Networks **Segment Connector** (the Linux lightweight agent) on Linux hosts. It runs the `segment-connector-linux-installer` CLI from the installer zip you download from the Zero Networks portal.

The project uses only `ansible.builtin` modules and needs no Ansible collections. It requires `ansible-core` 2.12 or later on the controller.

## Contents

```
Install-Segment-Connector/
├── ansible.cfg                          Points Ansible at the local roles and inventory
├── install-segment-connector.yml        Install or reinstall playbook
├── uninstall-segment-connector.yml      Uninstall playbook
├── inventory.example.ini                Example inventory (copy to inventory.ini)
├── group_vars/
│   └── segment_connector_hosts.example.yml   Example settings (copy to group_vars/segment_connector_hosts.yml)
├── installer/                           Place the installer zip here (not committed)
└── roles/install_segment_connector/     Role: defaults, tasks (install, uninstall), meta
```

## Prerequisites

**Controller**

- `ansible-core` 2.12 or later.
- SSH access to the target hosts, with a user that can use `sudo` (`become`).

**Target hosts**

- Linux with systemd. The installer runs as root, which the playbook gets with `become: true`.
- DNS resolution for the TXT record of the token's audience. The installer looks up this record to find the Zero Networks service.
- Outbound network access to the Zero Networks segment server. The installer registers with it and downloads the connector package from it.
- The role installs `unzip` if it is missing.

**Zero Networks portal**

1. Download the Linux installer zip at **Settings > Segment > Segment Connector**.
2. Generate an installation token in the same place.

## Quick start

1. Change into this directory and place the installer zip in `installer/`:

   ```sh
   cd Segment/Ansible/Install-Segment-Connector
   cp ~/Downloads/segment-connector-linux-installer-X.Y.Z.W.zip installer/
   ```

2. Create your inventory and settings from the examples:

   ```sh
   cp inventory.example.ini inventory.ini
   cp group_vars/segment_connector_hosts.example.yml group_vars/segment_connector_hosts.yml
   ```

   Edit both files. Set the host names, the SSH user, and `install_segment_connector_package_filename`.

3. Supply the token. Do not put it in any file that is committed to git. Choose one option:

   **Option A: a local secrets file** (ignored by git through the `secrets*.yml` rule):

   ```yaml
   # secrets.yml
   install_segment_connector_token: "<paste token from the portal>"
   ```

   ```sh
   ansible-playbook -i inventory.ini install-segment-connector.yml -e @secrets.yml
   ```

   **Option B: Ansible Vault** (recommended for shared use):

   ```sh
   ansible-vault encrypt secrets.yml          # encrypts the file in place
   ansible-playbook -i inventory.ini install-segment-connector.yml \
     -e @secrets.yml --ask-vault-pass
   ```

   **Option C: an environment variable.** Uncomment the `lookup('ansible.builtin.env', ...)` line in `group_vars/segment_connector_hosts.yml`, then:

   ```sh
   export ZN_SEGMENT_CONNECTOR_TOKEN='<paste token from the portal>'
   ansible-playbook -i inventory.ini install-segment-connector.yml
   ```

4. Check the result on the host with `systemctl status zn-segment-connector`.

## Common runs

| Task | Command |
|---|---|
| Install | `ansible-playbook -i inventory.ini install-segment-connector.yml -e @secrets.yml` |
| Reinstall (installer runs again) | `... install-segment-connector.yml -e @secrets.yml -e install_segment_connector_reinstall=true` |
| Enroll a host that is not yet in the portal (FQDN) | `... -e @secrets.yml -e install_segment_connector_enroll_asset=true -e install_segment_connector_asset_fqdn=connector01.example.com` |
| Enroll with a static IP | `... -e @secrets.yml -e install_segment_connector_enroll_asset=true -e install_segment_connector_with_static_ip=true -e install_segment_connector_asset_name=connector01` |
| Run as root instead of zn-user | `... -e @secrets.yml -e install_segment_connector_run_as=root` |
| Uninstall | `ansible-playbook -i inventory.ini uninstall-segment-connector.yml -e @secrets.yml` |
| Uninstall, replacing a conflicting assetId | `... uninstall-segment-connector.yml -e @secrets.yml -e install_segment_connector_force=true` |

Add `--limit connector01.example.com` to run against a single host.

**Install behaviour when the service already exists.** If `zn-segment-connector` is already installed, the role skips the installer and prints a message. Set `install_segment_connector_reinstall=true` to run the installer again. The installer handles re-registration itself.

## Variables

Set these in `group_vars`, in the inventory, or with `-e`. Defaults are in `roles/install_segment_connector/defaults/main.yml`.

| Variable | Default | Description |
|---|---|---|
| `install_segment_connector_token` | `""` | **Required.** Installation token from the portal. Never commit it. |
| `install_segment_connector_package_filename` | `""` | **Required.** Filename of the installer zip in `installer/`. |
| `install_segment_connector_package_path` | `{{ playbook_dir }}/installer/<filename>` | Controller path to the zip. Override to use a zip stored elsewhere. |
| `install_segment_connector_staging_dir` | `/opt/zn-segment-connector-setup` | Directory on the target where the zip is extracted. |
| `install_segment_connector_run_as` | `zn-user` | Account the connector runs as: `zn-user` or `root`. Passed as `-run-as`. |
| `install_segment_connector_force` | `false` | Passes `-force` to the installer. |
| `install_segment_connector_asset_id` | `""` | Existing asset ID to attach to. Passed as `-assetId`. |
| `install_segment_connector_reinstall` | `false` | Run the installer even when the service already exists. |
| `install_segment_connector_enroll_asset` | `false` | Create a new portal asset if none matches. Passed as `-allow-create`. |
| `install_segment_connector_asset_fqdn` | `{{ ansible_facts.fqdn }}` | FQDN for the new asset. Passed as `-asset-fqdn`. Must contain a dot. Not used with static IP. |
| `install_segment_connector_asset_name` | `""` | Display name for the new asset. Passed as `-name`. Requires `enroll_asset`. Required with static IP. |
| `install_segment_connector_with_static_ip` | `false` | Enroll with a static IP. Passed as `-with-static-ip`, which replaces `-asset-fqdn`. Requires `enroll_asset` and `asset_name`. |

**Validation.** The role stops before it changes anything if the options conflict:

- `asset_name` requires `enroll_asset=true`.
- `with_static_ip=true` requires `enroll_asset=true` and a non-empty `asset_name`.
- With an FQDN (not static IP), the FQDN must be set and must contain a dot. The default `ansible_facts.fqdn` is often a short name on hosts that are not configured with a domain. In that case, set `install_segment_connector_asset_fqdn` explicitly or use static IP mode.

The installer validates the FQDN again and rejects names that are not valid.

## Run as root or as zn-user

- `zn-user` (default): the installer creates a dedicated local account, `zn-user`, if it does not exist.
- `root`: the connector runs as root and no `zn-user` account is created.

A host that was installed as root and is reinstalled as `zn-user` fails if the `zn-user` account does not exist. To avoid this, use the same `install_segment_connector_run_as` value that the host was installed with, or uninstall first.

## Troubleshooting

The installer log on each target is `/var/zeronetworks/logs/installer.log`. Check it first. The service is `zn-segment-connector`.

| Symptom | Likely cause and fix |
|---|---|
| `install_segment_connector_token must be set` | The token was not supplied. Use one of the options in Quick start step 3. |
| `Installer package not found on the controller` | The zip is not in `installer/`, or the filename does not match `install_segment_connector_package_filename`. |
| `segment-connector-linux-installer was not found` | The zip is not the Linux installer. Download it again from the portal. |
| Installer fails with an invalid token | The token is wrong, expired, or was generated for another environment. Generate a new one in the portal. |
| Installer fails resolving the token audience | DNS TXT lookup failed. Check that the target can resolve public DNS names. Check for a DNS filter or proxy. |
| Installer cannot reach the segment server | Check outbound access from the target to the Zero Networks segment server. Check proxies and firewalls. |
| FQDN validation fails | Set `install_segment_connector_asset_fqdn` to a fully qualified name such as `connector01.example.com`, or use `install_segment_connector_with_static_ip=true` with `install_segment_connector_asset_name`. |
| Installer reports a conflicting assetId | The host is already linked to a different asset. Set `install_segment_connector_force=true` to replace it, or pass the correct `install_segment_connector_asset_id`. |
| Reinstall did nothing | The service already exists. Set `install_segment_connector_reinstall=true`. |
| Reinstall as zn-user fails on a root install | The `zn-user` account does not exist. Reinstall with `install_segment_connector_run_as=root`, or uninstall first. |

## Security notes

- The token is written to a `0600` file in the staging directory on the target. It is removed in an `always` block, so it is removed even when the install fails.
- The installer takes the token as a command-line argument (`-token`). While the installer runs, the token is visible to other users on the target in the process list (`ps`). This is how the installer works and cannot be changed in this project. Run installs on hosts where only administrators have shell access, and do not run them while others are watching the process list.
- The task that writes the token file uses `no_log`. The installer command reads the token from that file inside the shell, so the token is not in the task arguments or the printed output.
- Use Ansible Vault or an environment variable for the token. Do not commit a token, a `secrets*.yml` file, or an installer zip. The `.gitignore` in this directory covers these, but check `git status` before you commit.

## Supported distributions

The installer does not restrict the distribution it runs on. The role metadata lists the distributions the role was written for. Confirm the supported distributions and versions with Zero Networks support before you deploy to production.

## License

MIT

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

- A supported Linux distribution (see [Supported platforms](#supported-platforms)). The installer runs as root, which the playbook gets with `become: true`.
- Python on the target, for Ansible itself. See [Target host requirements](#target-host-requirements).
- DNS resolution for the TXT record of the token's audience. The installer looks up this record to find the Zero Networks service.
- Outbound network access to the Zero Networks segment server. The installer registers with it and downloads the connector package from it.
- The role does not need `unzip`. It extracts the installer zip with the target's own Python `zipfile` module.

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

4. Check the result on the host. The service name is `zn-segment-connector`. On systemd hosts use `systemctl status zn-segment-connector`. On sysvinit hosts (for example RHEL/CentOS 6) use the init script, for example `service zn-segment-connector status`.

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

**Install behaviour when the connector already exists.** The role checks for the installer identity file (`install_segment_connector_identity_file`, default `/var/zeronetworks/.zn-internal/identity.json`). If it exists, the connector is already installed, and the role skips the installer and prints a message. Set `install_segment_connector_reinstall=true` to run the installer again. The installer handles re-registration itself.

## Variables

Set these in `group_vars`, in the inventory, or with `-e`. Defaults are in `roles/install_segment_connector/defaults/main.yml`.

| Variable | Default | Description |
|---|---|---|
| `install_segment_connector_token` | `""` | **Required.** Installation token from the portal. Never commit it. |
| `install_segment_connector_package_filename` | `""` | **Required.** Filename of the installer zip in `installer/`. |
| `install_segment_connector_package_path` | `{{ playbook_dir }}/installer/<filename>` | Controller path to the zip. Override to use a zip stored elsewhere. |
| `install_segment_connector_staging_dir` | `/opt/zn-segment-connector-setup` | Directory on the target where the zip is copied and extracted. The copied zip is deleted after extraction. |
| `install_segment_connector_identity_file` | `/var/zeronetworks/.zn-internal/identity.json` | File the installer writes on success. If it exists, the install is skipped unless `reinstall=true`. |
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

Check the logs on each target first:

- `/var/zeronetworks/logs/installer.log`. When an install fails, the playbook prints the last 50 lines of this file.
- `/var/zeronetworks/logs/install-script.log`. Written by the installer script itself, in the same directory. Check it when `installer.log` does not explain the failure.

The service is `zn-segment-connector`.

Non-fatal warnings printed before the install (missing `nft` and `iptables`, or SELinux enabled without `sudo`) do not stop the run. Fix them if the connector does not start.

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
| Reinstall did nothing | The connector is already installed (the identity file exists). Set `install_segment_connector_reinstall=true`. |
| Reinstall as zn-user fails on a root install | The `zn-user` account does not exist. Reinstall with `install_segment_connector_run_as=root`, or uninstall first. |

## Security notes

- The token is written to a `0600` file in the staging directory on the target. It is removed in an `always` block, so it is removed even when the install fails.
- The installer takes the token as a command-line argument (`-token`). While the installer runs, the token is visible to other users on the target in the process list (`ps`). This is how the installer works and cannot be changed in this project. Run installs on hosts where only administrators have shell access, and do not run them while others are watching the process list.
- The installer zip is copied to the staging directory and deleted after extraction, and again in the `always` block if extraction fails.
- The task that writes the token file uses `no_log`. The installer command reads the token from that file inside the shell, so the token is not in the task arguments or the printed output.
- Use Ansible Vault or an environment variable for the token. Do not commit a token, a `secrets*.yml` file, or an installer zip. The `.gitignore` in this directory covers these, but check `git status` before you commit.

## Supported platforms

Source: the Zero Networks "Supported Operating Systems" documentation. Confirm the current list there before you deploy.

| Distribution | Versions |
|---|---|
| Red Hat Enterprise Linux (RHEL) | 6 to 10 |
| CentOS | 6 to 8 |
| Ubuntu | 16 to 24 |
| Fedora | 19 to 40 |
| AlmaLinux, Rocky Linux | 8 to 10 |
| Oracle Linux | 7 to 10 |
| SUSE Linux Enterprise, openSUSE | 15 |
| Debian | 9 to 13 |
| Linux Mint | 18 to 22 |
| Kali Linux | 2017 to 2025 |
| Amazon Linux | 2 |
| VMware Photon OS | 4 and 5 |

32-bit systems are not supported.

The role metadata (`roles/install_segment_connector/meta/main.yml`) lists the same families using Galaxy platform names.

## Target host requirements

The installer detects the init system. It creates a systemd unit when systemd is PID 1, and an init.d script otherwise. RHEL/CentOS 6 use sysvinit.

**Python on the target.** Ansible needs Python on the target. See [Legacy platforms](#legacy-platforms).

**Agent runtime packages.** The Segment Connector agent needs these at runtime. The role does **not** install them. Install them before you run the playbook or make sure they are present:

- Firewall backend: `nftables`, or legacy `iptables`.
- Logging: `rsyslog` or `ulogd2`.
- `logrotate`.
- Python: `python2.7` (RHEL/CentOS 6, Ubuntu 16/18) or `python3.4` or later, plus `python3-pip` or `distutils`.
- RPM-based distributions: `cronie`. On Fedora 35 and later, also `iptables-legacy-libs`.
- Debian-based distributions: `cron` and `python3-venv`.
- RHEL/CentOS 6: `ipset`.

**SELinux.** On SELinux-enabled RHEL-family hosts the installer runs `sudo semodule` and `restorecon`. Make sure `sudo` and `policycoreutils` are installed. The role warns, and does not stop, when SELinux is enabled and `sudo` is missing.

## Legacy platforms

RHEL/CentOS 6 and Ubuntu 16/18 ship Python 2.7, 3.5, or 3.6 as their system Python. Current `ansible-core` releases cannot run on those targets:

- Use an `ansible-core` version that still supports Python 2.7 or 3.6+ targets (2.16 or earlier), or
- Install a newer Python on the target and point Ansible at it with `ansible_python_interpreter` in the inventory (see `inventory.example.ini`). Note that the Segment Connector agent itself still needs Python 2.7 on these legacy releases.

The install step extracts the zip with the target's Python `zipfile` module, so it works on Python 2.7 and 3.x without `unzip`.

**The role has not been tested on these legacy platforms.** Run it against a test host first.

## License

MIT

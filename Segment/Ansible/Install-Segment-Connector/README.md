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
└── roles/segment_connector/             Role
    ├── defaults/main.yml                Default variable values
    ├── vars/                            Role variables
    ├── tasks/
    │   ├── main.yml                     Entry point
    │   ├── install.yml                  Copy, extract, and run the installer
    │   ├── uninstall.yml                Run the uninstaller
    │   ├── report_version.yml           Record the installer version
    │   └── diagnose.yml                 Print logs and hints after a failure
    └── meta/main.yml                    Galaxy metadata and supported platforms
```

## Prerequisites

**Controller**

- `ansible-core` 2.12 or later.
- SSH access to the target hosts, with a user that can use `sudo` (`become`).

**Target hosts**

- A supported Linux distribution (see [Supported platforms](#supported-platforms)). The installer runs as root, which the playbook gets with `become: true`.
- Python on the target, for Ansible itself. See [Target host requirements](#target-host-requirements).
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

   Edit both files. Set the host names, the SSH user, and `segment_connector_package_filename`.

3. Supply the token. Do not put it in any file that is committed to git. Choose one option:

   **Option A: a local secrets file** (ignored by git through the `secrets*.yml` rule):

   ```yaml
   # secrets.yml
   segment_connector_token: "<paste token from the portal>"
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
| Auto-enroll a host that is not yet in the portal (the portal picks the FQDN) | `... install-segment-connector.yml -e @secrets.yml -e segment_connector_allow_create=true` |
| Enroll with an explicit FQDN | `... -e @secrets.yml -e segment_connector_allow_create=true -e segment_connector_asset_fqdn=connector01.example.com` |
| Enroll with a static IP | `... -e @secrets.yml -e segment_connector_allow_create=true -e segment_connector_with_static_ip=true -e segment_connector_asset_name=connector01` |
| Slow download link (raise the package download timeout to 600 seconds) | `... -e @secrets.yml -e segment_connector_download_timeout=600` |
| Debugging (installer trace logging) | `... -e @secrets.yml -e segment_connector_trace=true` |
| Reinstall (installer runs again) | `... install-segment-connector.yml -e @secrets.yml -e segment_connector_reinstall=true` |
| Reinstall and force (replace a conflicting assetId) | `... install-segment-connector.yml -e @secrets.yml -e segment_connector_reinstall=true -e segment_connector_force=true` |
| Run as root instead of zn-user | `... -e @secrets.yml -e segment_connector_run_as=root` |
| Uninstall | `ansible-playbook -i inventory.ini uninstall-segment-connector.yml -e @secrets.yml` |
| Uninstall with force (if unregistration fails) | `... uninstall-segment-connector.yml -e @secrets.yml -e segment_connector_force=true` |

Add `--limit connector01.example.com` to run against a single host.

Hosts already in the portal need no enrollment variables. Use `allow_create` only for hosts that are not yet registered.

**Install behaviour when the connector already exists.** The role checks for the installer identity file (`segment_connector_identity_file`, default `/var/zeronetworks/.zn-internal/identity.json`). If it exists, the connector is already installed, and the role skips the installer and prints a message. Set `segment_connector_reinstall=true` to run the installer again. The installer handles re-registration itself. On a reinstall the enrollment flags (`allow_create`, `asset_fqdn`, `asset_name`, `with_static_ip`) are ignored unless `segment_connector_force=true`.

## Variables

Set these in `group_vars`, in the inventory, or with `-e`. Defaults are in `roles/segment_connector/defaults/main.yml`.

| Variable | Default | Maps to | Notes |
|---|---|---|---|
| `segment_connector_token` | `""` | Installer `-token` | **Required.** Installation token from the portal. Never commit it. See [Security notes](#security-notes). |
| `segment_connector_package_filename` | `""` | n/a | **Required.** Filename of the installer zip in `installer/`. |
| `segment_connector_package_path` | `{{ playbook_dir }}/installer/<package_filename>` | n/a | Controller path to the zip. Override to use a zip stored elsewhere. |
| `segment_connector_staging_dir` | `/opt/zn-segment-connector-setup` | n/a | Directory on the target where the zip is copied and extracted. The copied zip is deleted after extraction. |
| `segment_connector_identity_file` | `/var/zeronetworks/.zn-internal/identity.json` | n/a | File the installer writes on success. If it exists, the install is skipped unless `reinstall=true`. |
| `segment_connector_reinstall` | `false` | n/a | Run the installer even when the connector is already installed (the identity file exists). |
| `segment_connector_run_as` | `zn-user` | `-run-as` | Account the connector runs as: `zn-user` or `root`. |
| `segment_connector_force` | `false` | `-force` | Passed to the installer on install and uninstall. Replaces a conflicting assetId. On a reinstall, also applies the enrollment flags. |
| `segment_connector_asset_id` | `""` | `-assetId` | Existing asset ID to attach to. Takes precedence over matching by FQDN. |
| `segment_connector_allow_create` | `false` | `-allow-create` | Let the portal create a new asset when none matches. Only for hosts not yet registered. |
| `segment_connector_asset_fqdn` | `""` | `-asset-fqdn` (only when set) | FQDN for the new asset. Must be a fully qualified name containing a dot, not an IP address. Requires `allow_create`. Cannot be combined with static IP. |
| `segment_connector_asset_name` | `""` | `-name` | Display name for the new asset. Requires `allow_create`. Required with static IP. |
| `segment_connector_with_static_ip` | `false` | `-with-static-ip` | Enroll using the source IP the portal sees. Requires `allow_create` and `asset_name`. Cannot be combined with `asset_fqdn`. |
| `segment_connector_installer_env` | `{}` | Environment variables | Extra environment variables passed to every installer call. String values. Empty or null values are dropped. See [Installer environment settings](#installer-environment-settings). |
| `segment_connector_download_timeout` | `""` | `ZN_SEGMENT_CONNECTOR_INSTALL_GET_PKG_TIMEOUT` | Package download timeout. A bare number such as `600` is seconds. Go durations such as `10m` also work. Installer default is 180s. |
| `segment_connector_trace` | `false` | `ZN_AGENT_INSTALLER_TRACE_ENABLED=true` | Turns on installer trace logging. Use for debugging. |
| `segment_connector_log_to_console` | `false` | `ZN_AGENT_INSTALLER_LOG_PRINT_TO_CONSOLE=true` | Prints installer log lines in the Ansible or AWX output. These lines are not redacted. Leave it off unless debugging. |
| `segment_connector_report_version` | `true` | n/a | Runs `<installer> -version` before install or uninstall and sets the fact `segment_connector_installer_version`. Never fails the play. See [Installer version](#installer-version). |

**Rules.** The role checks these before it changes anything on the host, and the installer checks them again:

- `asset_name` requires `allow_create=true`.
- `asset_fqdn` requires `allow_create=true`. It must contain a dot and must not be an IP address. It cannot be combined with `with_static_ip`.
- `with_static_ip=true` requires `allow_create=true` and a non-empty `asset_name`.

**Behaviour change.** `segment_connector_asset_fqdn` no longer defaults to the host's Ansible FQDN. If you do not set it, the portal chooses the name for a new asset. Set it explicitly if you want a specific name.

## How the host is matched to a portal asset

When the installer runs, it looks for the portal asset for the host in this order:

1. **Asset ID.** If `segment_connector_asset_id` is set, or the identity file already exists on the host, the installer uses that asset ID.
2. **Existing asset by FQDN.** The installer looks for Linux assets whose FQDN matches the host. If exactly one matches, it is used as-is. Nothing is created. If more than one matches, the install fails. Set `segment_connector_asset_id` to choose one.
3. **No match.**
   - Without `allow_create`, the install fails with `Couldn't find asset`.
   - With `allow_create`, the portal creates the asset. It uses the first of these that applies:
     - `segment_connector_asset_fqdn`, if set.
     - The source IP the portal sees, if `with_static_ip` is set. This needs `asset_name`.
     - The FQDN the portal derives for the host (the "trusted FQDN").
     - If none of these can be derived, the install fails and tells you to set `asset_fqdn` or use static IP.

The chassis type must be valid. OT assets are rejected.

Hosts already in the portal need no enrollment variables: the portal matches them by asset ID or by their FQDN.

## Installer environment settings

Named variables such as `segment_connector_trace` and `segment_connector_download_timeout` are the preferred way to set common options. Use `segment_connector_installer_env` for any other installer environment variable.

```yaml
segment_connector_installer_env:
  ZN_AGENT_INSTALLER_LOG_MAX_BACKUPS: "3"
```

- Values must be strings. Empty or null values are dropped.
- The map is passed to every installer call, on install and uninstall.
- **Precedence.** Named variables override the same keys in `installer_env`. For example, `segment_connector_trace=true` wins over `ZN_AGENT_INSTALLER_TRACE_ENABLED: "false"` in `installer_env`.
- **Durations.** A bare number is treated as seconds. The role appends `s`, so `600` becomes `600s`. Go durations such as `90s`, `5m`, or `10m` also work.

Other installer variables you can set through `installer_env` (defaults in parentheses):

| Variable | Default | Purpose |
|---|---|---|
| `ZN_AGENT_INSTALLER_LOG_MAX_SIZE_MB` | `20` | Maximum size of the installer log before rotation, in MB. |
| `ZN_AGENT_INSTALLER_LOG_MAX_BACKUPS` | `1` | Number of rotated installer log files to keep. |
| `ZN_AGENT_INSTALLER_LOG_COMPRESS_BACKUPS` | `false` | Compress rotated installer log files. |
| `ZN_SEGMENT_CONNECTOR_INSTALL_REGISTER_TIMEOUT` | `60s` | Timeout for registering with the segment server. |
| `ZN_SEGMENT_CONNECTOR_INSTALL_CONNECTION_TEST_TIMEOUT` | `5s` | Timeout for the connection test to the segment server. |
| `ZN_SEGMENT_CONNECTOR_INSTALL_SERVER_PORT` | `443` | Port used to reach the segment server. |
| `ZN_SEGMENT_CONNECTOR_INSTALL_MAX_MSG_SIZE` | Installer default | Maximum message size used by the installer. |

**Console logging.** `segment_connector_log_to_console=true` sends installer log lines to the Ansible or AWX output. Those lines are not redacted, so leave it off unless you are debugging.

## Installer version

After it runs the installer, the role records the installer version in the fact `segment_connector_installer_version`. The role runs `<installer> -version` before install and before uninstall. It skips the version report in `--check` mode, and when the install is skipped because the connector is already installed.

The fact is set only when the version report runs. In a later play of the same run, use a default for hosts where it was not set:

```yaml
- name: Show the Segment Connector installer version
  ansible.builtin.debug:
    msg: "Segment Connector installer {{ segment_connector_installer_version | default('not reported') }}"
```

Set `segment_connector_report_version=false` to skip the version report.

## Run as root or as zn-user

- `zn-user` (default): the installer creates a dedicated local account, `zn-user`, if it does not exist.
- `root`: the connector runs as root and no `zn-user` account is created.

A host that was installed as root and is reinstalled as `zn-user` fails if the `zn-user` account does not exist. To avoid this, use the same `segment_connector_run_as` value that the host was installed with, or uninstall first.

## Troubleshooting

When an install or uninstall fails, the role prints three things automatically:

- The last 50 lines of `/var/zeronetworks/logs/installer.log`.
- The installer output. Installer messages go to stderr, and the role shows both stdout and stderr.
- A **Hints** list that matches known errors.

Check the logs on each target first:

- `/var/zeronetworks/logs/installer.log`. When an install fails, the playbook prints the last 50 lines of this file.
- `/var/zeronetworks/logs/install-script.log`. Written by the installer script itself, in the same directory. Check it when `installer.log` does not explain the failure.

The service is `zn-segment-connector`.

Non-fatal warnings printed before the install (missing `nft` and `iptables`, or SELinux enabled without `sudo`) do not stop the run. Fix them if the connector does not start.

| Symptom | Likely cause and fix |
|---|---|
| `segment_connector_token must be set` | The token was not supplied. Use one of the options in Quick start step 3. |
| `Installer package not found on the controller` | The zip is not in `installer/`, or the filename does not match `segment_connector_package_filename`. |
| `segment-connector-linux-installer was not found` | The zip is not the Linux installer. Download it again from the portal. |
| Installer reports an invalid token | The token is wrong, expired, or was generated for another environment. Generate a new one in the portal. |
| DNS TXT lookup failure (installer fails resolving the token audience) | The target cannot resolve public DNS names. Check for a DNS filter or proxy. |
| Cannot reach segment server | Check outbound access from the target to the Zero Networks segment server. Check proxies and firewalls. |
| assetId conflict | The host is linked to a different asset. Set `segment_connector_force=true` to replace it, or remove `segment_connector_asset_id` and let matching find the asset. |
| Asset not found (`Couldn't find asset`) | No portal asset matches the host. Set `segment_connector_allow_create=true` to create one, or set `segment_connector_asset_id` to an existing asset. |
| No trusted FQDN | The portal cannot derive a name for the new asset. Set `segment_connector_asset_fqdn`, or use `segment_connector_with_static_ip=true` with `segment_connector_asset_name`. |
| More than one asset matches | Set `segment_connector_asset_id` to the asset you want. |
| Provided FQDN invalid | Set `segment_connector_asset_fqdn` to a fully qualified name with a dot, such as `connector01.example.com`. It must not be an IP address. |
| Static IP requires name | Set `segment_connector_asset_name` when using `segment_connector_with_static_ip=true`. |
| OT asset not supported | The matched asset is an OT asset, which this connector does not support. Check the asset in the portal and use a non-OT asset. |
| Asset inactive | The matched asset is inactive in the portal. Reactivate it in the portal, or attach to an active asset with `segment_connector_asset_id`. |
| Chassis or OS info invalid | Check the host's OS against [Supported platforms](#supported-platforms). The message `Windows version is not supported` on a Linux host means the distribution is not supported. |
| `zn-user` missing (installed with `run_as=root`) | The host was installed as root, so no `zn-user` account exists. Uninstall first, or use `segment_connector_run_as=root`. |
| Package download failed | The download timed out. Raise `segment_connector_download_timeout`, for example to `600`. |
| Must run with sudo | The installer needs root. The playbook uses `become: true`. Check that the SSH user can use `sudo`. |
| Prerequisites failed | Check `/var/zeronetworks/logs/install-script.log` for the missing prerequisite. See [Target host requirements](#target-host-requirements). |
| Uninstall: no asset ID | The host has no asset ID to unregister. Pass `segment_connector_asset_id` to the uninstall run. |
| Uninstall: unregistration failed | Run the uninstall again with `segment_connector_force=true`. |
| Uninstall: cleanup incomplete | The host was unregistered, but removing the service or the local `zn-user` did not finish. Check `installer.log` and `install-script.log` for what remains and remove it manually. |

## Security notes

- The token is written to a `0600` file in the staging directory on the target. It is removed in an `always` block, so it is removed even when the install fails.
- The installer takes the token as a command-line argument (`-token`). While the installer runs, the token is visible to other users on the target in the process list (`ps`). This is how the installer works and cannot be changed in this project. Run installs on hosts where only administrators have shell access, and do not run them while others are watching the process list.
- The installer zip is copied to the staging directory and deleted after extraction, and again in the `always` block if extraction fails.
- The task that writes the token file uses `no_log`. The installer command reads the token from that file inside the shell, so the token is not in the task arguments or the printed output.
- Use Ansible Vault or an environment variable for the token. Do not commit a token, a `secrets*.yml` file, or an installer zip. The `.gitignore` in this directory covers these, but check `git status` before you commit.
- `segment_connector_log_to_console=true` prints installer log lines without redaction. Leave it off unless you are debugging.

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

The role metadata (`roles/segment_connector/meta/main.yml`) lists the same families using Galaxy platform names.

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

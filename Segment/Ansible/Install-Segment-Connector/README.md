# Install the Zero Networks Segment Connector (Linux) with Ansible

Installs, reinstalls, and uninstalls the Zero Networks **Segment Connector** (the Linux lightweight agent) with Ansible.
It runs `segment-connector-linux-installer` from the installer zip you download from the Zero Networks portal.
The project uses only `ansible.builtin` modules, so it needs no Ansible collections. It needs `ansible-core` 2.12 or later on the controller.

> **Read before you run.** This is a community example. Test it in a non-production environment first.
> See [Caveats and testing status](#caveats-and-testing-status) for what was tested and what was not.

## Contents

```
Install-Segment-Connector/
├── ansible.cfg                          Sets the inventory, the roles path and Python discovery
├── .gitignore                           Keeps tokens, secrets and installer zips out of git
├── install-segment-connector.yml        Install or reinstall playbook
├── uninstall-segment-connector.yml      Uninstall playbook
├── inventory.example.ini                Example inventory (copy to inventory.ini)
├── group_vars/
│   └── segment_connector_hosts.example.yml   Example settings (copy to group_vars/segment_connector_hosts.yml)
├── installer/                           Place the installer zip here (zip files are not committed)
└── roles/segment_connector/             Role
    ├── defaults/main.yml                Default variable values
    ├── vars/                            Role variables
    ├── tasks/
    │   ├── main.yml                     Entry point
    │   ├── install.yml                  Copy, extract, and run the installer
    │   ├── uninstall.yml                Run the uninstaller
    │   ├── report_version.yml           Report the installer version (before install or uninstall)
    │   ├── verify_connection.yml        Check the connection to the segment server after install
    │   └── diagnose.yml                 Print logs and hints after a failure
    └── meta/main.yml                    Galaxy metadata and supported platforms
```

**On this page**

- [Prerequisites](#prerequisites)
- [How to use](#how-to-use)
- [Common runs](#common-runs)
- [Variables](#variables)
- [How it works](#how-it-works)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)
- [Supported platforms](#supported-platforms)
- [Target host requirements](#target-host-requirements)
- [Legacy platforms](#legacy-platforms)
- [Caveats and testing status](#caveats-and-testing-status)
- [License](#license)

## Prerequisites

**Controller**

- `ansible-core` 2.12 or later, running on a controller Python that your `ansible-core` release supports. 2.12 is the declared minimum. See [Caveats and testing status](#caveats-and-testing-status) for the versions that were tested.
- SSH access to the target hosts, with a user that can use `sudo` (`become`).

**Target hosts**

- A supported Linux distribution (see [Supported platforms](#supported-platforms)). The installer runs as root, which the playbook gets with `become: true`.
- Python on the target, for Ansible itself. See [Target host requirements](#target-host-requirements).
- Outbound TCP 443 to the Zero Networks segment server. The installer registers with it and downloads the connector package from it.
- DNS that works from the target:
	- The host must resolve the segment server's name. The portal gives the connector this name.

**Zero Networks portal**

1. Download the Segment Connector installer zip at **Settings > Segment > Segment Connector**.
2. Generate an installation token in the same place.

## How to use

Run the commands from the project directory, `Segment/Ansible/Install-Segment-Connector` (step 2 changes into it from the repository root). `ansible.cfg` sets the inventory (`inventory.ini`), so the commands do not need `-i`. It applies only when you run from the project directory.

1. Get the installer zip and an installation token from the portal (see [Prerequisites](#prerequisites)).

2. Copy the zip into `installer/`:

   ```sh
   cd Segment/Ansible/Install-Segment-Connector
   cp ~/Downloads/segment-connector-linux-installer-X.Y.Z.W.zip installer/
   ```

3. Create your inventory and settings from the examples:

   ```sh
   cp inventory.example.ini inventory.ini
   cp group_vars/segment_connector_hosts.example.yml group_vars/segment_connector_hosts.yml
   ```

   Edit both files. Set the host name, the SSH user, and `segment_connector_package_filename`.

4. Put the token in a local `secrets.yml`. Git ignores `secrets*.yml`:

   ```yaml
   # secrets.yml
   segment_connector_token: "<paste token from the portal>"
   ```

5. Run a dry run first. With `--check`, the installer is not run and the connection check is skipped. Use `--check` with the install playbook only:

   ```sh
   ansible-playbook install-segment-connector.yml -e @secrets.yml --check
   ```

   Then run it for real, without `--check`:

   ```sh
   ansible-playbook install-segment-connector.yml -e @secrets.yml
   ```

   Add `--ask-become-pass` if `sudo` needs a password. Add `--ask-pass` if SSH needs a password.

6. Verify the install. On a healthy host the output includes lines like these (the first one appears before the install runs). The segment server name comes from the portal, and `(collector started)` can be missing for the first minute:

   ```
   Segment Connector installer version on connector01.example.com: 1.2.22.0
   Segment Connector on connector01.example.com is connected to segment-server.example.com:443 (collector started).
   ```

   On systemd hosts, run `systemctl status zn-segment-connector` on the host. Check that the asset shows as Connected in the portal.
   If the play shows a warning instead, see [Connection check](#connection-check) and [Troubleshooting](#troubleshooting).

**Is the host already in the portal?** Choose the row that matches. Add the settings to the commands in step 5.

| Situation | What to add |
|---|---|
| Yes, the portal already has an asset for this host | Nothing extra. |
| No, the portal has no asset for this host | `-e segment_connector_allow_create=true`. Without it, the install fails with `Couldn't find asset`. |
| The install fails with `no trusted FQDN` | In addition to `allow_create=true`, add `-e segment_connector_asset_fqdn=connector01.example.com`, or use static IP: `-e segment_connector_with_static_ip=true -e segment_connector_asset_name=connector01` |

**Uninstall.** The uninstall reuses the installer that the install left in the staging directory. If that directory is gone, it needs the same zip again:

```sh
ansible-playbook uninstall-segment-connector.yml -e @secrets.yml
```

### Other ways to supply the token

Do not put the token in any file that is committed to git.

- **Ansible Vault.** Encrypt `secrets.yml` in place, then ask for the vault password when you run the playbook:

  ```sh
  ansible-vault encrypt secrets.yml
  ansible-playbook install-segment-connector.yml -e @secrets.yml --ask-vault-pass
  ```

- **An environment variable.** Uncomment the `lookup('ansible.builtin.env', ...)` line in `group_vars/segment_connector_hosts.yml`. Then export the token and run the playbook without `-e @secrets.yml`:

  ```sh
  export ZN_SEGMENT_CONNECTOR_TOKEN='<paste token from the portal>'
  ansible-playbook install-segment-connector.yml
  ```

## Common runs

| Task | Command |
|---|---|
| Install | `ansible-playbook install-segment-connector.yml -e @secrets.yml` |
| Auto-enroll a host that is not yet in the portal (the portal picks the FQDN) | `ansible-playbook install-segment-connector.yml -e @secrets.yml -e segment_connector_allow_create=true` |
| Enroll with an explicit FQDN | `ansible-playbook install-segment-connector.yml -e @secrets.yml -e segment_connector_allow_create=true -e segment_connector_asset_fqdn=connector01.example.com` |
| Enroll with a static IP | `ansible-playbook install-segment-connector.yml -e @secrets.yml -e segment_connector_allow_create=true -e segment_connector_with_static_ip=true -e segment_connector_asset_name=connector01` |
| Slow download link (raise the package download timeout to 600 seconds) | `ansible-playbook install-segment-connector.yml -e @secrets.yml -e segment_connector_download_timeout=600` |
| Debugging (installer trace logging) | `ansible-playbook install-segment-connector.yml -e @secrets.yml -e segment_connector_trace=true` |
| Reinstall (installer runs again) | `ansible-playbook install-segment-connector.yml -e @secrets.yml -e segment_connector_reinstall=true` |
| Reinstall and force (replace a conflicting assetId) | `ansible-playbook install-segment-connector.yml -e @secrets.yml -e segment_connector_reinstall=true -e segment_connector_force=true` |
| Have the Segment Connector service run as root instead of zn-user | `ansible-playbook install-segment-connector.yml -e @secrets.yml -e segment_connector_run_as=root` |
| Uninstall | `ansible-playbook uninstall-segment-connector.yml -e @secrets.yml` |
| Uninstall with force (if unregistration fails) | `ansible-playbook uninstall-segment-connector.yml -e @secrets.yml -e segment_connector_force=true` |

Some of these runs were not tested on a real host. See [Not tested](#not-tested).

Add `--limit connector01.example.com` to run against a single host.

## Variables

Set these in `group_vars`, in the inventory, or with `-e`. Defaults are in `roles/segment_connector/defaults/main.yml`.

"Used by" shows which playbook reads the variable: `install`, `uninstall`, or `both`. In the descriptions, a short name such as `allow_create` means `segment_connector_allow_create`.

| Variable | Required | Default | Used by | Description |
|---|---|---|---|---|
| **Required** | | | | |
| `segment_connector_token` | Yes | `""` | both | Installation token from the portal (installer flag `-token`). Never commit it. See [Security notes](#security-notes). |
| `segment_connector_package_filename` | Yes, or set `package_path` | `""` | both | Filename of the installer zip in `installer/`. |
| **Package and paths** | | | | |
| `segment_connector_package_path` | No | `{{ playbook_dir }}/installer/<package_filename>` | both | Controller path to the zip. Override to use a zip stored elsewhere. |
| `segment_connector_staging_dir` | No | `/opt/zn-segment-connector-setup` | both | Directory on the target where the zip is copied and extracted. The copied zip is deleted after extraction. The extracted installer stays here after an install, and the uninstall removes the directory. |
| `segment_connector_identity_file` | No | `/var/zeronetworks/.zn-internal/identity.json` | install | File the installer writes on success. If it exists, the install is skipped unless `reinstall=true`. |
| **Behaviour** | | | | |
| `segment_connector_run_as` | No | `zn-user` | install | Account the connector runs as: `zn-user` or `root` (installer flag `-run-as`). |
| `segment_connector_force` | No | `false` | both | Pass `-force` to the installer. On install, it replaces a conflicting assetId and also applies the enrollment flags on a reinstall. On uninstall, it is used when unregistration fails. |
| `segment_connector_reinstall` | No | `false` | install | Run the installer even when the connector is already installed (the identity file exists). |
| **Enrollment** | | | | |
| `segment_connector_asset_id` | No | `""` | install | Existing asset ID to attach to (installer flag `-assetId`). Takes precedence over matching by FQDN. |
| `segment_connector_allow_create` | No | `false` | install | Let the portal create a new asset when none matches (installer flag `-allow-create`). Only for hosts not yet in the portal. |
| `segment_connector_asset_fqdn` | No | `""` | install | FQDN for the new asset (installer flag `-asset-fqdn`, only when set). Must contain a dot and must not be an IP address. Requires `allow_create`. Cannot be combined with static IP. When empty, the portal derives the name. |
| `segment_connector_asset_name` | No | `""` | install | Display name for the new asset (installer flag `-name`). Requires `allow_create`. Required with static IP. |
| `segment_connector_with_static_ip` | No | `false` | install | Enroll using the source IP the portal sees (installer flag `-with-static-ip`). Requires `allow_create` and `asset_name`. Cannot be combined with `asset_fqdn`. |
| **Installer environment** | | | | |
| `segment_connector_installer_env` | No | `{}` | both | Extra environment variables for every installer call. Quote the values: other types are converted to text, so an unquoted `true` becomes `True`. Empty or null values are dropped. A named variable that is switched on overrides the same key. See [Installer environment settings](#installer-environment-settings). |
| `segment_connector_download_timeout` | No | `""` | both | Package download timeout (`ZN_SEGMENT_CONNECTOR_INSTALL_GET_PKG_TIMEOUT`). A bare number such as `600` is seconds. Go durations such as `10m` also work. Empty uses the installer default (180 seconds). |
| `segment_connector_trace` | No | `false` | both | Turn on installer trace logging (`ZN_AGENT_INSTALLER_TRACE_ENABLED=true`). Use for debugging. |
| `segment_connector_log_to_console` | No | `false` | both | Print installer log lines in the Ansible or AWX output (`ZN_AGENT_INSTALLER_LOG_PRINT_TO_CONSOLE=true`). These lines are not redacted. Leave it off unless you are debugging. |
| **Checks** | | | | |
| `segment_connector_report_version` | No | `true` | both | Run `<installer> -version` before install or uninstall and set the fact `segment_connector_installer_version`. Never fails the play. Skipped in check mode and when the install is skipped. See [Installer version](#installer-version). |
| `segment_connector_verify_connection` | No | `true` | install | Run the connection check after an install. Also run as a health check when the install is skipped. Skipped in check mode. See [Connection check](#connection-check). |
| `segment_connector_verify_timeout` | No | `180` | install | Seconds to wait for the connection after an install. Whole number, at least 10. |
| `segment_connector_verify_strict` | No | `false` | install | Fail the play instead of warning when the connector does not connect. |

### Facts the role sets

| Fact | Set when | Values |
|---|---|---|
| `segment_connector_installer_version` | The version report runs. Not set in check mode or when the install is skipped. | The installer version (for example `1.2.22.0`), or `unknown` if it cannot be read. |
| `segment_connector_connection_state` | The connection check runs. Not set in check mode. | `operational`, `connected`, `failing`, `not_started`, `unknown`. See [Connection check](#connection-check). |

### Other inputs

| Input | Set in | Notes |
|---|---|---|
| Inventory group `segment_connector_hosts` | `inventory.ini` | Both playbooks run on this group. |
| `ansible_python_interpreter` | Inventory or `group_vars` | Python on the target, for legacy hosts. See [Legacy platforms](#legacy-platforms). |
| `ZN_SEGMENT_CONNECTOR_TOKEN` (environment variable) | Controller shell | Used only if you uncomment the lookup line in `group_vars/segment_connector_hosts.yml`. |

### Enrollment rules

The role checks these rules before it changes anything on the host. The installer checks them again.

- `asset_name` requires `allow_create=true`.
- `asset_fqdn` requires `allow_create=true`. It must contain a dot and must not be an IP address. It cannot be combined with `with_static_ip`.
- `with_static_ip=true` requires `allow_create=true` and a non-empty `asset_name`.

## How it works

### How the host is matched to a portal asset

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

Hosts already in the portal need no enrollment variables. The portal will attempt to match them by asset ID or by their FQDN. If this process fails, you will need to provide variables outlined in step #3 above.

### Skip or reinstall

The role checks for the installer identity file (`segment_connector_identity_file`, default `/var/zeronetworks/.zn-internal/identity.json`). If the file exists, the connector is already installed. The role skips the installer and prints a message.

Set `segment_connector_reinstall=true` to run the installer again. The installer handles re-registration itself. On a reinstall, the enrollment flags (`allow_create`, `asset_fqdn`, `asset_name`, `with_static_ip`) are ignored unless `segment_connector_force=true`.

### Run as root or as zn-user

- `zn-user` (default): the installer creates a dedicated local account, `zn-user`, if it does not exist.
- `root`: the connector runs as root and no `zn-user` account is created.

A host that was installed as root and is reinstalled as `zn-user` fails if the `zn-user` account does not exist. To avoid this, use the same `segment_connector_run_as` value that the host was installed with, or uninstall first.

### Installer environment settings

Named variables such as `segment_connector_trace` and `segment_connector_download_timeout` are the preferred way to set common options. Use `segment_connector_installer_env` for any other installer environment variable.

```yaml
segment_connector_installer_env:
  ZN_AGENT_INSTALLER_LOG_MAX_BACKUPS: "3"
```

- Quote the values. Values that are not strings are converted to text, so an unquoted `true` becomes `True`. Empty or null values are dropped.
- The map is passed to every installer call, on install and uninstall.
- **Precedence.** A named variable that is switched on overrides the same key in `installer_env`: `segment_connector_trace=true`, `segment_connector_log_to_console=true`, or a non-empty `segment_connector_download_timeout`. For example, `segment_connector_trace=true` wins over `ZN_AGENT_INSTALLER_TRACE_ENABLED: "false"`. When the named variable is off or empty, the value in `installer_env` is passed through unchanged.
- **Durations.** A bare number is treated as seconds. The role appends `s`, so `600` becomes `600s`. Go durations such as `90s`, `5m`, or `10m` also work.

Other installer variables you can set through `installer_env`. The names and defaults come from the installer and can change between installer versions, so confirm them for yours:

| Variable | Default | Purpose |
|---|---|---|
| `ZN_AGENT_INSTALLER_LOG_MAX_SIZE_MB` | `20` | Maximum size of the installer log before rotation, in MB. |
| `ZN_AGENT_INSTALLER_LOG_MAX_BACKUPS` | `1` | Number of rotated installer log files to keep. |
| `ZN_AGENT_INSTALLER_LOG_COMPRESS_BACKUPS` | `false` | Compress rotated installer log files. |
| `ZN_SEGMENT_CONNECTOR_INSTALL_REGISTER_TIMEOUT` | `60s` | Timeout for registering with the segment server. |
| `ZN_SEGMENT_CONNECTOR_INSTALL_CONNECTION_TEST_TIMEOUT` | `5s` | Timeout for the connection test to the segment server. |
| `ZN_SEGMENT_CONNECTOR_INSTALL_SERVER_PORT` | `443` | Port used to reach the segment server. |
| `ZN_SEGMENT_CONNECTOR_INSTALL_MAX_MSG_SIZE` | Installer default | Maximum message size used by the installer. |

### Installer version

The role runs `<installer> -version` before the install and before the uninstall. It sets the fact `segment_connector_installer_version`. The version report is skipped in check mode, and when the install is skipped because the connector is already installed.

If the version cannot be read, the fact is `unknown`, a warning is shown, and the play continues.

The fact is set only when the version report runs. In a later play of the same run, use a default for hosts where it was not set:

```yaml
- name: Show the Segment Connector installer version
  ansible.builtin.debug:
    msg: "Segment Connector installer {{ segment_connector_installer_version | default('not reported') }}"
```

Set `segment_connector_report_version=false` to skip the version report.

### Connection check

A finished install does not prove that the connector can reach its segment server. The connector can still fail to connect, for example when the host cannot resolve the segment server's name. After the installer finishes, the role reads the connector's own log on the host (`/var/zeronetworks/logs/zn-segment-connector.log`) and reports whether the connector reached its segment server.

- **Only new log lines count.** Before the installer runs, the role records the host's clock in UTC. The check looks only at log lines written after that time, so earlier runs in the log are ignored. The connector writes UTC timestamps, and the check assumes this.
- **Waiting after an install.** A status script re-reads the log about every 5 seconds, for up to `segment_connector_verify_timeout` seconds (default 180). Ansible polls that task every 10 seconds. The check stops early when the connector reports `connected` or `operational`. The wait is long on purpose. Right after enrollment, the segment server can briefly answer `asset is not known for this segment server`.
- **Health check on re-runs.** If the install is skipped because the connector is already installed, the role reads the whole current log and does one check. A re-run of the playbook is therefore a quick health check.

The check sets the fact `segment_connector_connection_state` to one of these states:

| State | Meaning |
|---|---|
| `operational` | The connector is connected, and the segment server has told it to start collecting. |
| `connected` | The connector is connected to the segment server. The collector can take up to about a minute to start. |
| `failing` | The last thing in the log is a connection error. |
| `not_started` | The log has no new connector start and no connection result since the install began. |
| `unknown` | The log has no usable connection information. |

If the connector has not reached `connected` or `operational` when the timeout ends, the role prints a warning message in the task output. The warning names the state and the last connection error, and includes a hint for that error. For example, when the segment server name does not resolve (your output may show the line breaks differently):

```
WARNING: the Segment Connector was installed on connector01.example.com, but it did not report a connection to a segment server within 180 seconds. State: failing. Last error: rpc error: code = Unavailable desc = name resolver error: produced zero addresses.
- The host cannot resolve the segment server name segment-server.example.com. Fix DNS for that name (a DNS forwarder, or a hosts entry) on this host.
The installer succeeded; this only reports what the connector log shows. Set segment_connector_verify_strict=true to fail the play instead.
```

By default this is a warning, not a failed play, because the installation itself succeeded. To change this:

- **Wait longer:** `segment_connector_verify_timeout: 300`. Use a whole number of seconds, at least 10.
- **Fail the play instead:** `segment_connector_verify_strict: true`.
- **Turn the check off:** `segment_connector_verify_connection: false`.

**Limits**

- A `connected` or `operational` state does not prove that the portal shows the asset as Connected.
- The check depends on the connector's log messages.
- The check is skipped in check mode.
- The check was tested on systemd hosts only. See [Caveats and testing status](#caveats-and-testing-status).

See [Troubleshooting](#troubleshooting) for the hints that appear with each warning.

## Troubleshooting

When the installer itself fails during an install or uninstall, the role prints three things automatically. Mistakes in your variables fail earlier with a plain message and no diagnostics. See the first rows of the table.

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
| `segment_connector_token must be set` | The token was not supplied. Use one of the options in [How to use](#how-to-use). |
| `Invalid enrollment options`, `is not a valid fully qualified domain name`, `segment_connector_run_as must be`, or a message about `segment_connector_verify_timeout` or `segment_connector_download_timeout` | A variable value is not allowed. The role stops before it changes anything on the host. See [Enrollment rules](#enrollment-rules) and the [Variables](#variables) table. |
| `Installer package not found on the controller` | The zip is not in `installer/`, or the filename does not match `segment_connector_package_filename`. |
| `segment-connector-linux-installer was not found` | The zip is not the Linux installer. Download it again from the portal. |
| Installer reports an invalid token | The token is wrong, expired, or was generated for another environment. Generate a new one in the portal. |
| `failed to perform dns query` (the installer cannot do the DNS TXT lookup for the token audience) | The target cannot resolve public DNS names. Check for a DNS filter or proxy. |
| Cannot reach segment server | Check outbound access from the target to the Zero Networks segment server. Check proxies and firewalls. |
| assetId conflict | The host is linked to a different asset. Set `segment_connector_force=true` to replace it, or remove `segment_connector_asset_id` and let matching find the asset. |
| Asset not found (`Couldn't find asset`) | No portal asset matches the host. Set `segment_connector_allow_create=true` to create one, or set `segment_connector_asset_id` to an existing asset. |
| No trusted FQDN | The portal cannot derive a name for the new asset. Set `segment_connector_asset_fqdn`, or use `segment_connector_with_static_ip=true` with `segment_connector_asset_name`. |
| More than one asset matches | Set `segment_connector_asset_id` to the asset you want. |
| Provided FQDN invalid | Set `segment_connector_asset_fqdn` to a fully qualified name with a dot, such as `connector01.example.com`. It must not be an IP address. |
| Static IP requires name | Set `segment_connector_asset_name` when using `segment_connector_with_static_ip=true`. |
| Asset inactive | The matched asset is inactive in the portal. Reactivate it in the portal, or attach to an active asset with `segment_connector_asset_id`. |
| Chassis or OS info invalid | Check the host's OS against [Supported platforms](#supported-platforms). The message `Windows version is not supported` on a Linux host means the distribution is not supported. |
| `zn-user` missing (installed with `run_as=root`) | The host was installed as root, so no `zn-user` account exists. Uninstall first, or use `segment_connector_run_as=root`. |
| Package download failed | The download timed out. Raise `segment_connector_download_timeout`, for example to `600`. |
| Must run with sudo | The installer needs root. The playbook uses `become: true`. Check that the SSH user can use `sudo`. |
| `failed to verify installation prerequisites` or `failed to install package` | Check `/var/zeronetworks/logs/install-script.log` for the missing prerequisite. See [Target host requirements](#target-host-requirements). |
| Uninstall: no asset identity found | The host has no asset identity to unregister, so the connector may not be installed. Uninstall does not take `segment_connector_asset_id`. Check that the connector is installed on this host. |
| Uninstall: unregistration failed | Run the uninstall again with `segment_connector_force=true`. |
| Uninstall: cleanup incomplete | The host was unregistered, but removing the service or the local `zn-user` did not finish. Check `installer.log` and `install-script.log` for what remains and remove it manually. |
| Warning "did not report a connection" with `name resolver error` or `produced zero addresses` as the last error | The host cannot resolve the segment server's name. Fix DNS on the host, or add a hosts entry for the segment server. See [Connection check](#connection-check). |
| Warning "did not report a connection" with `failed to lookup txt records` as the last error | The host cannot do the DNS TXT lookup the connector needs. Allow DNS (UDP and TCP 53) to the host's resolver and to public DNS. |
| Warning "did not report a connection" with `connection refused`, `i/o timeout`, `deadline exceeded`, `network is unreachable` or `no route to host` as the last error | The host cannot reach the segment server on TCP 443. Check the firewall, routing and any proxy between the host and the segment server. |
| Warning "did not report a connection" with `x509`, `certificate` or `tls handshake` as the last error | TLS to the segment server failed. Check for TLS inspection on the path and that the host clock is correct. |
| Warning "did not report a connection" with `asset is not known for this segment server` as the last error | The segment server does not know the asset yet. This usually clears within minutes after enrollment. If it does not clear, check the asset in the portal. The check waits up to `segment_connector_verify_timeout` for it to clear. |
| Warning "did not report a connection" with state `not_started` | No new connector start was logged since the install began. Check `systemctl status zn-segment-connector`, `/var/zeronetworks/logs/shell-std-err.log` and `/var/zeronetworks/logs/zn-segment-connector.log.panic`. |
| Warning "did not report a connection" with "No known cause matched" | The last error is not in the list of known causes. Read the last connector events in the warning, and check `/var/zeronetworks/logs/zn-segment-connector.log` on the host. |

## Security notes

- The token is written to a `0600` file in the staging directory on the target. It is removed in an `always` block, so it is removed even when the install fails.
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

The role metadata (`roles/segment_connector/meta/main.yml`) lists these families only approximately, using Galaxy platform names. Use the table above as the reference.

Only Rocky Linux 9.8 was tested. See [Caveats and testing status](#caveats-and-testing-status).

## Target host requirements

The installer detects the init system. It creates a systemd unit when systemd is PID 1, and an init.d script otherwise. RHEL/CentOS 6 use sysvinit.

**Python on the target.** Ansible needs Python on the target. See [Legacy platforms](#legacy-platforms).

**Agent runtime packages.** The Segment Connector agent needs these at runtime. The role does **not** install them. Install them before you run the playbook or make sure they are present:

- Firewall backend: `nftables`, or legacy `iptables`.
- Logging: `rsyslog` or `ulogd2`.
- `logrotate`.
- Python: Python 2.7, or Python 3.4 or later, plus `python3-pip` or `distutils`. The releases marked with an asterisk in the Zero Networks list (RHEL/CentOS 6, Ubuntu 16 and 18) need Python 2.7.
- RPM-based distributions: `cronie`. On Fedora 35 and later, also `iptables-legacy-libs`.
- Debian-based distributions: `cron` and `python3-venv`.
- RHEL/CentOS 6: `ipset`.

**SELinux.** On SELinux-enabled RHEL-family hosts the installer runs `sudo semodule` and `restorecon`. Make sure `sudo` and `policycoreutils` are installed. The role warns, and does not stop, when SELinux is enabled and `sudo` is missing.

## Legacy platforms

The Zero Networks list of supported operating systems marks some older releases (RHEL/CentOS 6, Ubuntu 16 and 18) with an asterisk. The Segment Connector agent needs Python 2.7 on those releases. Check which Python your hosts actually have.

Ansible also needs a Python on the target that your `ansible-core` release supports:

- Use an `ansible-core` release that supports the Python on the target. Targets that only have Python 2.7 need `ansible-core` 2.16 or earlier. See [Caveats and testing status](#caveats-and-testing-status).
- Or install a newer Python on the target and point Ansible at it with `ansible_python_interpreter` in the inventory (see `inventory.example.ini`). The agent itself still needs Python 2.7 on the asterisk releases.

The install extracts the zip with the target's own Python `zipfile` module, so it does not need `unzip`.

**Legacy platforms were not tested, and the Python 2.7 path has never been run.** Run the playbook against a test host first.

## Caveats and testing status

This is a community example. Test it in a non-production environment first. Confirm support with Zero Networks before you use it in production.

### Tested

| Area | What was tested |
|---|---|
| Hosts | Ansible host and target host, both Rocky Linux 9.8. Systemd, SELinux enforcing, target Python 3.9. |
| Versions | Controller ansible-core 2.14.18. Installer 1.2.22.0 (connector 1.0.14.0). |
| Scenarios on real hosts | `--check`. Install with `allow_create` and an explicit FQDN. Install skipped on a host that is already installed. Reinstall. Uninstall. Invalid token. Host not in the portal. No trusted FQDN. Connection check on a healthy host, and on a host with broken DNS for the segment server. The token was not found on the target after the run. |
| Offline tests (fake installer and fake connector logs, ansible-core 2.19) | Environment variable passthrough. Timeout conversion. Validation rules. Check-mode behaviour. Connection-check states and the wait loop. |
| Static checks | `--syntax-check` on ansible-core 2.16 and 2.19. `ansible-lint` with the production profile. |

### Not tested

- Target hosts with Python 2.7 or older. The role's inline Python is written to be Python 2.7 compatible, but it has never been run on Python 2.7. Python 2.6 and earlier is not tested and not expected to work.
- ansible-core 2.12, 2.13, 2.15, 2.17 and 2.18. (2.12 is the declared minimum.)
- Any distribution other than Rocky Linux 9.8, including RHEL/CentOS 6, Ubuntu, Debian, SUSE, Amazon Linux, Fedora, Oracle Linux, Photon OS, Kali and Linux Mint.
- sysvinit (init.d) hosts.
- Enrollment by static IP or by asset ID.
- `segment_connector_force`.
- `segment_connector_run_as=root`.
- Trace and console logging, `segment_connector_download_timeout` and `segment_connector_installer_env` on a real host.
- `--check` with the uninstall playbook.
- A token supplied through Ansible Vault or the environment variable. Only a `-e @secrets.yml` file was used.
- AWX or Ansible Automation Platform.
- Proxies.
- Real runs from a non-Linux controller.
- Installer versions other than 1.2.22.0. The connection check reads connector log messages, and those messages may change.

**Python 2.7 and ansible-core.** ansible-core 2.17 and later need Python 3.7 or later on target hosts. So targets that only have Python 2.7 need ansible-core 2.16 or earlier. The role declares 2.12 as its minimum, so the version window for Python 2.7 targets is ansible-core 2.12 to 2.16. This window is untested. In general, choose an `ansible-core` release whose support matrix covers both your controller Python and the Python on every target: very new targets can need a newer release, and old targets an older one. Confirm the current versions in the Ansible core support matrix before you rely on them.

### Functional caveats

- The role itself does not install the agent's runtime packages. See [Target host requirements](#target-host-requirements). However, if enabled (is by default), the setup process with the Segment Server, proceeding initial installation, will install packages. To enable or disable this, navigate to **Settings > Entity Repositories > Linux > Expand applicable linux profile > Allow package installation**.
- The portal must be able to derive a trusted FQDN for the host, or you must set one with `segment_connector_asset_fqdn` or static IP. Names such as `*.local` were not accepted in testing.
- The connection check is best-effort. It does not prove that the portal shows the asset as Connected.
- The connection check depends on connector log messages. It was verified with installer 1.2.22.0 only.

## License

MIT

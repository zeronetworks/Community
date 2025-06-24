# Zero Networks Connect Server Installer

This is an automated Bash script designed to simplify the installation of the Zero Networks Connect Server on supported Linux systems.

---

## Features

- Automatically installs required dependencies (`unzip`)
- Supports passing the download URL as a CLI argument or prompts interactively
- Checks for existing Connect Server installations and offers update or reuse options
- Prompts securely for your Connect Server token (or accepts it via environment variable)
- Extracts, validates, and launches the Connect Server installer
- Performs post-install log analysis (if `setup.log` exists) to explain common failure causes

---

## Usage

### Option 1: Fully Interactive

Run the script directly:

```bash
bash <(curl -sSL https://raw.githubusercontent.com/Chris-b-aka-crispy/zero-connect-installer/main/installer.sh)
```

You'll be prompted for:

- The setup package URL
- Your Connect Server token
- Whether to update or skip existing installation

### Option 2: With CLI arguments

```bash
bash <(curl -sSL https://raw.githubusercontent.com/Chris-b-aka-crispy/zero-connect-installer/main/installer.sh) --url <PACKAGE_URL>
```

You can also set your token as an environment variable:

```bash
export ZNC_TOKEN=<your_token>
```

This avoids the interactive token prompt.

---

## Example

```bash
export ZNC_TOKEN="<your_jwt_token>"
bash <(curl -sSL https://raw.githubusercontent.com/Chris-b-aka-crispy/zero-connect-installer/main/installer.sh) --url "https://download.link/path/to/zero-connect-server-setup-<version>.zip"
```

---

## What it does

1. Installs required tools silently if missing
2. Parses version from the provided package URL
3. Creates a directory like `zero-connect-server-setup-5.1.3.0`
4. Downloads and unzips the Connect Server package
5. Flattens nested ZIP structure if needed
6. Writes your token to a local file with secure permissions
7. Makes all internal binaries/scripts executable
8. Runs the `zero-connect-setup` binary with `-token $token`
9. Cleans up the token file
10. If setup.log is generated, parses it and explains any failure (APT lock, missing token, low disk space, etc.)

---

## Requirements

- Ubuntu/Debian or RHEL/CentOS-based system
- Root or sudo privileges

---

## Notes

- If a version is already installed, you can reuse it or download a new one.
- The token must be a valid JWT of at least 400 characters. (Just a sanity copy+paste check)
- The script performs minimal validation and sanitization; run it in a controlled environment.
- No telemetry, no background services. Everything is local and transparent.

---

## Troubleshooting

- If the script fails with `invalid argument`, verify that your token is complete and properly quoted.
- If the token is incorrect or missing, the installer may silently exit.
- If the script exits without explanation, check for a `setup.log` file in the install directory—this script parses it and surfaces known failure reasons automatically.

---

### APT Lock Error

If another process (like `apt`, `apt-daily`, or an auto-updater) is running during install, the script may fail to install required packages like `net-tools`.

**What to check:**

if a PID is returned, stop the process:

`sudo kill -9 <PID>`

`sudo rm -f /var/lib/dpkg/lock-frontend`

Then re-run the installer.

## License

© Zero Networks. All rights reserved. Unauthorized distribution or modification is prohibited.

---

## Author

Chris Boehm (Field CTO @ Zero Networks)  
https://github.com/Chris-b-aka-crispy

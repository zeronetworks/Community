# Linux Segment Connector Deployment Scripts

This folder has two scripts to assist in managing deployment of the Segment Connector (Lightweight Agent) onto Linux servers:
1. `enroll-linux-install-segment-connector.sh`: When ran on a Linux server, will enroll it as a new Linux asset in the Zero Networks portal, and then install the Segment Connector package accompanying the script.
2. `uninstall-linux-segment-connector.sh`: Uninstalls the Segment Connect from a Linux asset

## Script Prerequisites

- Root/sudo access (both scripts must be run as root)
- Network connectivity to the Zero Networks portal
- A valid **super admin** API key for your Zero Networks portal
- A valid **installation token** for to use with the Segment Connector installation package. Can be generated in the portal at **Settings > Segment > Segment Connector**.
- Latest Linux Segment Connector installation package (ZIP archive). Can be downloaded in the portal at **Settings > Segment > Segment Connector**.

Note: **You must deploy the installation package alongside either script.**

## Server Software Prerquisites
Your server MUST have the following software packages **to run the scripts**:
- **curl** (required for `enroll-linux-install-segment-connector.sh` only)
- **jq** (required for `enroll-linux-install-segment-connector.sh` only)
- **One of the following zip extraction tools** (required for both scripts):
  - `unzip`
  - `python3`
  - `python`
  - `jar`

  *The list above is NOT the dependcies the Segment Connector requires to run. If you have questions regarding the Segment Connectors software dependencies, please contact support@zeronetworks.com.*

# How to enroll your Linux server in Zero Networks and install the Segment Connector

```enroll-linux-install-segment-connector.sh```

This script enrolls a Linux asset into the Zero Networks portal and installs the segment connector.

### Parameters

#### Required Parameters

- `--api-token, -t <token>`  
  The API token used to authenticate with the Zero Networks portal API. This token is required for enrolling the asset.

- `--install-token, -i <token>`  
  The install token used by the segment connector installer during installation.

- `--installer-path, -p <path>`  
  The path to the segment connector installer package. 

#### Optional Parameters

- `--portal-url, -u <url>`  
  The URL of your Zero Networks portal (e.g `https://mycompany-admin.zeronetworks.com`).

- `--run-as-root`  
  A switch that causes the segment connector to be installed with the `--run-as=root` parameter. This forces the connector to run as the root user.

- `--debug, -v`  
  Enables debug mode, which outputs additional debug-level logging messages throughout script execution.

- `--help, -h`  
  Displays the usage information and exits.

### How It Works
1. **Installer Extraction**: The script extracts the installer executable from the provided zip archive using one of the available tools (unzip, python3, python, or jar).

1. **Enrollment IP/FQDN Determination**: The script determines whether to use the server's FQDN (from `hostname -f`) or IP address for enrollment:
   - If the hostname is a valid FQDN format, it uses the FQDN
   - Otherwise, it queries the Zero Networks API to find the primary segment server and determines the which of the servers interface IP addresses route towards it.

4. **Asset Enrollment**: The script enrolls the asset in the Zero Networks portal using the API. If the API indicates the asset is already enrolles, it attempts to retrieve the existing asset ID before continuing.

5. **Installation**: The script executes the segment connector installer executable with the required parameters.

### Example Usage

**Basic installation:**
```bash
sudo ./enroll-linux-install-segment-connector.sh \
  --api-token "your-api-token" \
  --install-token "your-install-token" \
  --installer-path "./segment-connector-linux-installer-1.2.13.0.zip" \
  --portal-url "https://portal.zeronetworks.com"
```

**Installation with debug output:**
```bash
sudo ./enroll-linux-install-segment-connector.sh \
  -t "your-api-token" \
  -i "your-install-token" \
  -p "./segment-connector-linux-installer-1.2.13.0.zip" \
  -u "https://portal.zeronetworks.com" \
  --debug
```

**Installation with run-as-root flag:**
```bash
sudo ./enroll-linux-install-segment-connector.sh \
  --api-token "your-api-token" \
  --install-token "your-install-token" \
  --installer-path "./segment-connector-linux-installer-1.2.13.0.zip" \
  --portal-url "https://portal.zeronetworks.com" \
  --run-as-root
```

**Installation using environment variables:**
```bash
sudo ./enroll-linux-install-segment-connector.sh \
  -t "$ZN_API_KEY" \
  -p "$INSTALL_ARCHIVE_PATH" \
  -u "$BASE_URL" \
  -i "$INSTALL_TOKEN" \
  --debug
```

---

# Uninstalling the Segment Connector from a Linux asset

`uninstall-linux-segment-connector.sh`

This script uninstalls the segment connector from a Linux asset.

### Parameters

#### Required Parameters

- `--install-token, -i <token>`  
  The install token used by the segment connector installer. Required even with uninstallation.

- `--installer-path, -p <path>`  
  The path to the segment connector installer zip archive. The script will extract this archive and execute the uninstaller.

#### Optional Parameters

- `--debug, -v`  
  Enables debug mode, which outputs additional debug-level logging messages throughout script execution.

- `--help, -h`  
  Displays the usage information and exits.

### How It Works

1. **Installer Extraction**: The script extracts the installer executable from the provided zip archive using one of the available tools (unzip, python3, python, or jar).

2. **Uninstallation**: The script executes the segment connector installer with the `-uninstall` flag and the provided install token.

### Example Usage

**Basic uninstallation:**
```bash
sudo ./uninstall-linux-segment-connector.sh \
  --install-token "your-install-token" \
  --installer-path "./segment-connector-linux-installer-1.2.13.0.zip"
```

**Uninstallation with debug output:**
```bash
sudo ./uninstall-linux-segment-connector.sh \
  -i "your-install-token" \
  -p "./segment-connector-linux-installer-1.2.13.0.zip" \
  --debug
```

**Uninstallation using environment variables:**
```bash
sudo ./uninstall-linux-segment-connector.sh \
  -i "$INSTALL_TOKEN" \
  -p "./segment-connector-linux-installer-1.2.13.0.zip" \
  --debug
```

---
# Helpful information 
## Error Handling

Both scripts attempt to catch and handle errors are gracefully as possible. For unrecoverable errors, it attempts to log additional contextual information before terminating. 

If either script is terminating unexpectedly while displaying no relevant error message, please make sure to run the script with the `--debug` or `-v` parameter, then [open an issue](https://github.com/zeronetworks/Community/issues) and include the debug output (redacted of sensitive information).

## Logging

Both scripts use syslog-compatible logging with the following format:
```
<timestamp> <hostname> <program>[<pid>]: <level>: <message>
```

Log levels:
- **INFO**: General informational messages
- **DEBUG**: Detailed debug information (only shown when `--debug` is enabled)
- **WARN**: Warning messages (non-fatal issues)
- **ERROR**: Error messages (fatal issues that cause script termination)

## Troubleshooting

If you encounter issues during installation or uninstallation:

1. Enable debug mode with the `--debug` or `-v` flag to see detailed execution information
2. Check the logs in `/var/zeronetworks/logs/` for detailed error messages from the installer
3. Verify that all required parameters are provided and valid
4. Ensure the system has network connectivity to the Zero Networks portal
5. Confirm that the installer zip archive is not corrupted and contains the expected executable

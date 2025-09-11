#!/bin/zsh

# A Zsh script to install or uninstall the Cloud Connector on macOS.

# --- Default Parameters ---
CLOUD_CONNECTOR_FUNCTION="uninstall"
CLOUD_CONNECTOR_TOKEN="<INSERT_CC_TOKEN>"
CLOUD_CONNECTOR_SOURCE="MANUAL_MAC"

# --- Ensure TMPDIR is set to a writable location ---
TMPDIR="${TMPDIR:-/tmp}"

# --- Usage Instructions ---
usage() {
    echo "Usage: $0 [-f <install|uninstall>] [-t <token>] [-s <source>]"
    echo "  -f, --function    Function to perform: 'install' or 'uninstall'. Default: install"
    echo "  -t, --token       Cloud Connector JWT token. (Required for install)"
    echo "  -s, --source      Cloud Connector source. Default: AD"
    exit 1
}

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--function)
            CLOUD_CONNECTOR_FUNCTION="$2"
            shift 2
            ;;
        -t|--token)
            CLOUD_CONNECTOR_TOKEN="$2"
            shift 2
            ;;
        -s|--source)
            CLOUD_CONNECTOR_SOURCE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# --- Logging Setup ---
LOG_FILE="$TMPDIR/CloudConnector.log"
write_log() {
    local message="$1"
    local level="${2:-INFO}"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

write_log "Script execution started."

# --- Dependency Check ---
if ! command -v jq &> /dev/null; then
    write_log "jq is not installed." "ERROR"
    echo "ERROR: jq is required. Install it with: brew install jq"
    exit 1
fi

if [[ "$CLOUD_CONNECTOR_FUNCTION" == "install" && "$CLOUD_CONNECTOR_TOKEN" == "<INSERT_CC_TOKEN>" ]]; then
    write_log "Token required for installation but not provided." "ERROR"
    echo "ERROR: Provide a token with the -t flag."
    usage
fi

# --- JWT Parsing ---
write_log "Parsing JWT to find audience."
payload=$(echo "$CLOUD_CONNECTOR_TOKEN" | cut -d '.' -f 2)

# Add padding if needed
padding=$(( (4 - ${#payload} % 4) % 4 ))
payload="${payload}$(printf '=%.0s' $(seq 1 $padding))"

decoded_payload=$(echo "$payload" | tr -- '-_' '+/' | base64 --decode 2>/dev/null)
if [[ -z "$decoded_payload" ]]; then
    write_log "Failed to decode JWT payload." "ERROR"
    exit 1
fi

audience=$(echo "$decoded_payload" | jq -r .aud)
if [[ "$audience" == "null" || -z "$audience" ]]; then
    write_log "Missing 'aud' in JWT." "ERROR"
    exit 1
fi
write_log "Audience found: $audience"


# --- Prepare Installer Arguments ---
INSTALLER_ARGS=()

if [[ "$CLOUD_CONNECTOR_FUNCTION" == "install" ]]; then
    INSTALLER_ARGS+=("-install" "-token" "$CLOUD_CONNECTOR_TOKEN" "-source" "$CLOUD_CONNECTOR_SOURCE")
elif [[ "$CLOUD_CONNECTOR_FUNCTION" == "uninstall" ]]; then
    INSTALLER_ARGS+=("-uninstall" "-token" "$CLOUD_CONNECTOR_TOKEN" "-source" "$CLOUD_CONNECTOR_SOURCE")
else
    write_log "Invalid function: $CLOUD_CONNECTOR_FUNCTION" "ERROR"
    usage
fi

# --- API Request for Installer URL ---
INSTALLER_URI="https://${audience}/installer?platform=MAC_ARM64"
write_log "Requesting installer URL from $INSTALLER_URI"

http_response=$(curl -sS -w "\n%{http_code}" \
    -H "Authorization: $CLOUD_CONNECTOR_TOKEN" \
    -H "Content-Type: application/json" \
    "$INSTALLER_URI")

http_status=$(echo "$http_response" | tail -n1)
response_body=$(echo "$http_response" | sed '$d')

if [[ "$http_status" -ne 200 ]]; then
    write_log "Download URL request failed. Status: $http_status" "ERROR"
    exit 1
fi

DOWNLOAD_URL=$(echo "$response_body" | jq -r .url)
if [[ "$DOWNLOAD_URL" == "null" || -z "$DOWNLOAD_URL" ]]; then
    write_log "Missing download URL in response." "ERROR"
    exit 1
fi
write_log "Download URL retrieved."

# --- Download & Extract ---
FILE_NAME="znCC-Installer"
ZIP_PATH="$TMPDIR/$FILE_NAME.zip"
INSTALLER_FOLDER_PATH="$TMPDIR/$FILE_NAME"

write_log "Downloading installer to $ZIP_PATH"
curl -L --fail -o "$ZIP_PATH" "$DOWNLOAD_URL" || {
    write_log "Download failed." "ERROR"
    exit 1
}

write_log "Extracting installer to $INSTALLER_FOLDER_PATH"
unzip -o "$ZIP_PATH" -d "$INSTALLER_FOLDER_PATH" || {
    write_log "Extraction failed." "ERROR"
    exit 1
}

INSTALLER_FILE=$(find "$INSTALLER_FOLDER_PATH" -type f -name "cloud-connector-installer" | head -n 1)

if [[ -z "$INSTALLER_FILE" || ! -x "$INSTALLER_FILE" ]]; then
    write_log "Installer file 'cloud-connector-installer' not found or not executable." "ERROR"
    exit 1
fi


write_log "Found installer: $INSTALLER_FILE"
write_log "Executing installer with token."

chmod +x "$INSTALLER_FILE"
#write_log "Executing installer with args: ${INSTALLER_ARGS[*]}"
sudo "$INSTALLER_FILE" "${INSTALLER_ARGS[@]}"

if [[ $? -ne 0 ]]; then
    write_log "Installer execution failed." "ERROR"
    exit 1
fi
write_log "Installer executed successfully."


if [[ $? -ne 0 ]]; then
    write_log "Installer execution failed." "ERROR"
    exit 1
fi

# --- Tail Setup Log ---
SETUP_LOG_PATH="$HOME/Library/Logs/ZeroNetworks/setup.log"
[[ -f "$SETUP_LOG_PATH" ]] && write_log "Setup log: $(tail -n 1 "$SETUP_LOG_PATH")"

# --- Cleanup ---
write_log "Cleaning up..."
rm -f "$ZIP_PATH"
rm -rf "$INSTALLER_FOLDER_PATH"

# --- Uninstall Cleanup ---
if [[ "$CLOUD_CONNECTOR_FUNCTION" == "uninstall" ]]; then
    SERVICE_NAME="com.zeronetworks.zncloudconnector"
    SYSTEM_PATH="/Library/Application Support/ZeroNetworks"

    if launchctl list | grep -q "$SERVICE_NAME"; then
        write_log "Stopping service: $SERVICE_NAME"
        sudo launchctl bootout system "/Library/LaunchDaemons/$SERVICE_NAME.plist" 2>/dev/null
    fi

    if [[ -d "$SYSTEM_PATH" ]]; then
        write_log "Removing system files..."
        sudo rm -rf "$SYSTEM_PATH" || write_log "Failed to remove system files." "WARNING"
    fi
fi

write_log "Script completed successfully."
echo "Done. See log: $LOG_FILE"

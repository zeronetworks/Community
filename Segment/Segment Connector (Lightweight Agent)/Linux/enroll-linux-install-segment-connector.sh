#!/bin/bash
set -euo pipefail

# Script to handle command-line parameters
# Parameters:
#   --api-token, -t: API token (required)
#   --install-token, -i: Install token (required)
#   --run-as-root: Run as root (switch)
#   --installer-path, -p: Installer path (optional)
#   --debug, -v: Debug mode (switch)
#   --portal-url, -u: Portal URL (optional, defaults to https://portal.zeronetworks.com)

# Initialize parameter variables
API_TOKEN=""
INSTALL_TOKEN=""
RUN_AS_ROOT=false
INSTALLER_PATH=""
DEBUG=false
PORTAL_URL="https://portal.zeronetworks.com"
TESTING_MODE=false

# Constants
EXECUTABLE_NAME="segment-connector-linux-installer"
INSTALL_LOG_DIR="/var/zeronetworks/logs/"

# Variables that will be dynamically populated during script execution
SERVER_FULL_HOSTNAME=$(hostname -f)
NAMESERVER_IP=""
ENROLLMENT_IP_OR_FQDN=""
EXECUTABLE_PATH=""
SERVER_IP_ADDRESS=""
SERVER_ETH_INTERFACE=""

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --api-token, -t <token>     API token (required)"
    echo "  --install-token, -i <token> Install token (required)"
    echo "  --run-as-root               Run as root (switch)"
    echo "  --installer-path, -p <path> Installer path (optional)"
    echo "  --debug, -v                 Enable debug mode (switch)"
    echo "  --portal-url, -u <url>      Portal URL (optional, defaults to https://portal.zeronetworks.com)"
    echo "  --help, -h                  Display this help message"
    echo ""
    exit 1
}

# Logging functions following syslog best practices
# Format: <timestamp> <hostname> <program>[<pid>]: <level>: <message>
log_info() {
    local message="$1"
    local timestamp=$(date '+%b %d %H:%M:%S')
    local hostname=$(hostname -s 2>/dev/null || echo "localhost")
    local program=$(basename "$0")
    local pid=$$
    echo "$timestamp $hostname $program[$pid]: INFO: $message"
}

log_debug() {
    local message="$1"
    if [[ "$DEBUG" == true ]]; then
        local timestamp=$(date '+%b %d %H:%M:%S')
        local hostname=$(hostname -s 2>/dev/null || echo "localhost")
        local program=$(basename "$0")
        local pid=$$
        echo "$timestamp $hostname $program[$pid]: DEBUG: $message"
    fi
}

log_warn() {
    local message="$1"
    local timestamp=$(date '+%b %d %H:%M:%S')
    local hostname=$(hostname -s 2>/dev/null || echo "localhost")
    local program=$(basename "$0")
    local pid=$$
    echo "$timestamp $hostname $program[$pid]: WARN: $message" >&2
}

log_error() {
    local message="$1"
    local timestamp=$(date '+%b %d %H:%M:%S')
    local hostname=$(hostname -s 2>/dev/null || echo "localhost")
    local program=$(basename "$0")
    local pid=$$
    echo "$timestamp $hostname $program[$pid]: ERROR: $message" >&2
    exit 1
}

log_error_no_exit() {
    local message="$1"
    local timestamp=$(date '+%b %d %H:%M:%S')
    local hostname=$(hostname -s 2>/dev/null || echo "localhost")
    local program=$(basename "$0")
    local pid=$$
    echo "$timestamp $hostname $program[$pid]: ERROR: $message" >&2
}
# Function to get primary IP address
get_primary_ip() {

    if [[ -z "${PRIMARY_SEG_SERVER_IP:-}" ]]; then
        log_error "Primary segment server IP is not set! Unable to determine correct interface IP address. Exiting..."
    fi
    
    log_debug "Will determine correct interface IP address by calling 'ip route get $PRIMARY_SEG_SERVER_IP'"
    # Try ip route method first (most reliable)
    SERVER_IP_ADDRESS=$(ip route get "$PRIMARY_SEG_SERVER_IP" 2>&1 | grep -oP 'src \K\S+' || true)

    if [[ -z "$SERVER_IP_ADDRESS" || $? -ne 0 ]]; then
        log_error "Unable to determine correct interface IP address! Found no route to segment server $PRIMARY_SEG_SERVER_IP!"
    fi

}

get_primary_segment_server_ip() {
    ########################################################
    # Get primary segment server IP address
    ########################################################
    DEPLOYMENTS_URL="$BASE_API_URL/environments/deployments"
    log_debug "Calling zero networks API to retrieve primary segment server IP address. API URL: $DEPLOYMENTS_URL"

    DEPLOYMENTS_RESPONSE=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: $API_TOKEN" \
        "$DEPLOYMENTS_URL" 2>&1
    )

    if [[ $? -ne 0 || -z "$DEPLOYMENTS_RESPONSE" ]]; then
        log_error "Failed to retrieve segment server deployments from API! Error: $?"
    fi

    HTTP_STATUS_CODE=$(echo "$DEPLOYMENTS_RESPONSE" | tail -n 1)
    DEPLOYMENTS_BODY=$(echo "$DEPLOYMENTS_RESPONSE" | sed '$d')

    if [[ "$HTTP_STATUS_CODE" -ne 200 ]]; then
        log_error "Failed to retrieve deployments! HTTP status code: $HTTP_STATUS_CODE, and response body: $DEPLOYMENTS_BODY"
    fi
    log_debug "Deployments response body: $DEPLOYMENTS_BODY"

    # Filter response to find seg server with state == 1 (primary) and get it's IP address
    if ! PRIMARY_SEG_SERVER_IP=$(echo "$DEPLOYMENTS_BODY" | jq -r '.items[] | select(.state == 1) | .internalIpAddress // empty' 2>/dev/null); then
        log_error "Unable to determine primary segment server IP address! Failed to parse deployments response with jq"
    elif [[ -z "$PRIMARY_SEG_SERVER_IP" ]] || [[ "$PRIMARY_SEG_SERVER_IP" == "null" ]]; then
        log_error "Unable to determine primary segment server IP address! API likely returned 0 segment servers or no primary segment server found (state == 1) in deployments response."
    fi
    log_debug "Retrieved primary segment server IP address from API: $PRIMARY_SEG_SERVER_IP"
}

determine_enrollment_ip_or_fqdn() {
    # When enrolling an asset into the portal, ideally, you use an FQDN. 
    # However, not every asset might have an ACTUAL FQDN hostname.
    # So this function determines if the hostname -f is an FQDN, and if not, tries to determine the proper
    # IP address to use for enrollment.
    
    # Validate that the hostname -f is a valid FQDN format using regex
    if [[ "$SERVER_FULL_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        log_debug "Server long-form hostname, $SERVER_FULL_HOSTNAME, is a valid FQDN format. Will use server's long-form hostname during enrollment."
        ENROLLMENT_IP_OR_FQDN="$SERVER_FULL_HOSTNAME"
    else
        log_warn "Server long-form hostname, $SERVER_FULL_HOSTNAME, is not a valid FQDN format. Will use server's IP address during enrollment."
        get_primary_segment_server_ip
        get_primary_ip
        log_debug "Determined servers primary IP address (which routes to segment server $PRIMARY_SEG_SERVER_IP) is $SERVER_IP_ADDRESS"
        ENROLLMENT_IP_OR_FQDN="$SERVER_IP_ADDRESS"
    fi
    
    log_info "Will use the following IP/FQDN for server $SERVER_FULL_HOSTNAME during zero networks enrollment: $ENROLLMENT_IP_OR_FQDN"

}

extract_installer_from_zip() {
    # This code will attempt to extract the installer from the zip file using the following tools: unzip, python3, python, or jar
    # Multiple tools are supported for flexibility across different systems.
    local zipfile="$1"
    local dest="${zipfile::-4}"
    # Combine the destination with the expected executable name to get the relative path to the executable
    EXECUTABLE_PATH="$dest/$EXECUTABLE_NAME"

    if [[ ! -f "$dest" ]]; then
        log_warn "Destination directory $dest already exists! Removing it to avoid conflicts."
        rm -rf "$dest"
    fi
    
    if command -v unzip &> /dev/null; then
    log_debug "Extracting installer from zip file $zipfile to $dest using unzip"
        unzip -q "$zipfile" 2>&1
    elif command -v python3 &> /dev/null; then
        log_debug "Extracting installer from zip file $zipfile to $dest using python3"
        python3 -c "import zipfile; zipfile.ZipFile('$zipfile').extractall()" 2>&1
    elif command -v python &> /dev/null; then
        log_debug "Extracting installer from zip file $zipfile to $dest using python"
        python -c "import zipfile; zipfile.ZipFile('$zipfile').extractall()" 2>&1
    elif command -v jar &> /dev/null; then
        log_debug "Extracting installer from zip file $zipfile to $dest using jar"
        (jar xf "$zipfile" 2>&1)
    else
        log_error "No zip extraction tool available (unzip, python3, python, or jar required)"
    fi

    if [[ $? -ne 0 ]]; then
        log_error "Failed to extract installer from zip file $zipfile! Error: $?"
    fi

    # Validate that the executable path exists after extraction
    if [[ ! -f "$EXECUTABLE_PATH" ]]; then
        log_error "Path to extracted installer $EXECUTABLE_PATH does not exist! Failed to extract installation zip!"
    fi
    log_info "Extracted installer $EXECUTABLE_PATH"

}

mark_installer_as_executable() {
    # Validate that the executable path is set and exists
    if [[ -z "$EXECUTABLE_PATH" ]]; then
        log_error "Executable path is not set! Failed to mark installer as executable"
    fi
    # Mark the installer as executable
    log_debug "Marking installer $EXECUTABLE_PATH as executable"
    chmod +x "$EXECUTABLE_PATH"
    # Validate that the installer is executable
    if [[ ! -x "$EXECUTABLE_PATH" ]]; then
        log_error "Failed to mark installer $EXECUTABLE_PATH as executable"
    fi
    log_debug "Marked installer $EXECUTABLE_PATH as executable"
}

########################################################
# Parse command-line arguments
########################################################
if [[ $# -eq 0 ]]; then
    usage
fi
# This will parse the command-line arguments and set the appropriate variables
# It will also validate that parameters requiring a value have one
while [[ $# -gt 0 ]]; do
    case $1 in
        --api-token|-t)
            if [[ -z "$2" ]] || [[ "$2" == -* ]]; then
                log_error "Error: --api-token (-t) requires a value"
                usage
            fi
            API_TOKEN="$2"
            shift 2
            ;;
        --install-token|-i)
            if [[ -z "$2" ]] || [[ "$2" == -* ]]; then
                log_error "Error: --install-token (-i) requires a value"
                usage
            fi
            INSTALL_TOKEN="$2"
            shift 2
            ;;
        --run-as-root)
            RUN_AS_ROOT=true
            shift
            ;;
        --installer-path|-p)
            if [[ -z "$2" ]] || [[ "$2" == -* ]]; then
                log_error "Error: --installer-path (-p) requires a value"
            fi
            INSTALLER_PATH="$2"
            shift 2
            ;;
        --debug|-v)
            DEBUG=true
            shift
            ;;
        --testing-mode)
            TESTING_MODE=true
            shift
            ;;
        --portal-url|-u)
            if [[ -z "$2" ]] || [[ "$2" == -* ]]; then
                log_error "Error: --portal-url (-u) requires a value"
            fi
            PORTAL_URL="$2"
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        *)
            log_error "Error: Unknown option: $1"
            ;;
    esac
done

########################################################
# Parameter validation
########################################################
# Check for super user permissions, as this script requires it to:
# - Update installer to be executable
# - Install segment connector
if [[ $EUID -ne 0 ]]; then
    log_error "Error: script must be run as root!"
fi

if [[ -z "$PORTAL_URL" ]]; then
    log_error "Error: --portal-url (-u) is required"
fi

if [[ -z "$API_TOKEN" ]]; then
    log_error "Error: --api-token (-t) is required"
fi

if [[ -z "$INSTALL_TOKEN" ]]; then
    log_error "Error: --install-token (-i) is required"
fi

########################################################
# Main script logic starts here
########################################################
log_info "Starting script to enroll $SERVER_FULL_HOSTNAME into Zero Networks portal and install segment connector"
# Define base API URL
BASE_API_URL="$PORTAL_URL/api/v1"

########################################################
# Log basic parameter information
########################################################
log_debug "PORTAL_URL: $PORTAL_URL"
log_debug "BASE_API_URL: $BASE_API_URL"
log_debug "INSTALLER_PATH: $INSTALLER_PATH"
log_debug "SERVER_FULL_HOSTNAME: $SERVER_FULL_HOSTNAME"
log_debug "RUN_AS_ROOT: $RUN_AS_ROOT"
log_debug "DEBUG: $DEBUG"

if [[ "$TESTING_MODE" == true ]]; then
    log_debug "TESTING_MODE: $TESTING_MODE"
fi
if [[ "$RUN_AS_ROOT" == true ]]; then
    log_info "Will install segement connector with -run-as=root parameter."
fi

###############################################################################
# Validate installer path, extract installer if valid, and mark as executable
###############################################################################
if [[ -z "$INSTALLER_PATH" ]]; then
    log_error "Error: --installer-path (-p) is required"
elif [[ -n "$INSTALLER_PATH" ]]; then
    if [[ ! -f "$INSTALLER_PATH" ]]; then
        log_error "Path to segment connector installer archive does not exist: $INSTALLER_PATH"
    else
        log_info "Path to segment connector installer is valid: $INSTALLER_PATH"
        extract_installer_from_zip "$INSTALLER_PATH"
        mark_installer_as_executable
    fi
fi

########################################################
# Determine whether to use FQDN or IP address for enrollment
########################################################
determine_enrollment_ip_or_fqdn
log_info "Will use the following IP/FQDN for server during zero networks enrollment: $ENROLLMENT_IP_OR_FQDN"

########################################################
# Enroll asset in portal
########################################################
log_info "Calling zero networks API to enroll asset in portal."

# ONLY USE DURING TESTING
# This randomizes the asset name before enrollment, as ZN cannot have duplicate asset names,
# and you cannot remove manually enrolled linux assets from the portal 🙃.
if [[ "$TESTING_MODE" == true ]]; then
    log_debug "Randomizing asset name for testing purposes."
    SERVER_FULL_HOSTNAME="$(date +%s)-$SERVER_FULL_HOSTNAME"
    OLD_ENROLLMENT_IP_OR_FQDN="$ENROLLMENT_IP_OR_FQDN"
    ENROLLMENT_IP_OR_FQDN="10.$((RANDOM%199+1)).$((RANDOM%254+1)).$((RANDOM%254+1))"
    log_debug "Randomized asset name to $SERVER_FULL_HOSTNAME"
    log_debug "Randomized enrollment IP or FQDN to $ENROLLMENT_IP_OR_FQDN"
fi

ENROLLMENT_URL="$BASE_API_URL/assets/linux"
ENROLLMENT_PAYLOAD="{\"displayName\": \"$SERVER_FULL_HOSTNAME\", \"fqdn\": \"$ENROLLMENT_IP_OR_FQDN\"}"
log_debug "Enrollment API URL: $ENROLLMENT_URL"
log_debug "Enrollmentpayload $ENROLLMENT_PAYLOAD"

ENROLLMENT_RESPONSE=$(curl -s -X POST -w "\n%{http_code}" "$BASE_API_URL/assets/linux" \
  -H "Content-Type: application/json" \
  -H "Authorization: $API_TOKEN" \
  -d "{\"displayName\": \"$SERVER_FULL_HOSTNAME\", \"fqdn\": \"$ENROLLMENT_IP_OR_FQDN\"}"
)
HTTP_STATUS_CODE=$(echo "$ENROLLMENT_RESPONSE" | tail -n 1)
ENROLLMENT_BODY=$(echo "$ENROLLMENT_RESPONSE" | sed '$d')

if [[ "$HTTP_STATUS_CODE" -ne 200 ]]; then
    log_warn "Failed to enroll asset in portal! HTTP status code: $HTTP_STATUS_CODE, and response body: $ENROLLMENT_BODY"
    
    # If a status code of 409 is returned, then the asset is already enrolled in the portal.
    # We will attempt to retrieve the existing asset ID and continue with installation.
    if [[ "$HTTP_STATUS_CODE" -eq 409 ]]; then
        
        log_warn "Asset already enrolled in portal! Will attempt to retreive existing asset ID and continue with installation."

        #--data-urlencode "_limit=1" \
        #--data-urlencode "_filters=[{\"id\":\"name\",\"includeValues\":[\"$SERVER_FULL_HOSTNAME\"]}]" \
        FILTERS_JSON=$(echo "[{\"id\":\"name\",\"includeValues\":[\"$SERVER_FULL_HOSTNAME\"]}]" | jq -rR @uri)
        ASSET_URL="$BASE_API_URL/assets?_limit=1&_filters=$FILTERS_JSON"
        log_debug "Asset API URL: $ASSET_URL"
        ASSET_RETRIEVAL_RESPONSE=$(curl -s -w "\n%{http_code}" "$ASSET_URL" \
            -H "Content-Type: application/json" \
            -H "Authorization: $API_TOKEN" \
        )

        HTTP_STATUS_CODE=$(echo "$ASSET_RETRIEVAL_RESPONSE" | tail -n 1)
        ASSET_RETRIEVAL_BODY=$(echo "$ASSET_RETRIEVAL_RESPONSE" | sed '$d')
        
        if [[ "$HTTP_STATUS_CODE" -ne 200 ]]; then
            log_error "Failed to retrieve existing asset ID! HTTP status code: $HTTP_STATUS_CODE, and response body: $ASSET_RETRIEVAL_BODY"
        fi
        
        log_debug "Asset retrieval response body: $(jq -r '.' <<< "$ASSET_RETRIEVAL_BODY")"
        
        if ! ASSET_ID=$(echo "$ASSET_RETRIEVAL_BODY" | jq -r '.items[0].id // empty' 2>/dev/null); then
            log_error "Unable to determine asset ID! Failed to parse asset retrieval response with jq"
        elif [[ -z "$ASSET_ID" ]] || [[ "$ASSET_ID" == "null" ]]; then
            log_error "Unable to determine asset ID! API likely returned 0 assets or no asset was returned in asset retrieval response."
        fi

        log_info "Successfully retrieved existing asset ID $ASSET_ID for $SERVER_FULL_HOSTNAME in Zero Networks portal ($PORTAL_URL)"
    else
        log_error "Failed to enroll asset in portal! HTTP status code: $HTTP_STATUS_CODE, and response body: $ENROLLMENT_BODY"
    fi
#Else if status code is 200, it successfully enrolled the asset in the portal.
else
    log_debug "Enrollment response body: $(jq -r '.' <<< "$ENROLLMENT_BODY")"
    if ! ASSET_ID=$(echo "$ENROLLMENT_BODY" | jq -r '.items[0] // empty' 2>/dev/null); then
        log_error "Unable to determine asset ID! Failed to parse enrollment response with jq"
    elif [[ -z "$ASSET_ID" ]] || [[ "$ASSET_ID" == "null" ]]; then
        log_error "Unable to determine asset ID! API likely returned 0 assets or no asset was returned in enrollment response."
    fi
    log_info "Successfully enrolled $SERVER_FULL_HOSTNAME as asset $ASSET_ID in Zero Networks portal ($PORTAL_URL)"
fi

# If random asset name was used for testing, revert it back to the original hostname
if [[ "$TESTING_MODE" == true ]]; then
    SERVER_FULL_HOSTNAME=$(hostname -f)
    ENROLLMENT_IP_OR_FQDN="$OLD_ENROLLMENT_IP_OR_FQDN"
    log_debug "Reverted randomized asset name back to hostname: $SERVER_FULL_HOSTNAME"
    log_debug "Reverted randomized enrollment IP or FQDN back to original: $ENROLLMENT_IP_OR_FQDN"
fi

########################################################
# Install segment connector
########################################################
# Install segment connector using installer path, propagating any errors
log_info "Attempting to install segment connector using executable path: $EXECUTABLE_PATH"

# Validate installer path and executable permissions one last time before running
if [[ ! -f "$EXECUTABLE_PATH" ]]; then
    log_error "Installer not found: $EXECUTABLE_PATH"
fi

if [[ ! -x "$EXECUTABLE_PATH" ]]; then
    log_error "Installer is not executable: $EXECUTABLE_PATH"
fi

# Build command arguments
INSTALLER_ARGS=(
    "-install" 
    "-assetId" "$ASSET_ID" # This are side-by-side just for readability
    "-token" "$INSTALL_TOKEN" # They are still different indices in the array
)

if [[ "$RUN_AS_ROOT" == true ]]; then
    log_debug "Adding --run-as=root to installer arguments"
    INSTALLER_ARGS+=("--run-as=root")
fi

log_debug "Installation command to be executed: $EXECUTABLE_PATH ${INSTALLER_ARGS[*]}"

# Execute with error handling
echo ""
echo "########################################################"
echo "########################################################"
echo "Running segment connector installation... output below:"
echo "########################################################"
echo ""

set +e
"$EXECUTABLE_PATH" "${INSTALLER_ARGS[@]}" 2>&1
INSTALL_EXIT_CODE=$?
set -e

echo ""
echo "########################################################"
echo "########################################################"
echo ""

#INSTALL_OUTPUT="test output"
#INSTALL_EXIT_CODE=1

if [[ "$INSTALL_EXIT_CODE" -ne 0 ]]; then
    log_error_no_exit "Segment connector installation failed with exit code $INSTALL_EXIT_CODE"
    log_error "Retrieve the contents of /var/zeronetworks/logs/ to further troubleshoot the installation failure."
fi


log_info "Segment connector installed successfully"

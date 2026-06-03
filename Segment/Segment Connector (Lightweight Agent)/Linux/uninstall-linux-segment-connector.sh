#!/bin/bash
set -euo pipefail

# Script to handle command-line parameters
# Parameters:
#   --install-token, -i: Install token (required)
#   --installer-path, -p: Installer path (optional)
#   --debug, -v: Debug mode (switch)

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
    echo "  --install-token, -i <token> Install token (required)"
    echo "  --installer-path, -p <path> Installer path (optional)"
    echo "  --debug, -v                 Enable debug mode (switch)"
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
        --install-token|-i)
            if [[ -z "$2" ]] || [[ "$2" == -* ]]; then
                log_error "Error: --install-token (-i) requires a value"
                usage
            fi
            INSTALL_TOKEN="$2"
            shift 2
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
# - Uninstall segment connector
if [[ $EUID -ne 0 ]]; then
    log_error "Error: script must be run as root!"
fi

if [[ -z "$INSTALL_TOKEN" ]]; then
    log_error "Error: --install-token (-i) is required"
fi

########################################################
# Main script logic starts here
########################################################
log_info "Starting script to uninstall segment connector from $SERVER_FULL_HOSTNAME"

########################################################
# Log basic parameter information
########################################################
log_debug "INSTALLER_PATH: $INSTALLER_PATH"
log_debug "SERVER_FULL_HOSTNAME: $SERVER_FULL_HOSTNAME"
log_debug "DEBUG: $DEBUG"

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
# Uninstall segment connector
########################################################
# Uninstall segment connector using installer path, propagating any errors
log_info "Attempting to uninstall segment connector using executable path: $EXECUTABLE_PATH"

# Validate installer path and executable permissions one last time before running
if [[ ! -f "$EXECUTABLE_PATH" ]]; then
    log_error "Installer not found: $EXECUTABLE_PATH"
fi

if [[ ! -x "$EXECUTABLE_PATH" ]]; then
    log_error "Installer is not executable: $EXECUTABLE_PATH"
fi

# Build command arguments
INSTALLER_ARGS=(
    "-uninstall" 
    "-token" "$INSTALL_TOKEN" # They are still different indices in the array
)

log_debug "Uninstallation command to be executed: $EXECUTABLE_PATH ${INSTALLER_ARGS[*]}"

# Execute with error handling
echo ""
echo "########################################################"
echo "########################################################"
echo "Running command to uninstall segment connector... output below:"
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
    log_error_no_exit "Failed to uninstall segment connector with exit code $INSTALL_EXIT_CODE"
    log_error "Retrieve the contents of /var/zeronetworks/logs/ to further troubleshoot the failure."
fi


log_info "Segment connector uninstalled successfully"

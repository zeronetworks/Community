#!/bin/bash
#
# Zero Networks Cloud Connector — macOS install
#
# Downloads the Cloud Connector installer for this Mac and runs it. Paste your
# enrolment token below, or pass --token, then run as root: through any MDM that
# can execute a shell script, or by hand with sudo.
#
# Usage
#   sudo ./zn-cloud-connector-install.sh [options]
#
#   --token <token>      enrolment token (or set it below, or in ZN_TOKEN)
#   --arch <auto|arm|amd>
#                        which build to fetch. auto (default) reads the
#                        hardware; arm = Apple silicon, amd = Intel
#   --timeout <seconds>  stop the installer if it runs longer than this.
#                        Default 600, 0 = no limit. Keep it below the MDM's own
#                        script time limit, so this script can stop the
#                        installer and restart the connector itself
#   --force              skip the already-installed check and the reinstall
#                        shortcut, and run a full install
#   --force-reprovision  re-register this Mac from scratch. Don't leave it on in
#                        an MDM script that runs repeatedly: every run would
#                        re-register the Mac. The script already retries once
#                        with it when the cloud asks for it (see below)
#   --connect            also install the Zero Networks Connect client
#   --help
#
# Safe to run repeatedly
#   When this Mac is already enrolled, a previous run of this script installed
#   it, and both the connector service and the network extension are running,
#   the script changes nothing and exits 0. Otherwise it runs the installer.
#
#   If the cloud refuses the registration because this Mac is already enrolled
#   (its local identity was lost) or rejects the identity the Mac still has, the
#   script runs the installer once more with -force-reprovision.
#
#   If a run fails or is stopped, the connector services that were running
#   before it started are started again, so a failed re-run does not leave the
#   Mac without its connector.
#
# Exit codes
#   0  installed, or already installed and running
#   1  the installer failed, or a setting is wrong (see the log)
#   2  no user is logged in. The network extension can only be activated in a
#      user's session, so nothing was changed. Run it again later
#   3  another run of this script, or an installer it started, is still in
#      progress on this Mac
#   4  the installer ran longer than --timeout and was stopped
#
# Before this will complete, the Configuration Profile carrying the System
# Extension and Content Filter payloads must be installed.
#
# Output goes to the console and to /var/log/zn-agent-install.log. The
# installer's own log is /var/log/zero-networks/cloud-connector/setup.log.

set -euo pipefail

# --- Settings ----------------------------------------------------------------

# Enrolment token, generated in the Zero Networks portal.
TOKEN="${ZN_TOKEN:-}"

# Defaults for the options above. Command-line switches override them, so an
# MDM can either edit this block or pass parameters.
ARCH=auto
FORCE=false
FORCE_REPROVISION=false
CONNECT=false
TIMEOUT=600

# -----------------------------------------------------------------------------

LOG_FILE=/var/log/zn-agent-install.log
SETUP_LOG=/var/log/zero-networks/cloud-connector/setup.log
IDENTITY_FILE=/etc/zero-networks/cloud-connector/identity.json
# Lives in the connector's own folder, so an uninstall removes it too.
INSTALLED_MARKER=/etc/zero-networks/cloud-connector/install-script-asset-id
LAUNCH_DAEMONS=/Library/LaunchDaemons
SERVICES=(com.zeronetworks.cloudconnector.service com.zeronetworks.cloudconnector.updater)
SERVICE_PROCESS=zn-cloud-connector-service
EXTENSION_PROCESS=zn-segment-extension
LOCK_DIR=/var/run/zn-cloud-connector-install.lock

WORK=""
HAVE_LOCK=false
INSTALLER=""
INSTALLER_PID=""
WAS_LOADED=""
STATUS=0
TIMED_OUT=false

usage() {
    awk 'NR>2 && /^#/ { sub(/^# ?/, ""); print; next } NR>2 { exit }' "$0"
}

say() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*"; }

cleanup() {
    if [ -n "$WORK" ]; then
        rm -rf "$WORK"
    fi
    if [ "$HAVE_LOCK" = true ]; then
        rm -rf "$LOCK_DIR"
    fi
}

# mkdir is atomic, so two runs can't both take the lock. A lock whose owner is
# gone (the run was killed) is taken over; /var/run is also emptied on reboot.
take_lock() {
    local owner

    if mkdir "$LOCK_DIR" 2>/dev/null; then
        echo $$ > "$LOCK_DIR/pid"
        HAVE_LOCK=true
        return 0
    fi

    owner=$(cat "$LOCK_DIR/pid" 2>/dev/null || true)

    if [ -z "$owner" ] || kill -0 "$owner" 2>/dev/null; then
        return 1
    fi

    rm -rf "$LOCK_DIR"
    mkdir "$LOCK_DIR" 2>/dev/null || return 1
    echo $$ > "$LOCK_DIR/pid"
    HAVE_LOCK=true
}

identity_asset_id() {
    if [ -f "$IDENTITY_FILE" ]; then
        LC_ALL=C sed -n 's/.*"AssetID"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$IDENTITY_FILE" 2>/dev/null || true
    fi
}

# Prints why this Mac needs the installer, or nothing when it doesn't. A local
# identity alone is not enough: a run that failed after registering leaves one
# behind. Success is what this script records once the installer exits 0.
install_needed_because() {
    local asset

    asset=$(identity_asset_id)

    if [ -z "$asset" ]; then
        echo "there is no local identity ($IDENTITY_FILE)"
    elif [ "$(cat "$INSTALLED_MARKER" 2>/dev/null || true)" != "$asset" ]; then
        echo "no completed install of asset $asset is recorded on this Mac"
    elif ! launchctl list "${SERVICES[0]}" >/dev/null 2>&1 || ! pgrep -x "$SERVICE_PROCESS" >/dev/null 2>&1; then
        echo "the Cloud Connector service is not running"
    elif ! pgrep -x "$EXTENSION_PROCESS" >/dev/null 2>&1; then
        echo "the network extension is not running"
    fi
}

loaded_services() {
    local label

    for label in "${SERVICES[@]}"; do
        if launchctl list "$label" >/dev/null 2>&1; then
            echo "$label"
        fi
    done
}

# The installer stops the running services before it registers, and on failure
# it doesn't start them again. Put back whatever was running when we began.
restore_services() {
    local label

    for label in $WAS_LOADED; do
        if ! launchctl list "$label" >/dev/null 2>&1 && [ -f "$LAUNCH_DAEMONS/$label.plist" ]; then
            say "Starting $label again, as it was running before this run"
            launchctl load "$LAUNCH_DAEMONS/$label.plist" || say "Could not start $label"
        fi
    done
}

# Children first: the installer runs its package script, which runs installer(8)
# and the Segment app, and those must not outlive it.
signal_tree() {
    local child

    for child in $(pgrep -P "$1" 2>/dev/null || true); do
        signal_tree "$child" "$2"
    done

    kill -"$2" "$1" 2>/dev/null || true
}

stop_installer() {
    local waited=0

    signal_tree "$INSTALLER_PID" TERM

    while kill -0 "$INSTALLER_PID" 2>/dev/null && [ "$waited" -lt 10 ]; do
        sleep 1
        waited=$((waited + 1))
    done

    if kill -0 "$INSTALLER_PID" 2>/dev/null; then
        signal_tree "$INSTALLER_PID" KILL
    fi
}

on_signal() {
    say "Stopped by a signal"

    if [ -n "$INSTALLER_PID" ]; then
        stop_installer
        restore_services
    fi

    exit 143
}

# The installer's console line only carries the innermost error; setup.log has
# the whole chain, so this run's part of it is kept for wants_reprovision.
run_installer() {
    local log_size=0 started

    if [ -f "$SETUP_LOG" ]; then
        log_size=$(stat -f %z "$SETUP_LOG")
    fi

    say "Installing${*:+ ($*)}"

    "$INSTALLER" -install -token "$TOKEN" "$@" > "$WORK/installer.out" 2>&1 &
    INSTALLER_PID=$!
    TIMED_OUT=false
    started=$SECONDS

    while kill -0 "$INSTALLER_PID" 2>/dev/null; do
        if [ "$TIMEOUT" -gt 0 ] && [ $((SECONDS - started)) -ge "$TIMEOUT" ]; then
            say "The installer is still running after ${TIMEOUT}s. Stopping it"
            TIMED_OUT=true
            stop_installer
            break
        fi
        sleep 2
    done

    STATUS=0
    wait "$INSTALLER_PID" || STATUS=$?
    INSTALLER_PID=""

    cat "$WORK/installer.out"
    echo

    : > "$WORK/setup.out"
    if [ -f "$SETUP_LOG" ]; then
        if [ "$(stat -f %z "$SETUP_LOG")" -ge "$log_size" ]; then
            tail -c +$((log_size + 1)) "$SETUP_LOG" > "$WORK/setup.out"
        else
            cp "$SETUP_LOG" "$WORK/setup.out"
        fi
    fi
}

# Retry with -force-reprovision only when the cloud turned down the
# registration itself. A bad token or no route to the cloud won't be fixed by
# re-registering.
wants_reprovision() {
    local output

    output=$(cat "$WORK/installer.out" "$WORK/setup.out" 2>/dev/null || true)

    case "$output" in
        *"invalid or expired token"*|*"failed to contact registration server"*|*"failed to communicate with Cloud service"*)
            return 1 ;;
        *"already provisioned"*|*"failed to run reinstall"*|*"failed to authorize installation"*|*"failed to register cloud connector"*)
            return 0 ;;
    esac

    return 1
}

finish_installed() {
    local asset

    asset=$(identity_asset_id)

    if [ -n "$asset" ]; then
        printf '%s\n' "$asset" > "$INSTALLED_MARKER"
    fi

    say "Done${asset:+ (asset $asset)}"
    exit 0
}

finish_failed() {
    restore_services

    if [ "$TIMED_OUT" = true ]; then
        say "The installer did not finish within ${TIMEOUT}s. See $SETUP_LOG."
        exit 4
    fi

    say "The installer failed (exit $STATUS). See $SETUP_LOG."
    exit 1
}

main() {
    local reason running console_user payload base_url platform url
    local flags=() retry_flags=()

    # Unrecognised arguments are ignored rather than rejected: MDMs prepend
    # their own positional parameters (a mount point, the computer name, the
    # console user) ahead of the operator's, and the offset varies between them.
    while [ $# -gt 0 ]; do
        case "$1" in
            --token)             TOKEN="${2:-}"; shift 2 ;;
            --token=*)           TOKEN="${1#*=}"; shift ;;
            --arch)              ARCH="${2:-}"; shift 2 ;;
            --arch=*)            ARCH="${1#*=}"; shift ;;
            --timeout)           TIMEOUT="${2:-}"; shift 2 ;;
            --timeout=*)         TIMEOUT="${1#*=}"; shift ;;
            --force)             FORCE=true; shift ;;
            --force-reprovision) FORCE_REPROVISION=true; shift ;;
            --connect)           CONNECT=true; shift ;;
            --help|-h)           usage; exit 0 ;;
            *)                   shift ;;
        esac
    done

    if [ "$(id -u)" -ne 0 ]; then
        echo "Run this as root." >&2
        exit 1
    fi

    exec > >(tee -a "$LOG_FILE") 2>&1

    trap cleanup EXIT
    trap on_signal TERM INT HUP

    if ! take_lock; then
        say "Another run of this script is still in progress (pid $(cat "$LOCK_DIR/pid" 2>/dev/null || echo unknown)). Leaving it to finish."
        exit 3
    fi

    # A run the MDM killed outright can leave its installer behind, still
    # working, after its lock has gone stale.
    running=$(pgrep -f 'cloud-connector-installer -install' 2>/dev/null | tr '\n' ' ' || true)

    if [ -n "$running" ]; then
        say "An installer from an earlier run is still running (pid ${running% }). Leaving it to finish."
        exit 3
    fi

    if [ "$FORCE" = true ] || [ "$FORCE_REPROVISION" = true ]; then
        say "Forced run: not checking whether the Cloud Connector is already installed"
    else
        reason=$(install_needed_because)

        if [ -z "$reason" ]; then
            say "Already installed and running (asset $(identity_asset_id)). Nothing to do."
            exit 0
        fi

        say "Installing because $reason"
    fi

    console_user=$(stat -f %Su /dev/console 2>/dev/null || true)

    case "$console_user" in
        ""|root|loginwindow|_mbsetupuser)
            say "No user is logged in. The network extension can only be activated in a user's session, so nothing was changed. Run this again once a user is logged in."
            exit 2
            ;;
    esac

    case "$TIMEOUT" in
        ""|*[!0-9]*)
            say "--timeout must be a whole number of seconds, not '$TIMEOUT'."
            exit 1
            ;;
    esac

    if [ -z "$TOKEN" ]; then
        say "No token. Set TOKEN at the top of this script, pass --token, or set ZN_TOKEN."
        exit 1
    fi

    # The provisioning host is the token's "aud" claim, which is where the
    # installer reads it from too. It is not the portal address: the console is
    # a different host and answers 404 here.
    payload=$(printf '%s' "$TOKEN" | cut -d. -f2 | tr '_-' '/+')

    # JWT segments carry no padding, and base64 -D wants it.
    case $(( ${#payload} % 4 )) in
        2) payload="$payload==" ;;
        3) payload="$payload=" ;;
    esac

    # || true: a token that is not really a JWT makes base64 fail, and pipefail
    # would otherwise kill the script here with no explanation.
    # LC_ALL=C so sed treats the decoded payload as bytes: a token that is not a
    # JWT decodes to binary, and sed would otherwise complain about it first.
    base_url=$(printf '%s' "$payload" | base64 -D 2>/dev/null |
        LC_ALL=C sed -n 's/.*"aud"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p') || true

    if [ -z "$base_url" ]; then
        say "Could not read the tenant from this token. Check it was copied whole."
        exit 1
    fi

    # auto asks the hardware rather than the shell: uname -m reports x86_64 for
    # a script running under Rosetta, and the installer refuses to run
    # translated.
    case "$ARCH" in
        auto)
            if [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = "1" ]; then
                platform=MAC_ARM64
            else
                platform=MAC_X64
            fi
            ;;
        arm|arm64)             platform=MAC_ARM64 ;;
        amd|amd64|x64|x86_64)  platform=MAC_X64 ;;
        *)
            say "Unknown --arch '$ARCH'. Use auto, arm or amd."
            exit 1
            ;;
    esac

    # Flag order follows the Windows builder's sharedFlags, so the two
    # platforms produce comparable command lines.
    #
    # Note -connect is accepted but does nothing on macOS:
    # downloadAndInstallConnect in setup/utils_mac.go is a stub that returns
    # nil. It is wired up here for parity with Windows, and so it starts
    # working if that stub ever does.
    [ "$FORCE" = true ]             && flags+=(-force)
    [ "$FORCE_REPROVISION" = true ] && flags+=(-force-reprovision)
    [ "$CONNECT" = true ]           && flags+=(-connect)

    retry_flags=(-force-reprovision)
    [ "$CONNECT" = true ]           && retry_flags+=(-connect)

    WORK=$(mktemp -d)

    say "Asking $base_url for the $platform installer"

    # /installer answers with a short-lived signed download URL. It takes the
    # raw token with no "Bearer" prefix, and needs no assetId, so this enrols
    # nothing.
    url=$(curl -fsS --connect-timeout 30 --max-time 120 -H "Authorization: $TOKEN" \
        "https://$base_url/installer?platform=$platform" |
        sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p') || true

    if [ -z "$url" ]; then
        say "No download URL came back for $platform."
        exit 1
    fi

    say "Downloading"
    curl -fsS --connect-timeout 30 --max-time 300 -o "$WORK/installer.zip" "$url"
    ditto -x -k "$WORK/installer.zip" "$WORK"

    # The x64 archive's inner folder is named amd64, not x86_64, so the binary
    # is found by name rather than at a predicted path.
    INSTALLER=$(find "$WORK" -type f -name cloud-connector-installer | head -1)

    if [ -z "$INSTALLER" ]; then
        say "The downloaded archive does not contain cloud-connector-installer."
        exit 1
    fi

    chmod +x "$INSTALLER"

    WAS_LOADED=$(loaded_services)
    rm -f "$INSTALLED_MARKER"

    run_installer ${flags[@]+"${flags[@]}"}

    if [ "$STATUS" -eq 0 ]; then
        finish_installed
    fi

    if [ "$TIMED_OUT" = true ] || [ "$FORCE_REPROVISION" = true ] || ! wants_reprovision; then
        finish_failed
    fi

    say "The cloud did not accept this Mac's registration. Trying once more with -force-reprovision"
    run_installer "${retry_flags[@]}"

    if [ "$STATUS" -eq 0 ]; then
        finish_installed
    fi

    finish_failed
}

main "$@"

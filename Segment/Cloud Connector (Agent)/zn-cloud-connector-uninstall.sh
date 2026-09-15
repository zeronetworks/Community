#!/bin/bash
#
# Zero Networks Cloud Connector — macOS uninstall
#
# Downloads the Cloud Connector installer for this Mac and runs its -uninstall:
# it asks the cloud for permission, removes the network extension, stops the
# services and deletes the installed files. Paste your enrolment token below, or
# pass --token, then run as root: through any MDM that can execute a shell
# script, or by hand with sudo.
#
# The tenant comes from the token itself, so there is no host to configure.
#
# Usage
#   sudo ./zn-cloud-connector-uninstall.sh [options]
#
#   --token <token>      enrolment token (or set it below, or in ZN_TOKEN)
#   --arch <auto|arm|amd>
#                        which build to fetch. auto (default) reads the
#                        hardware; arm = Apple silicon, amd = Intel
#   --connect            also uninstall the Zero Networks Connect client
#   --help
#
# There is no --force or --force-reprovision here: the installer's uninstall
# path never reads them.
#
# A user must be logged in. The installer deregisters this Mac before it removes
# the network extension, and removing the extension means launching Zero
# Networks Segment.app in a user session — so an uninstall that runs at the
# login window leaves the Mac enrolled locally but gone from the portal. macOS
# may also prompt that user for their password to remove the extension, which
# blocks the uninstall until someone answers it.
#
# Output goes to the console and to /var/log/zn-agent-install.log.

set -euo pipefail

# --- Settings ----------------------------------------------------------------

# Enrolment token, generated in the Zero Networks portal.
TOKEN="${ZN_TOKEN:-}"

# Defaults for the options above. Command-line switches override them.
ARCH=auto
CONNECT=false

# -----------------------------------------------------------------------------

usage() {
    awk 'NR>2 && /^#/ { sub(/^# ?/, ""); print; next } NR>2 { exit }' "$0"
}

# Unrecognised arguments are ignored rather than rejected: MDMs prepend their
# own positional parameters (a mount point, the computer name, the console
# user) ahead of the operator's, and the offset varies between them.
while [ $# -gt 0 ]; do
    case "$1" in
        --token)     TOKEN="${2:-}"; shift 2 ;;
        --token=*)   TOKEN="${1#*=}"; shift ;;
        --arch)      ARCH="${2:-}"; shift 2 ;;
        --arch=*)    ARCH="${1#*=}"; shift ;;
        --connect)   CONNECT=true; shift ;;
        --help|-h)   usage; exit 0 ;;
        *)           shift ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root." >&2
    exit 1
fi

exec > >(tee -a /var/log/zn-agent-install.log) 2>&1

say() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*"; }

if [ -z "$TOKEN" ]; then
    say "No token. Set TOKEN at the top of this script, pass --token, or set ZN_TOKEN."
    exit 1
fi

# The provisioning host is the token's "aud" claim, which is where the installer
# reads it from too. It is not the portal address: the console is a different
# host and answers 404 here.
PAYLOAD=$(printf '%s' "$TOKEN" | cut -d. -f2 | tr '_-' '/+')

# JWT segments carry no padding, and base64 -D wants it.
case $(( ${#PAYLOAD} % 4 )) in
    2) PAYLOAD="$PAYLOAD==" ;;
    3) PAYLOAD="$PAYLOAD=" ;;
esac

# || true: a token that is not really a JWT makes base64 fail, and pipefail
# would otherwise kill the script here with no explanation.
# LC_ALL=C so sed treats the decoded payload as bytes: a token that is not a
# JWT decodes to binary, and sed would otherwise complain about it first.
BASE_URL=$(printf '%s' "$PAYLOAD" | base64 -D 2>/dev/null |
    LC_ALL=C sed -n 's/.*"aud"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p') || true

if [ -z "$BASE_URL" ]; then
    say "Could not read the tenant from this token. Check it was copied whole."
    exit 1
fi

# auto asks the hardware rather than the shell: uname -m reports x86_64 for a
# script running under Rosetta, and the installer refuses to run translated.
case "$ARCH" in
    auto)
        if [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = "1" ]; then
            PLATFORM=MAC_ARM64
        else
            PLATFORM=MAC_X64
        fi
        ;;
    arm|arm64)             PLATFORM=MAC_ARM64 ;;
    amd|amd64|x64|x86_64)  PLATFORM=MAC_X64 ;;
    *)
        say "Unknown --arch '$ARCH'. Use auto, arm or amd."
        exit 1
        ;;
esac

# -connect is accepted but does nothing on macOS: uninstallConnect in
# setup/utils_mac.go is a stub that returns nil. It is wired up here for parity
# with Windows, and so it starts working if that stub ever does.
FLAGS=()
[ "$CONNECT" = true ] && FLAGS+=(-connect)

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

say "Asking $BASE_URL for the $PLATFORM installer"

# /installer answers with a short-lived signed download URL. It takes the raw
# token with no "Bearer" prefix.
URL=$(curl -fsS -H "Authorization: $TOKEN" \
    "https://$BASE_URL/installer?platform=$PLATFORM" |
    sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

if [ -z "$URL" ]; then
    say "No download URL came back for $PLATFORM."
    exit 1
fi

say "Downloading"
curl -fsS -o "$WORK/installer.zip" "$URL"
ditto -x -k "$WORK/installer.zip" "$WORK"

# The x64 archive's inner folder is named amd64, not x86_64, so the binary is
# found by name rather than at a predicted path.
INSTALLER=$(find "$WORK" -type f -name cloud-connector-installer | head -1)

if [ -z "$INSTALLER" ]; then
    say "The downloaded archive does not contain cloud-connector-installer."
    exit 1
fi

chmod +x "$INSTALLER"

say "Uninstalling${FLAGS[*]:+ (${FLAGS[*]})}"
# Captured rather than left to set -e, so the installer's exit code is
# reported and its output — which carries no trailing newline — is closed off
# on the failure path too.
STATUS=0
"$INSTALLER" -uninstall -token "$TOKEN" ${FLAGS[@]+"${FLAGS[@]}"} || STATUS=$?
echo

if [ "$STATUS" -ne 0 ]; then
    say "The installer failed (exit $STATUS). See /var/log/zero-networks/cloud-connector/setup.log."
    exit "$STATUS"
fi

say "Done"

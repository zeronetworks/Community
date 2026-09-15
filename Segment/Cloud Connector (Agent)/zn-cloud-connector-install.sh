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
#   --force              skip the reinstall shortcut and run a full install.
#                        A Mac that is already enrolled is refused by the cloud
#                        with "already provisioned" — use --force-reprovision
#   --force-reprovision  re-register this Mac from scratch. This is the one that
#                        works on an already-enrolled Mac
#   --connect            also install the Zero Networks Connect client
#   --help
#
# Before this will complete, the Configuration Profile carrying the System
# Extension and Content Filter payloads must be installed, and a user must be
# logged in — the installer activates the network extension in their session.
#
# Output goes to the console and to /var/log/zn-agent-install.log.

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

# -----------------------------------------------------------------------------

usage() {
    awk 'NR>2 && /^#/ { sub(/^# ?/, ""); print; next } NR>2 { exit }' "$0"
}

# Unrecognised arguments are ignored rather than rejected: MDMs prepend their
# own positional parameters (a mount point, the computer name, the console
# user) ahead of the operator's, and the offset varies between them.
while [ $# -gt 0 ]; do
    case "$1" in
        --token)             TOKEN="${2:-}"; shift 2 ;;
        --token=*)           TOKEN="${1#*=}"; shift ;;
        --arch)              ARCH="${2:-}"; shift 2 ;;
        --arch=*)            ARCH="${1#*=}"; shift ;;
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

# Flag order follows the Windows builder's sharedFlags, so the two platforms
# produce comparable command lines.
#
# Note -connect is accepted but does nothing on macOS: downloadAndInstallConnect
# in setup/utils_mac.go is a stub that returns nil. It is wired up here for
# parity with Windows, and so it starts working if that stub ever does.
FLAGS=()
[ "$FORCE" = true ]             && FLAGS+=(-force)
[ "$FORCE_REPROVISION" = true ] && FLAGS+=(-force-reprovision)
[ "$CONNECT" = true ]           && FLAGS+=(-connect)

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

say "Asking $BASE_URL for the $PLATFORM installer"

# /installer answers with a short-lived signed download URL. It takes the raw
# token with no "Bearer" prefix, and needs no assetId, so this enrols nothing.
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

say "Installing${FLAGS[*]:+ (${FLAGS[*]})}"
# Captured rather than left to set -e, so the installer's exit code is
# reported and its output — which carries no trailing newline — is closed off
# on the failure path too.
STATUS=0
"$INSTALLER" -install -token "$TOKEN" ${FLAGS[@]+"${FLAGS[@]}"} || STATUS=$?
echo

if [ "$STATUS" -ne 0 ]; then
    say "The installer failed (exit $STATUS). See /var/log/zero-networks/cloud-connector/setup.log."
    exit "$STATUS"
fi

say "Done"

#!/bin/bash

set -e

SCRIPT_URL=""
TMP_ZIP=""
TOKEN=""
INSTALL_DIR=""

trap '[[ -f "$TMP_ZIP" ]] && rm -f "$TMP_ZIP"' EXIT

# --- Parse CLI args ---
while [[ $# -gt 0 ]]; do
  case $1 in
    --url)
      SCRIPT_URL="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# --- Tool check ---
for tool in curl unzip sudo; do
  if ! command -v "$tool" &>/dev/null; then
    echo "[ERROR] Missing required tool: $tool"
    exit 1
  fi
done

# --- Ask for URL if not provided ---
if [[ -z "$SCRIPT_URL" ]]; then
  echo ""
  read -p "Enter the Connect Server ZIP package URL: " SCRIPT_URL
  [[ -z "$SCRIPT_URL" ]] && { echo "[ERROR] No URL provided."; exit 1; }
fi

# --- Parse and sanitize version ---
VERSION=$(echo "$SCRIPT_URL" | grep -oP 'zero-connect-server-setup-\K[0-9\.]+' | sed 's/\.*$//')
INSTALL_BASE="zero-connect-install-$VERSION"
INSTALL_DIR="$INSTALL_BASE"

# --- Clean and prepare directory ---
[[ -d "$INSTALL_DIR" ]] && rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# --- Download + extract ZIP ---
TMP_ZIP=$(mktemp)
echo "Downloading package..."
curl -sSL "$SCRIPT_URL" -o "$TMP_ZIP"
echo "Extracting..."
unzip -q "$TMP_ZIP" -d "$INSTALL_DIR"

# --- Flatten if nested (auto-move inner folder contents) ---
INNER_DIR=$(find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 -type d -name 'zero-connect-server-setup-*' | head -n 1)
if [[ -n "$INNER_DIR" ]]; then
  echo "[INFO] Nested folder detected. Flattening..."
  cp -r "$INNER_DIR"/* "$INSTALL_DIR/"
  rm -rf "$INNER_DIR"
fi

# --- Token input ---
if [[ -z "$ZNC_TOKEN" ]]; then
  while true; do
    echo ""
    read -s -p "Enter your Zero Networks Connect Server token (input hidden): " TOKEN
    echo ""
    TOKEN=$(echo "$TOKEN" | tr -d '[:space:]')
    [[ -z "$TOKEN" ]] && echo "Blank token. Try again." && continue
    [[ ${#TOKEN} -lt 400 ]] && echo "Token looks short. Try again." && continue
    break
  done
else
  TOKEN=$(echo "$ZNC_TOKEN" | tr -d '[:space:]')
  echo "Using token from env var ZNC_TOKEN"
fi

# --- Move into correct working directory ---
cd "$INSTALL_DIR" || { echo "[ERROR] Failed to enter install folder"; exit 1; }

# --- Make sure all internal binaries/scripts are executable ---
[[ -f "zero-connect-setup" ]] || { echo "[ERROR] zero-connect-setup not found."; exit 1; }
chmod +x zero-connect-setup
[[ -d "dependencies/bin" ]] && chmod +x dependencies/bin/* || echo "[WARN] No bin folder found."
[[ -d "dependencies/scripts" ]] && chmod +x dependencies/scripts/*.sh || echo "[WARN] No scripts folder found."

# --- Optional: Save token to file (if required by setup) ---
echo "$TOKEN" > token
chmod 600 token

# --- Launch installer from correct dir ---
echo ""
echo "=============================================================="
echo "Launching Connect Server installer..."
echo "Path: $(pwd)"
echo "Token preview: ${TOKEN:0:20}...[redacted]"
echo "=============================================================="
echo ""

sudo ./zero-connect-setup -token "$TOKEN"

# --- Clean up token file ---
rm -f token

# --- Optional: analyze setup.log if setup failed ---
if [[ -f "setup.log" ]]; then
  echo ""
  echo "=============================================================="
  echo "Setup log found. Running recovery analysis..."
  echo "=============================================================="

  if grep -q "missing token" setup.log; then
    echo "[ISSUE] Token was not passed correctly or was missing during setup."
    echo "        Re-run with: sudo ./zero-connect-setup -token \"\$TOKEN\""
  fi

  if grep -q "not enough free disk space" setup.log; then
    echo "[WARN] Low disk space detected. Recommended: at least 100GB free."
    df -h /
  fi

  if grep -q "Unable to acquire the dpkg frontend lock" setup.log; then
    echo "[ISSUE] APT was locked by another process."
    echo "        Run: sudo lsof /var/lib/dpkg/lock-frontend"
    echo "        Then: sudo kill -9 <PID> && sudo rm -f /var/lib/dpkg/lock-frontend"
  fi

  if grep -q "failed to install net tools" setup.log; then
    echo "[FAIL] Could not install net-tools. Likely due to apt lock or missing perms."
    echo "       Try: sudo apt update && sudo apt install net-tools"
  fi

  if grep -q "Validate core libraries" setup.log && grep -q "failed" setup.log; then
    echo "[ERROR] Core library validation failed. Setup halted."
    echo "        Check if dependencies/bin/zero-connect-server exists and is executable."
  fi

  echo "--------------------------------------------------------------"
  echo "Log tail:"
  tail -n 10 setup.log
  echo "=============================================================="
fi

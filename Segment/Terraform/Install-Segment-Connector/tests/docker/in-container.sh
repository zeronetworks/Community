#!/usr/bin/env bash
#
# Runs inside one Linux container. Started by tests/docker/run-docker-tests.sh,
# which mounts the project read-only at /repo and runs this file with bash.
#
# What it does:
#   1. Installs unzip and python3 when they are missing. The install script needs
#      one of them to unpack the installer zip, and python3 for the connection check.
#   2. Runs the rendered install and uninstall scripts (tests/build/<variant>/)
#      against the fake installer from the zip, then checks what happened.
#      Nothing contacts a real Zero Networks service.
#
# The scripts must run as root, so this runs as root inside the container.
# Each check clears the files left behind by the one before it.
#
# Exit code: 0 when every check passed, 1 otherwise.

set -u

REPO=/repo
BUILD=$REPO/tests/build
ZIP=$BUILD/segment-connector-linux-installer.zip

# Rendered variants this file expects (rendered by tests/run-offline-tests.sh).
# default: fresh install, env token. strict: verify_strict. reinstall: reinstall = true.
# download600: download_timeout = 600. enroll_fqdn / enroll_static / asset_force:
# enrollment options. token_file: token_source = file.
VARIANTS="default strict reinstall download600 enroll_fqdn enroll_static asset_force token_file"

# Paths the rendered scripts use (the core module defaults).
IDENTITY=/var/zeronetworks/.zn-internal/identity.json
LOGS_DIR=/var/zeronetworks/logs
STAGING=/opt/zn-segment-connector-setup
LOG_FILE=/var/log/zn-segment-connector-terraform.log

# Paths used only by these checks.
TOKEN_FILE=/root/zn-test-token        # written by the token_file checks
CALLS=/tmp/fake-calls                 # written by the fake installer
OUT=/tmp/case-output.txt              # stdout and stderr of the last script run
NOEXT_DIR=/tmp/no-extractor-bin       # a PATH with no unzip and no python

TOKEN="test-token-ABC123"
FILE_TOKEN="FILE-TOKEN-MUST-NOT-LEAK-987"
TOKEN_B64=$(printf '%s' "$TOKEN" | base64 | tr -d '\n')
BASH_BIN=$(command -v bash)

PASS=0
FAIL=0
CASE_FAILS=0
RC=0

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

# Prints a passing check.
pass() {
  PASS=$((PASS + 1))
  echo "    PASS  $1"
}

# Prints a failing check.
fail() {
  FAIL=$((FAIL + 1))
  echo "    FAIL  $1"
}

# Runs a command and records a pass or fail. $1 = description, the rest = command.
check() {
  local what=$1
  shift
  if "$@"; then
    pass "$what"
  else
    fail "$what"
  fi
}

# Starts a numbered group of checks.
begin_case() {
  CASE_FAILS=$FAIL
  echo
  echo "== $1"
}

# Ends a group. When a check failed, shows the end of the last script output.
end_case() {
  if [ "$FAIL" -gt "$CASE_FAILS" ] && [ -s "$OUT" ]; then
    echo "    --- last script output (end) ---"
    tail -n 40 "$OUT" | sed 's/^/    | /'
    echo "    --------------------------------"
  fi
}

# Succeeds when FILE contains TEXT anywhere. $1 = file, $2 = text.
has_text() { grep -qF -- "$2" "$1" 2>/dev/null; }

# Succeeds when FILE has a line that is exactly TEXT. $1 = file, $2 = text.
has_line() { grep -qxF -- "$2" "$1" 2>/dev/null; }

# Succeeds when FILE matches REGEX (case-insensitive). $1 = file, $2 = regex.
has_regex() { grep -qiE -- "$2" "$1" 2>/dev/null; }

# Succeeds when FILE does not contain TEXT (a missing file counts as not containing it).
lacks_text() { ! grep -qF -- "$2" "$1" 2>/dev/null; }

# Succeeds when PATH_TO_CHECK does not exist.
is_absent() { [ ! -e "$1" ]; }

# Prints how many installer calls were recorded.
calls_count() {
  local n
  n=$(grep -c '^CALL$' "$CALLS" 2>/dev/null)
  echo "${n:-0}"
}

# Prints the arguments of the last recorded installer call, separated by single spaces.
last_args() {
  awk '/^CALL$/ { args = ""; n = 0; next }
       /^ARG / { sub(/^ARG /, ""); args = args (n ? " " : "") $0; n++ }
       END { print args }' "$CALLS" 2>/dev/null
}

# Succeeds when the last installer call had exactly these arguments. $1 = expected text.
args_are() { [ "$(last_args)" = "$1" ]; }

# Clears the files and folders that a previous check may have left behind.
reset_state() {
  rm -f "$IDENTITY" "$CALLS" "$TOKEN_FILE" "$LOG_FILE" "$OUT"
  rm -rf "$STAGING" "$LOGS_DIR"
}

# Runs one rendered script. $1 = variant, $2 = install or uninstall.
# Output (stdout and stderr together) goes to $OUT. Sets RC to the exit code.
run_script() {
  bash "$BUILD/$1/$2.sh" >"$OUT" 2>&1
  RC=$?
}

# Installs unzip, python3 and find (findutils) when they are missing.
# Minimal images such as amazonlinux:2023 do not include find, and real hosts do.
install_tools() {
  local -a missing=()
  command -v unzip >/dev/null 2>&1 || missing+=(unzip)
  command -v python3 >/dev/null 2>&1 || missing+=(python3)
  command -v find >/dev/null 2>&1 || missing+=(findutils)
  if [ "${#missing[@]}" -eq 0 ]; then
    echo "Tools already present: unzip, python3 and find."
    return 0
  fi

  echo "Installing missing tools: ${missing[*]}"
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null && apt-get install -y -qq "${missing[@]}" >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q "${missing[@]}" >/dev/null
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q "${missing[@]}" >/dev/null
  else
    echo "No supported package manager (apt-get, dnf or yum) was found."
    return 1
  fi

  command -v unzip >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 && command -v find >/dev/null 2>&1
}

# Builds a PATH folder that has every command except unzip and python.
# Used to check the "no extractor" error.
make_no_extractor_dir() {
  local dir name f
  rm -rf "$NOEXT_DIR"
  mkdir -p "$NOEXT_DIR"
  for dir in /bin /usr/bin /usr/local/bin; do
    [ -d "$dir" ] || continue
    for f in "$dir"/*; do
      name=$(basename "$f")
      case "$name" in
        unzip|funzip|zipinfo|bsdtar|python|python[0-9]*) continue ;;
      esac
      if [ -x "$f" ] && [ ! -e "$NOEXT_DIR/$name" ]; then
        ln -s "$f" "$NOEXT_DIR/$name"
      fi
    done
  done
}

# Writes a fresh identity file, as if the connector were already installed.
make_identity() {
  mkdir -p "$(dirname "$IDENTITY")"
  echo '{"assetId":"pre-existing"}' >"$IDENTITY"
}

# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------

# 1. A fresh install runs the installer once with the expected arguments.
case_fresh_install() {
  begin_case "1. Fresh install runs the installer once with the expected arguments"
  reset_state
  export FAKE_MODE=connected
  run_script default install
  check "install script exits 0" [ "$RC" -eq 0 ]
  check "installer was called once" [ "$(calls_count)" -eq 1 ]
  check "installer arguments are: -install -token <token> -run-as zn-user" \
    args_are "-install -token $TOKEN -run-as zn-user"
  check "installer reported version 9.9.9.9" has_text "$OUT" "version=9.9.9.9"
  check "identity file was written by the installer" test -f "$IDENTITY"
  end_case
}

# 2. An existing install is skipped (no installer call), but the result is still reported.
case_skip_when_installed() {
  begin_case "2. Existing identity file skips the install"
  reset_state
  make_identity
  export FAKE_MODE=connected
  run_script default install
  check "install script exits 0" [ "$RC" -eq 0 ]
  check "the output says the install was skipped" has_regex "$OUT" "skipping the install"
  check "installer was not called" [ "$(calls_count)" -eq 0 ]
  check "existing identity file is kept" has_text "$IDENTITY" "pre-existing"
  end_case
}

# 3. reinstall = true runs the installer even when the identity file exists.
case_reinstall() {
  begin_case "3. reinstall = true runs the installer again"
  reset_state
  make_identity
  export FAKE_MODE=connected
  run_script reinstall install
  check "install script exits 0" [ "$RC" -eq 0 ]
  check "installer was called once" [ "$(calls_count)" -eq 1 ]
  check "installer arguments are: -install -token <token> -run-as zn-user" \
    args_are "-install -token $TOKEN -run-as zn-user"
  end_case
}

# Runs one install variant and checks the installer arguments it produced.
# $1 = variant, $2 = expected installer arguments after the token.
check_install_args() {
  reset_state
  export FAKE_MODE=connected
  run_script "$1" install
  check "[$1] install script exits 0" [ "$RC" -eq 0 ]
  check "[$1] installer arguments are: -install -token <token> $2" \
    args_are "-install -token $TOKEN $2"
}

# 4. Enrollment options turn into the matching installer arguments.
case_enrollment_combos() {
  begin_case "4. Enrollment options become the matching installer arguments"
  check_install_args enroll_fqdn "-run-as zn-user -allow-create -asset-fqdn connector01.example.com"
  end_case
  begin_case "4b. Static-IP enrollment with a name"
  check_install_args enroll_static "-run-as zn-user -allow-create -with-static-ip -name edge-01"
  end_case
  begin_case "4c. Asset ID with force"
  check_install_args asset_force "-run-as zn-user -force -assetId 0123456789abcdef"
  end_case
}

# 5. download_timeout = 600 is passed to the installer as 600s.
case_download_timeout() {
  begin_case "5. download_timeout 600 becomes ZN_SEGMENT_CONNECTOR_INSTALL_GET_PKG_TIMEOUT=600s"
  reset_state
  export FAKE_MODE=connected
  run_script download600 install
  check "install script exits 0" [ "$RC" -eq 0 ]
  check "installer environment has the 600s timeout" \
    has_line "$CALLS" "ENV ZN_SEGMENT_CONNECTOR_INSTALL_GET_PKG_TIMEOUT=600s"
  end_case
}

# 6. An installer failure exits non-zero and prints the matching hint.
case_installer_failure() {
  begin_case "6. Installer failure (bad token) exits non-zero and shows a hint"
  reset_state
  export FAKE_MODE=bad_token
  run_script default install
  check "install script exits non-zero" [ "$RC" -ne 0 ]
  check "the output has a Hints section" has_regex "$OUT" "hints?:"
  check "the hint says the token is invalid or expired" has_regex "$OUT" "token.*(invalid|expired)"
  check "the run does not report a connected state" lacks_text "$OUT" "state=connected"
  end_case
}

# 7. A token file is read, then removed, and the token text never appears in output or the log.
case_token_file() {
  begin_case "7. token_source = file: token file removed, token not printed or logged"
  reset_state
  printf '%s' "$FILE_TOKEN" >"$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  local saved_b64=${ZN_SEGMENT_CONNECTOR_TOKEN_B64:-}
  unset ZN_SEGMENT_CONNECTOR_TOKEN_B64
  export FAKE_MODE=connected
  run_script token_file install
  export ZN_SEGMENT_CONNECTOR_TOKEN_B64=$saved_b64
  check "install script exits 0" [ "$RC" -eq 0 ]
  check "installer received the token from the file" has_text "$CALLS" "ARG $FILE_TOKEN"
  check "token file was removed" is_absent "$TOKEN_FILE"
  check "token text is absent from the script output" lacks_text "$OUT" "$FILE_TOKEN"
  check "log file exists" test -f "$LOG_FILE"
  check "token text is absent from the log file" lacks_text "$LOG_FILE" "$FILE_TOKEN"
  end_case
}

# 8. A good connection is reported as connected or operational.
case_verify_connected() {
  begin_case "8. Verify: connected connector is reported as connected or operational"
  reset_state
  export FAKE_MODE=connected
  run_script default install
  check "install script exits 0" [ "$RC" -eq 0 ]
  check "result line reports connected or operational" \
    has_regex "$OUT" "ZN_SEGMENT_CONNECTOR_RESULT action=install state=(connected|operational)"
  check "output says the connector is connected" has_text "$OUT" "is connected to"
  end_case
}

# 9. A DNS failure is a warning with a DNS hint, and the exit code stays 0.
case_dns_fail() {
  begin_case "9. Verify: DNS failure gives a warning and a DNS hint, exit 0"
  reset_state
  export FAKE_MODE=dns_fail
  run_script default install
  check "install script exits 0" [ "$RC" -eq 0 ]
  check "result line reports failing" has_text "$OUT" "state=failing"
  check "output has a WARNING" has_text "$OUT" "WARNING"
  check "output has a DNS hint" has_regex "$OUT" "dns"
  end_case
}

# 10. The same DNS failure with verify_strict = true exits 2.
case_dns_fail_strict() {
  begin_case "10. Verify: DNS failure with verify_strict = true exits 2"
  reset_state
  export FAKE_MODE=dns_fail
  run_script strict install
  check "install script exits 2" [ "$RC" -eq 2 ]
  end_case
}

# 11. Uninstall calls the installer's -uninstall and removes the staging folder.
case_uninstall() {
  begin_case "11. Uninstall removes the staging folder"
  reset_state
  export FAKE_MODE=connected
  run_script default install
  check "setup install exits 0" [ "$RC" -eq 0 ]
  check "staging folder exists after install" test -d "$STAGING"
  run_script default uninstall
  check "uninstall script exits 0" [ "$RC" -eq 0 ]
  check "installer was called with -uninstall" has_line "$CALLS" "ARG -uninstall"
  check "staging folder is removed" is_absent "$STAGING"
  check "identity file is removed" is_absent "$IDENTITY"
  end_case
}

# 12. With no unzip and no python, the install stops with a clear error.
case_no_extractor() {
  begin_case "12. No unzip and no python: clear error, installer never runs"
  reset_state
  export FAKE_MODE=connected
  PATH=$NOEXT_DIR "$BASH_BIN" "$BUILD/default/install.sh" >"$OUT" 2>&1
  RC=$?
  check "install script exits non-zero" [ "$RC" -ne 0 ]
  check "error names unzip or python" has_regex "$OUT" "unzip|python"
  check "installer was not called" [ "$(calls_count)" -eq 0 ]
  end_case
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Prints the name of the Linux distribution in this container.
os_name() {
  # The file /etc/os-release is present in every image we use.
  # shellcheck disable=SC1091
  ( . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" )
}

main() {
  local variant
  echo "Linux container checks"
  echo "Image: $(os_name)"

  if ! install_tools; then
    echo "FAIL  could not install unzip and python3"
    exit 1
  fi
  echo "Tools: $(command -v unzip) $(command -v python3)"

  if [ ! -f "$ZIP" ]; then
    echo "ERROR: $ZIP is missing. Run tests/docker/run-docker-tests.sh on the host."
    exit 1
  fi
  for variant in $VARIANTS; do
    if [ ! -f "$BUILD/$variant/install.sh" ] || [ ! -f "$BUILD/$variant/uninstall.sh" ]; then
      echo "ERROR: rendered scripts for '$variant' are missing. Run tests/run-offline-tests.sh first."
      exit 1
    fi
  done

  # Settings every script run inherits: the installer zip (from the fake) and the token.
  export ZN_SEGMENT_CONNECTOR_INSTALLER_ZIP=$ZIP
  export ZN_SEGMENT_CONNECTOR_TOKEN_B64=$TOKEN_B64
  make_no_extractor_dir

  case_fresh_install
  case_skip_when_installed
  case_reinstall
  case_enrollment_combos
  case_download_timeout
  case_installer_failure
  case_token_file
  case_verify_connected
  case_dns_fail
  case_dns_fail_strict
  case_uninstall
  case_no_extractor

  rm -rf "$NOEXT_DIR"
  reset_state

  echo
  echo "Linux container result: $PASS passed, $FAIL failed"
  [ "$FAIL" -eq 0 ]
}

main

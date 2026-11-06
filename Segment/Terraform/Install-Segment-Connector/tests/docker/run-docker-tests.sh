#!/usr/bin/env bash
#
# Host-side runner for the Linux container checks.
#
# What it does:
#   1. Builds the fake installer zip into tests/build/ (the zip holds the fake
#      installer and the connector-log fixtures). The zip is never committed.
#   2. Starts one container for each Linux image below. Each container gets the
#      project read-only at /repo and runs tests/docker/in-container.sh.
#
# The rendered install scripts must already exist in tests/build/<variant>/.
# tests/run-offline-tests.sh makes them, then calls this file.
#
# Images: rockylinux:9, ubuntu:24.04, debian:12, amazonlinux:2023.
#
# Exit code: 0 when every image passed, 1 otherwise.

set -u

DOCKER_DIR=$(cd "$(dirname "$0")" && pwd)
TESTS_DIR=$(cd "$DOCKER_DIR/.." && pwd)
ROOT=$(cd "$TESTS_DIR/.." && pwd)
BUILD=$TESTS_DIR/build
FAKE_SRC=$DOCKER_DIR/fake-installer/segment-connector-linux-installer
FIXTURES_SRC=$DOCKER_DIR/fixtures
ZIP=$BUILD/segment-connector-linux-installer.zip
IMAGES="rockylinux:9 ubuntu:24.04 debian:12 amazonlinux:2023"

# Prints an error and stops when Docker is not reachable.
require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: the docker command was not found. Install Docker Desktop, then run this again."
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker is not running. Start Docker Desktop, wait until it says it is running,"
    echo "then run this again: $DOCKER_DIR/run-docker-tests.sh"
    exit 1
  fi
}

# Writes the fake installer zip into tests/build/.
# The fake installer goes in at the top level. The fixtures go in fixtures/.
build_fake_zip() {
  mkdir -p "$BUILD"
  rm -f "$ZIP"
  if command -v python3 >/dev/null 2>&1; then
    python3 -I - "$FAKE_SRC" "$FIXTURES_SRC" "$ZIP" <<'PYEOF'
import glob
import os
import sys
import zipfile

fake, fixtures_dir, out = sys.argv[1], sys.argv[2], sys.argv[3]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    # The fake is marked executable inside the zip.
    info = zipfile.ZipInfo("segment-connector-linux-installer")
    info.external_attr = 0o755 << 16
    with open(fake, "rb") as f:
        z.writestr(info, f.read())
    for path in sorted(glob.glob(os.path.join(fixtures_dir, "*.jsonl"))):
        z.write(path, "fixtures/" + os.path.basename(path))
PYEOF
  elif command -v zip >/dev/null 2>&1; then
    # Same layout, built with the zip command when python3 is missing.
    local tmp
    tmp=$(mktemp -d "$BUILD/zip-src.XXXXXX") || return 1
    cp "$FAKE_SRC" "$tmp/segment-connector-linux-installer"
    chmod 755 "$tmp/segment-connector-linux-installer"
    mkdir -p "$tmp/fixtures"
    cp "$FIXTURES_SRC"/*.jsonl "$tmp/fixtures/"
    (cd "$tmp" && zip -q -r "$ZIP" .)
    rm -rf "$tmp"
  else
    echo "ERROR: neither python3 nor zip is available to build the fake installer zip."
    return 1
  fi
}

require_docker

if [ ! -f "$BUILD/default/install.sh" ]; then
  echo "ERROR: rendered scripts are missing in $BUILD. Run $TESTS_DIR/run-offline-tests.sh first."
  exit 1
fi

echo "== Building the fake installer zip"
if ! build_fake_zip; then
  echo "FAIL  could not build $ZIP"
  exit 1
fi
echo "Built $ZIP"

RESULTS=""
FAILED=0
for image in $IMAGES; do
  echo
  echo "== $image"
  if docker run --rm -v "$ROOT:/repo:ro" "$image" bash /repo/tests/docker/in-container.sh; then
    RESULTS="$RESULTS
PASS  $image"
  else
    RESULTS="$RESULTS
FAIL  $image"
    FAILED=$((FAILED + 1))
  fi
done

echo
echo "== Linux container summary"
printf '%s\n' "$RESULTS" | sed '/^$/d' | sed 's/^/  /'
if [ "$FAILED" -eq 0 ]; then
  echo "All Linux container checks passed."
  exit 0
fi
echo "$FAILED image(s) failed. See the output above."
exit 1

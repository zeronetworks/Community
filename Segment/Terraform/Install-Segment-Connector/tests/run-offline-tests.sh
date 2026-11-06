#!/usr/bin/env bash
#
# Offline test runner for the Segment Connector Terraform project.
#
# "Offline" means no cloud account, no real installer and no calls to Zero
# Networks. Every tool runs in a Docker container, so only Docker is needed.
#
# Steps (each one is PASS, FAIL or SKIP in the final summary):
#   T1  terraform fmt -check, init (no backend) and validate, for each module,
#       each example and the render root in tests/render.
#   T2  tflint, for each module and example.
#   T3  terraform test in the core module (modules/segment-connector-script).
#   T4  terraform test in the other modules and examples that have tests.
#   T5  render the core module into test scripts (tests/build/<variant>/) and
#       run shellcheck on them and on the test harness.
#   T6  Linux container checks (tests/docker/run-docker-tests.sh).
#
# Options (environment variables):
#   TF_IMAGE           Terraform image (default hashicorp/terraform:1.9)
#   TFLINT_IMAGE       tflint image (default ghcr.io/terraform-linters/tflint:v0.53.0)
#   SHELLCHECK_IMAGE   shellcheck image (default koalaman/shellcheck:stable)
#   SKIP_DOCKER_TESTS  set to 1 to skip T6
#
# Exit code: 0 when no step failed; 1 when a step failed or Docker is not running.
# Full output for every step is saved in tests/build/step-output/.

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
BUILD=$SCRIPT_DIR/build
OUTPUT_DIR=$BUILD/step-output
TF_IMAGE=${TF_IMAGE:-hashicorp/terraform:1.9}
TFLINT_IMAGE=${TFLINT_IMAGE:-ghcr.io/terraform-linters/tflint:v0.53.0}
SHELLCHECK_IMAGE=${SHELLCHECK_IMAGE:-koalaman/shellcheck:stable}
USER_IDS="$(id -u):$(id -g)"

RESULTS=()
FAILED=0

# Stops with a helpful message when Docker is not available.
require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: the docker command was not found."
    echo "Install Docker Desktop, start it, then run: $SCRIPT_DIR/run-offline-tests.sh"
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker is not running."
    echo "The offline tests run Terraform, tflint, shellcheck and the Linux container"
    echo "checks inside Docker. Start Docker Desktop, wait until it says it is running,"
    echo "then run: $SCRIPT_DIR/run-offline-tests.sh"
    exit 1
  fi
}

# Saves a result. $1 = PASS, FAIL or SKIP, $2 = step name.
record() {
  RESULTS+=("$1  $2")
  if [ "$1" = "FAIL" ]; then
    FAILED=$((FAILED + 1))
  fi
}

# Runs one step and saves its output. $1 = step name, the rest = the command.
# On failure, prints the end of the output so the problem is visible.
run_step() {
  local name=$1 file
  shift
  file="$OUTPUT_DIR/$(printf '%s' "$name" | tr -c 'A-Za-z0-9._-' '_').out"
  echo "  .. $name"
  if "$@" >"$file" 2>&1; then
    record PASS "$name"
  else
    record FAIL "$name"
    echo "  !! $name failed. Last lines of its output:"
    tail -n 40 "$file" | sed 's/^/     | /'
  fi
}

# Runs a shell command in the Terraform container, from a folder inside the project.
# $1 = folder relative to the project root, $2 = shell command.
# (Called by name through run_step, which shellcheck cannot follow.)
# shellcheck disable=SC2329
tf() {
  docker run --rm --user "$USER_IDS" -e HOME=/tmp -e TF_IN_AUTOMATION=1 \
    -v "$ROOT:/work" -w "/work/$1" --entrypoint /bin/sh "$TF_IMAGE" -c "$2"
}

# Prints the folders under modules/ and examples/ that contain .tf files,
# relative to the project root.
module_dirs() {
  local base d
  for base in modules examples; do
    [ -d "$ROOT/$base" ] || continue
    for d in "$ROOT/$base"/*/; do
      [ -d "$d" ] || continue
      if ls "$d"*.tf >/dev/null 2>&1; then
        d=${d#"$ROOT"/}
        echo "${d%/}"
      fi
    done
  done
}

# Renders one test variant. $1 = variant name, $2 = "name=value ..." test settings.
# Writes tests/build/<variant>/install.sh and uninstall.sh.
# (Called by name through run_step, which shellcheck cannot follow.)
# shellcheck disable=SC2329
render_variant() {
  local name=$1 spec=$2 var_args="" kv state
  for kv in $spec; do
    var_args="$var_args -var $kv"
  done
  mkdir -p "$BUILD/$name"
  state=/work/tests/build/$name/render.tfstate
  tf tests/render "terraform init -input=false -no-color >/dev/null && terraform apply -input=false -auto-approve -no-color -state=$state $var_args >/dev/null && terraform output -raw -state=$state install_script >/work/tests/build/$name/install.sh && terraform output -raw -state=$state uninstall_script >/work/tests/build/$name/uninstall.sh"
}

# Test variants rendered in T5. One per line: name|test settings (name=value, space separated).
# The names must match the ones tests/docker/in-container.sh expects.
VARIANTS="default|verify_timeout=10
strict|verify_timeout=10 verify_strict=true
reinstall|verify_timeout=10 reinstall=true
download600|verify_timeout=10 download_timeout=600
enroll_fqdn|verify_timeout=10 allow_create=true asset_fqdn=connector01.example.com
enroll_static|verify_timeout=10 allow_create=true with_static_ip=true asset_name=edge-01
asset_force|verify_timeout=10 asset_id=0123456789abcdef force=true
token_file|verify_timeout=10 token_source=file token_file_path=/root/zn-test-token"

main() {
  local dir label name spec file
  local -a dirs file_list
  mkdir -p "$OUTPUT_DIR"
  require_docker

  dirs=()
  while IFS= read -r dir; do
    [ -n "$dir" ] && dirs+=("$dir")
  done < <(module_dirs)
  if [ "${#dirs[@]}" -eq 0 ]; then
    echo "NOTE: no folders with .tf files were found under modules/ or examples/."
  fi

  echo "== T1 format, init and validate"
  for dir in ${dirs[@]+"${dirs[@]}"} tests/render; do
    run_step "T1 fmt $dir" tf "$dir" "terraform fmt -check -recursive -no-color"
    run_step "T1 init+validate $dir" tf "$dir" "terraform init -backend=false -input=false -no-color >/dev/null && terraform validate -no-color"
  done

  echo "== T2 tflint"
  for dir in ${dirs[@]+"${dirs[@]}"}; do
    run_step "T2 tflint $dir" docker run --rm --user "$USER_IDS" -e HOME=/tmp \
      -e TFLINT_PLUGIN_DIR=/tmp/tflint-plugins -v "$ROOT:/work" -w "/work/$dir" \
      --entrypoint /bin/sh "$TFLINT_IMAGE" -c "tflint --init >/dev/null && tflint --format compact --no-color"
  done

  echo "== T3 and T4 terraform test"
  for dir in ${dirs[@]+"${dirs[@]}"}; do
    if [ "$dir" = "modules/segment-connector-script" ]; then
      label=T3
    else
      label=T4
    fi
    if ls "$ROOT/$dir/tests/"*.tftest.hcl >/dev/null 2>&1; then
      run_step "$label terraform test $dir" tf "$dir" "terraform init -backend=false -input=false -no-color >/dev/null && terraform test -no-color"
    else
      record SKIP "$label terraform test $dir (no *.tftest.hcl files)"
    fi
  done

  echo "== T5 render and shellcheck"
  while IFS='|' read -r name spec; do
    [ -n "$name" ] || continue
    run_step "T5 render $name" render_variant "$name" "$spec"
  done <<VARIANT_LIST
$VARIANTS
VARIANT_LIST

  file_list=()
  while IFS= read -r file; do
    file_list+=("${file#"$ROOT"/}")
  done < <(find "$BUILD" -name '*.sh' -not -path "$OUTPUT_DIR/*" 2>/dev/null | sort)
  file_list+=(tests/run-offline-tests.sh tests/docker/run-docker-tests.sh tests/docker/in-container.sh tests/docker/fake-installer/segment-connector-linux-installer)
  run_step "T5 shellcheck (rendered scripts and test harness)" \
    docker run --rm -v "$ROOT:/work" -w /work --entrypoint shellcheck "$SHELLCHECK_IMAGE" "${file_list[@]}"

  echo "== T6 Linux container checks"
  if [ "${SKIP_DOCKER_TESTS:-0}" = "1" ]; then
    record SKIP "T6 Linux container checks (SKIP_DOCKER_TESTS=1)"
  else
    run_step "T6 Linux container checks" "$SCRIPT_DIR/docker/run-docker-tests.sh"
  fi

  echo
  echo "== Summary"
  local r
  for r in ${RESULTS[@]+"${RESULTS[@]}"}; do
    echo "  $r"
  done
  echo
  if [ "$FAILED" -eq 0 ]; then
    echo "OFFLINE TESTS PASSED (no failed steps)."
    exit 0
  fi
  echo "OFFLINE TESTS FAILED: $FAILED step(s) failed. Full output is in $OUTPUT_DIR"
  exit 1
}

main "$@"

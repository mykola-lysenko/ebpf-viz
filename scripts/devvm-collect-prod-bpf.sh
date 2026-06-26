#!/usr/bin/env bash
# Collect BPF data from a production target by relaying through a dev VM.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COLLECTOR="$ROOT_DIR/scripts/collect-l3-bpf.sh"

DEVVM=""
TARGET=""
OUTPUT=""
REMOTE_SCRIPT="/tmp/ebpf-viz-prod-collector-$$.sh"
PROFILE="${PROFILE:-network}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-20}"
MAX_TAIL_CALL_DEPTH="${MAX_TAIL_CALL_DEPTH:-4}"
MAX_PROGRAMS="${MAX_PROGRAMS:-160}"
MAX_PROG_ARRAY_MAPS="${MAX_PROG_ARRAY_MAPS:-64}"
MAX_TC_DEVS="${MAX_TC_DEVS:-64}"
BPFTOOL_VALUE="${BPFTOOL:-bpftool}"
SUDO_VALUE="${SUDO:-sudo -n}"
INCLUDE_XLATED="${INCLUDE_XLATED:-1}"
INCLUDE_TEXT="${INCLUDE_TEXT:-0}"
INCLUDE_JITED="${INCLUDE_JITED:-0}"
DUMP_PROG_ARRAY_MAPS="${DUMP_PROG_ARRAY_MAPS:-1}"
KEEP_REMOTE="${KEEP_REMOTE:-0}"
SSH_CONTROL_PATH=""
TMP_OUTPUT=""
SSH_COMMON_ARGS=()
SCP_COMMON_ARGS=()

usage() {
  cat <<'USAGE'
Usage:
  scripts/devvm-collect-prod-bpf.sh [options] --devvm user@devvm --target prod-host
  scripts/devvm-collect-prod-bpf.sh [options] user@devvm prod-host

Collects BPF data from a target host by SSHing to a dev VM first, then SSHing
from the dev VM to the target. The final archive is streamed back through the
dev VM, so no manual SCP from the target host is required. Target collection
uses non-interactive sudo by default (`sudo -n`) to avoid password prompts.

Options:
  --devvm HOST               Dev VM SSH destination.
  --target HOST              Final target SSH destination reachable from dev VM.
  --output PATH              Local tarball path (default: ./captures/<target>-<profile>-<ts>.tar.gz)
  --profile NAME             inventory, network, cgroup, or all (default: network)
  --timeout SECONDS          Per-command timeout on target (default: 20)
  --max-depth N              Tail-call discovery depth (default: 4)
  --max-programs N           Max programs to dump; 0 means unbounded (default: 160)
  --max-prog-array-maps N    Max prog-array maps to dump; 0 means unbounded (default: 64)
  --max-tc-devs N            Max network devices for tc filter snapshots (default: 64)
  --bpftool PATH             bpftool path on target (default: bpftool)
  --no-sudo                  Run bpftool/tc without sudo on target
  --include-jited            Include jited dumps; disabled by default for prod captures
  --include-text             Include text disassembly dumps; disabled by default
  --no-xlated                Skip xlated bytecode dumps
  --no-prog-array-dumps      Skip prog-array map dumps and tail-call target expansion
  --keep-remote              Keep target /tmp collection files for debugging
  -h, --help                 Show this help

Examples:
  scripts/devvm-collect-prod-bpf.sh --devvm devvm.example.com --target edge.example.com
  scripts/devvm-collect-prod-bpf.sh devvm.example.com edge.example.com --profile inventory
USAGE
}

require_arg() {
  local flag="$1"
  local value="${2:-}"
  if [ -z "$value" ]; then
    echo "Missing value for $flag" >&2
    exit 2
  fi
}

safe_name() {
  printf '%s' "${1:-unnamed}" | tr -c 'A-Za-z0-9_.-' '_'
}

shell_quote() {
  printf "%q" "$1"
}

setup_ssh_mux() {
  # Keep this short; macOS Unix-domain socket paths can hit small length limits.
  SSH_CONTROL_PATH="/tmp/evz-prod-$$.ssh"
  SSH_COMMON_ARGS=(
    -o ControlMaster=auto
    -o ControlPath="$SSH_CONTROL_PATH"
    -o ControlPersist=10m
    -o LogLevel=ERROR
  )
  SCP_COMMON_ARGS=(
    -o ControlMaster=auto
    -o ControlPath="$SSH_CONTROL_PATH"
    -o ControlPersist=10m
    -o LogLevel=ERROR
  )
}

cleanup() {
  if [ -n "$TMP_OUTPUT" ]; then
    rm -f "$TMP_OUTPUT" 2>/dev/null || true
  fi
  if [ -n "$DEVVM" ] && [ -n "$SSH_CONTROL_PATH" ] && [ -S "$SSH_CONTROL_PATH" ]; then
    ssh "${SSH_COMMON_ARGS[@]}" "$DEVVM" "rm -f $(shell_quote "$REMOTE_SCRIPT")" >/dev/null 2>&1 || true
    ssh "${SSH_COMMON_ARGS[@]}" -O exit "$DEVVM" >/dev/null 2>&1 || true
  fi
  if [ -n "$SSH_CONTROL_PATH" ]; then
    rm -f "$SSH_CONTROL_PATH" 2>/dev/null || true
  fi
}

POSITIONAL=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --devvm)
      require_arg "$1" "${2:-}"
      DEVVM="$2"
      shift 2
      ;;
    --target)
      require_arg "$1" "${2:-}"
      TARGET="$2"
      shift 2
      ;;
    --output)
      require_arg "$1" "${2:-}"
      OUTPUT="$2"
      shift 2
      ;;
    --profile)
      require_arg "$1" "${2:-}"
      PROFILE="$2"
      shift 2
      ;;
    --timeout)
      require_arg "$1" "${2:-}"
      TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --max-depth)
      require_arg "$1" "${2:-}"
      MAX_TAIL_CALL_DEPTH="$2"
      shift 2
      ;;
    --max-programs)
      require_arg "$1" "${2:-}"
      MAX_PROGRAMS="$2"
      shift 2
      ;;
    --max-prog-array-maps)
      require_arg "$1" "${2:-}"
      MAX_PROG_ARRAY_MAPS="$2"
      shift 2
      ;;
    --max-tc-devs)
      require_arg "$1" "${2:-}"
      MAX_TC_DEVS="$2"
      shift 2
      ;;
    --bpftool)
      require_arg "$1" "${2:-}"
      BPFTOOL_VALUE="$2"
      shift 2
      ;;
    --no-sudo)
      SUDO_VALUE=""
      shift
      ;;
    --include-jited)
      INCLUDE_JITED=1
      shift
      ;;
    --include-text)
      INCLUDE_TEXT=1
      shift
      ;;
    --no-xlated)
      INCLUDE_XLATED=0
      shift
      ;;
    --no-prog-array-dumps)
      DUMP_PROG_ARRAY_MAPS=0
      shift
      ;;
    --keep-remote)
      KEEP_REMOTE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [ "$#" -gt 0 ]; do
        POSITIONAL+=("$1")
        shift
      done
      ;;
    --*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [ -z "$DEVVM" ] && [ "${#POSITIONAL[@]}" -gt 0 ]; then
  DEVVM="${POSITIONAL[0]}"
fi
if [ -z "$TARGET" ] && [ "${#POSITIONAL[@]}" -gt 1 ]; then
  TARGET="${POSITIONAL[1]}"
fi
if [ "${#POSITIONAL[@]}" -gt 2 ]; then
  echo "Unexpected extra argument: ${POSITIONAL[2]}" >&2
  usage >&2
  exit 2
fi

if [ -z "$DEVVM" ] || [ -z "$TARGET" ]; then
  usage >&2
  exit 2
fi

case "$PROFILE" in
  inventory|network|l3|cgroup|all)
    ;;
  *)
    echo "Unsupported --profile: $PROFILE" >&2
    usage >&2
    exit 2
    ;;
esac

for numeric_value in TIMEOUT_SECONDS MAX_TAIL_CALL_DEPTH MAX_PROGRAMS MAX_PROG_ARRAY_MAPS MAX_TC_DEVS; do
  value="${!numeric_value}"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$numeric_value must be numeric, got: $value" >&2
    exit 2
  fi
done

for bool_value in INCLUDE_XLATED INCLUDE_TEXT INCLUDE_JITED DUMP_PROG_ARRAY_MAPS KEEP_REMOTE; do
  value="${!bool_value}"
  if [ "$value" != "0" ] && [ "$value" != "1" ]; then
    echo "$bool_value must be 0 or 1, got: $value" >&2
    exit 2
  fi
done

if [ ! -f "$COLLECTOR" ]; then
  echo "Missing collector script: $COLLECTOR" >&2
  exit 1
fi

for tool in ssh scp; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required." >&2
    exit 1
  fi
done

if [ -z "$OUTPUT" ]; then
  TS="$(date +%Y%m%d-%H%M%S)"
  OUTPUT="$ROOT_DIR/captures/$(safe_name "$TARGET")-${PROFILE}-${TS}.tar.gz"
fi

mkdir -p "$(dirname "$OUTPUT")"
setup_ssh_mux
trap cleanup EXIT

echo "=== Opening shared SSH connection to dev VM ==="
echo "One SSH auth prompt is expected here; later devvm steps reuse this connection."
ssh "${SSH_COMMON_ARGS[@]}" -fN "$DEVVM"

echo ""
echo "=== Uploading collector to dev VM ==="
scp "${SCP_COMMON_ARGS[@]}" "$COLLECTOR" "$DEVVM:$REMOTE_SCRIPT"

echo ""
echo "=== Collecting from target through dev VM ==="
echo "Dev VM: $DEVVM"
echo "Target: $TARGET"
echo "Profile: $PROFILE"
echo "Local output: $OUTPUT"
echo "Limits: programs=$MAX_PROGRAMS prog-array-maps=$MAX_PROG_ARRAY_MAPS tc-devices=$MAX_TC_DEVS"
if [ "$INCLUDE_JITED" = "0" ]; then
  echo "JIT dumps: disabled"
else
  echo "JIT dumps: enabled"
fi

TMP_OUTPUT="${OUTPUT}.tmp.$$"
if ssh "${SSH_COMMON_ARGS[@]}" "$DEVVM" bash -s -- \
  "$REMOTE_SCRIPT" \
  "$TARGET" \
  "$PROFILE" \
  "$TIMEOUT_SECONDS" \
  "$MAX_TAIL_CALL_DEPTH" \
  "$MAX_PROGRAMS" \
  "$MAX_PROG_ARRAY_MAPS" \
  "$MAX_TC_DEVS" \
  "$BPFTOOL_VALUE" \
  "$SUDO_VALUE" \
  "$INCLUDE_XLATED" \
  "$INCLUDE_TEXT" \
  "$INCLUDE_JITED" \
  "$DUMP_PROG_ARRAY_MAPS" \
  "$KEEP_REMOTE" >"$TMP_OUTPUT" <<'REMOTE_RELAY'
set -euo pipefail

REMOTE_SCRIPT="$1"
TARGET="$2"
PROFILE="$3"
TIMEOUT_SECONDS="$4"
MAX_TAIL_CALL_DEPTH="$5"
MAX_PROGRAMS="$6"
MAX_PROG_ARRAY_MAPS="$7"
MAX_TC_DEVS="$8"
BPFTOOL_VALUE="$9"
SUDO_VALUE="${10}"
INCLUDE_XLATED="${11}"
INCLUDE_TEXT="${12}"
INCLUDE_JITED="${13}"
DUMP_PROG_ARRAY_MAPS="${14}"
KEEP_REMOTE="${15}"

q() {
  printf "%q" "$1"
}

TARGET_CONTROL_PATH="/tmp/evz-tgt-$$.ssh"
TARGET_SCRIPT="/tmp/ebpf-viz-prod-collector-$$.sh"
TARGET_OUT="/tmp/ebpf-viz-prod-capture-$$"
TARGET_ARCHIVE="/tmp/ebpf-viz-prod-capture-$$.tar.gz"
SSH_TARGET_ARGS=(
  -o ControlMaster=auto
  -o ControlPath="$TARGET_CONTROL_PATH"
  -o ControlPersist=10m
  -o LogLevel=ERROR
)

cleanup_target_mux() {
  ssh "${SSH_TARGET_ARGS[@]}" -O exit "$TARGET" >/dev/null 2>&1 || true
  rm -f "$TARGET_CONTROL_PATH" 2>/dev/null || true
}
trap cleanup_target_mux EXIT

echo "Opening target SSH connection from dev VM..." >&2
ssh "${SSH_TARGET_ARGS[@]}" -fN "$TARGET" 1>&2

echo "Uploading collector to target /tmp..." >&2
ssh "${SSH_TARGET_ARGS[@]}" "$TARGET" \
  "cat > $(q "$TARGET_SCRIPT") && chmod 700 $(q "$TARGET_SCRIPT")" \
  <"$REMOTE_SCRIPT" 1>&2

echo "Running target collector and streaming archive back..." >&2
TARGET_COMMAND="$(cat <<EOF
set -uo pipefail
cleanup() {
  rm -f $(q "$TARGET_SCRIPT") 2>/dev/null || true
  if [ "$(q "$KEEP_REMOTE")" != "1" ]; then
    rm -rf $(q "$TARGET_OUT") $(q "$TARGET_ARCHIVE") 2>/dev/null || true
  else
    echo "Kept remote collection directory: $(q "$TARGET_OUT")" >&2
    echo "Kept remote archive: $(q "$TARGET_ARCHIVE")" >&2
  fi
}
trap cleanup EXIT
OUT=$(q "$TARGET_OUT")
ARCHIVE=$(q "$TARGET_ARCHIVE")
PROFILE=$(q "$PROFILE")
TIMEOUT_SECONDS=$(q "$TIMEOUT_SECONDS")
MAX_TAIL_CALL_DEPTH=$(q "$MAX_TAIL_CALL_DEPTH")
MAX_PROGRAMS=$(q "$MAX_PROGRAMS")
MAX_PROG_ARRAY_MAPS=$(q "$MAX_PROG_ARRAY_MAPS")
MAX_TC_DEVS=$(q "$MAX_TC_DEVS")
BPFTOOL=$(q "$BPFTOOL_VALUE")
SUDO=$(q "$SUDO_VALUE")
INCLUDE_XLATED=$(q "$INCLUDE_XLATED")
INCLUDE_TEXT=$(q "$INCLUDE_TEXT")
INCLUDE_JITED=$(q "$INCLUDE_JITED")
DUMP_PROG_ARRAY_MAPS=$(q "$DUMP_PROG_ARRAY_MAPS")
RUN_NICE=1
RUN_IONICE=1
export OUT ARCHIVE PROFILE TIMEOUT_SECONDS MAX_TAIL_CALL_DEPTH MAX_PROGRAMS
export MAX_PROG_ARRAY_MAPS MAX_TC_DEVS BPFTOOL SUDO INCLUDE_XLATED
export INCLUDE_TEXT INCLUDE_JITED DUMP_PROG_ARRAY_MAPS RUN_NICE RUN_IONICE
bash $(q "$TARGET_SCRIPT") >&2
status=\$?
if [ "\$status" -ne 0 ]; then
  echo "Target collector failed with status \$status" >&2
  exit "\$status"
fi
if [ ! -s $(q "$TARGET_ARCHIVE") ]; then
  echo "Target collector did not create archive: $(q "$TARGET_ARCHIVE")" >&2
  exit 1
fi
cat $(q "$TARGET_ARCHIVE")
EOF
)"

ssh "${SSH_TARGET_ARGS[@]}" "$TARGET" "$TARGET_COMMAND"
REMOTE_RELAY
then
  mv "$TMP_OUTPUT" "$OUTPUT"
  TMP_OUTPUT=""
else
  rm -f "$TMP_OUTPUT" 2>/dev/null || true
  TMP_OUTPUT=""
  echo "Collection failed." >&2
  exit 1
fi

echo ""
echo "Downloaded: $OUTPUT"
if command -v du >/dev/null 2>&1; then
  du -h "$OUTPUT" 2>/dev/null || true
fi

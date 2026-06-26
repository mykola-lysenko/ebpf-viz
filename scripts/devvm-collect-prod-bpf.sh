#!/usr/bin/env bash
# Collect BPF data from a production target by relaying through a dev VM.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANALYSIS_COLLECTOR="$ROOT_DIR/scripts/collect-l3-bpf.sh"
SNAPSHOT_COLLECTOR="$ROOT_DIR/scripts/capture-snapshot.sh"

DEVVM=""
TARGET=""
OUTPUT=""
REMOTE_SCRIPT="/tmp/ebpf-viz-prod-collector-$$.sh"
TARGET_CONTROL_PATH="/tmp/evz-tgt-$$.ssh"
COLLECTOR_MODE="${COLLECTOR_MODE:-analysis}"
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
SNAPSHOT_DUMP_MAPS="${SNAPSHOT_DUMP_MAPS:-0}"
SNAPSHOT_MAX_MAPS="${SNAPSHOT_MAX_MAPS:-500}"
MAP_OUTPUT=""
SSH_CONTROL_PATH=""
TMP_OUTPUT=""
TMP_EXTRACT=""
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
If target SSH requires interactive authentication, one target SSH prompt may
appear after the dev VM connection opens.

Options:
  --devvm HOST               Dev VM SSH destination.
  --target HOST              Final target SSH destination reachable from dev VM.
  --output PATH              Local output path. Analysis mode writes .tar.gz;
                             snapshot mode writes .json.
  --analysis                 Collect analysis archive via collect-l3-bpf.sh (default).
  --snapshot                 Collect UI snapshot JSON via capture-snapshot.sh.
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
  --dump-maps                Snapshot mode only: also collect map entry dump JSON
  --map-output PATH          Local map dump JSON path for --snapshot --dump-maps
  --max-maps N               Snapshot mode map dump limit (default: 500)
  --keep-remote              Keep target /tmp collection files for debugging
  -h, --help                 Show this help

Examples:
  scripts/devvm-collect-prod-bpf.sh --devvm devvm.example.com --target edge.example.com
  scripts/devvm-collect-prod-bpf.sh devvm.example.com edge.example.com --profile inventory
  scripts/devvm-collect-prod-bpf.sh devvm.example.com edge.example.com --snapshot
  scripts/devvm-collect-prod-bpf.sh devvm.example.com edge.example.com --snapshot --dump-maps
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
  if [ -n "$TMP_EXTRACT" ]; then
    rm -rf "$TMP_EXTRACT" 2>/dev/null || true
  fi
  if [ -n "$DEVVM" ] && [ -n "$SSH_CONTROL_PATH" ] && [ -S "$SSH_CONTROL_PATH" ]; then
    if [ -n "$TARGET" ] && [ -n "$TARGET_CONTROL_PATH" ]; then
      ssh -o BatchMode=yes "${SSH_COMMON_ARGS[@]}" "$DEVVM" \
        "ssh -o BatchMode=yes -o ControlPath=$(shell_quote "$TARGET_CONTROL_PATH") -O exit $(shell_quote "$TARGET") >/dev/null 2>&1 || true; rm -f $(shell_quote "$TARGET_CONTROL_PATH")" \
        >/dev/null 2>&1 || true
    fi
    ssh -o BatchMode=yes "${SSH_COMMON_ARGS[@]}" "$DEVVM" "rm -f $(shell_quote "$REMOTE_SCRIPT")" >/dev/null 2>&1 || true
    ssh -o BatchMode=yes "${SSH_COMMON_ARGS[@]}" -O exit "$DEVVM" >/dev/null 2>&1 || true
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
    --analysis)
      COLLECTOR_MODE="analysis"
      shift
      ;;
    --snapshot)
      COLLECTOR_MODE="snapshot"
      shift
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
    --dump-maps)
      SNAPSHOT_DUMP_MAPS=1
      shift
      ;;
    --map-output)
      require_arg "$1" "${2:-}"
      MAP_OUTPUT="$2"
      shift 2
      ;;
    --max-maps)
      require_arg "$1" "${2:-}"
      SNAPSHOT_MAX_MAPS="$2"
      shift 2
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

case "$COLLECTOR_MODE" in
  analysis|snapshot)
    ;;
  *)
    echo "Unsupported collector mode: $COLLECTOR_MODE" >&2
    usage >&2
    exit 2
    ;;
esac

case "$PROFILE" in
  inventory|network|l3|cgroup|all)
    ;;
  *)
    echo "Unsupported --profile: $PROFILE" >&2
    usage >&2
    exit 2
    ;;
esac

for numeric_value in TIMEOUT_SECONDS MAX_TAIL_CALL_DEPTH MAX_PROGRAMS MAX_PROG_ARRAY_MAPS MAX_TC_DEVS SNAPSHOT_MAX_MAPS; do
  value="${!numeric_value}"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$numeric_value must be numeric, got: $value" >&2
    exit 2
  fi
done

for bool_value in INCLUDE_XLATED INCLUDE_TEXT INCLUDE_JITED DUMP_PROG_ARRAY_MAPS KEEP_REMOTE SNAPSHOT_DUMP_MAPS; do
  value="${!bool_value}"
  if [ "$value" != "0" ] && [ "$value" != "1" ]; then
    echo "$bool_value must be 0 or 1, got: $value" >&2
    exit 2
  fi
done

if [ "$COLLECTOR_MODE" = "snapshot" ]; then
  COLLECTOR="$SNAPSHOT_COLLECTOR"
else
  COLLECTOR="$ANALYSIS_COLLECTOR"
fi

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

TS="$(date +%Y%m%d-%H%M%S)"
SAFE_TARGET="$(safe_name "$TARGET")"
if [ -z "$OUTPUT" ]; then
  if [ "$COLLECTOR_MODE" = "snapshot" ]; then
    OUTPUT="$ROOT_DIR/captures/${SAFE_TARGET}-snapshot-${TS}.json"
  else
    OUTPUT="$ROOT_DIR/captures/${SAFE_TARGET}-${PROFILE}-${TS}.tar.gz"
  fi
fi
if [ "$COLLECTOR_MODE" = "snapshot" ] && [ "$SNAPSHOT_DUMP_MAPS" = "1" ] && [ -z "$MAP_OUTPUT" ]; then
  output_dir="$(dirname "$OUTPUT")"
  output_base="$(basename "$OUTPUT")"
  output_stem="${output_base%.*}"
  MAP_OUTPUT="$output_dir/${output_stem}-mapdumps.json"
fi

mkdir -p "$(dirname "$OUTPUT")"
if [ -n "$MAP_OUTPUT" ]; then
  mkdir -p "$(dirname "$MAP_OUTPUT")"
fi
setup_ssh_mux
trap cleanup EXIT

echo "=== Opening shared SSH connection to dev VM ==="
echo "One SSH auth prompt is expected here; later devvm steps reuse this connection."
ssh "${SSH_COMMON_ARGS[@]}" -fN "$DEVVM"

echo ""
echo "=== Uploading collector to dev VM ==="
scp "${SCP_COMMON_ARGS[@]}" "$COLLECTOR" "$DEVVM:$REMOTE_SCRIPT"

echo ""
echo "=== Opening target SSH connection from dev VM ==="
echo "One target SSH auth prompt may appear here if the target requires it."
TARGET_OPEN_COMMAND="$(
  printf 'ssh -o ControlMaster=auto -o ControlPath=%s -o ControlPersist=10m -o LogLevel=ERROR -fN %s' \
    "$(shell_quote "$TARGET_CONTROL_PATH")" \
    "$(shell_quote "$TARGET")"
)"
SSH_TTY_ARGS=()
if [ -t 0 ]; then
  SSH_TTY_ARGS=(-tt)
fi
ssh "${SSH_COMMON_ARGS[@]}" ${SSH_TTY_ARGS[@]+"${SSH_TTY_ARGS[@]}"} "$DEVVM" "$TARGET_OPEN_COMMAND"

echo ""
echo "=== Collecting from target through dev VM ==="
echo "Dev VM: $DEVVM"
echo "Target: $TARGET"
echo "Collector: $COLLECTOR_MODE"
echo "Profile: $PROFILE"
echo "Local output: $OUTPUT"
if [ "$COLLECTOR_MODE" = "snapshot" ]; then
  if [ "$SNAPSHOT_DUMP_MAPS" = "1" ]; then
    echo "Map dump output: $MAP_OUTPUT"
    echo "Snapshot map dump limit: $SNAPSHOT_MAX_MAPS"
  else
    echo "Map dumps: disabled"
  fi
else
  echo "Limits: programs=$MAX_PROGRAMS prog-array-maps=$MAX_PROG_ARRAY_MAPS tc-devices=$MAX_TC_DEVS"
  if [ "$INCLUDE_JITED" = "0" ]; then
    echo "JIT dumps: disabled"
  else
    echo "JIT dumps: enabled"
  fi
fi

TMP_OUTPUT="${OUTPUT}.tmp.$$"
RELAY_ARGS=(
  "$REMOTE_SCRIPT"
  "$COLLECTOR_MODE"
  "$TARGET_CONTROL_PATH"
  "$TARGET"
  "$PROFILE"
  "$TIMEOUT_SECONDS"
  "$MAX_TAIL_CALL_DEPTH"
  "$MAX_PROGRAMS"
  "$MAX_PROG_ARRAY_MAPS"
  "$MAX_TC_DEVS"
  "$BPFTOOL_VALUE"
  "$SUDO_VALUE"
  "$INCLUDE_XLATED"
  "$INCLUDE_TEXT"
  "$INCLUDE_JITED"
  "$DUMP_PROG_ARRAY_MAPS"
  "$SNAPSHOT_DUMP_MAPS"
  "$SNAPSHOT_MAX_MAPS"
  "$KEEP_REMOTE"
)
RELAY_COMMAND="bash -s --"
for arg in "${RELAY_ARGS[@]}"; do
  RELAY_COMMAND+=" $(shell_quote "$arg")"
done

if ssh "${SSH_COMMON_ARGS[@]}" "$DEVVM" "$RELAY_COMMAND" >"$TMP_OUTPUT" <<'REMOTE_RELAY'
set -euo pipefail

REMOTE_SCRIPT="$1"
COLLECTOR_MODE="$2"
TARGET_CONTROL_PATH="$3"
TARGET="$4"
PROFILE="$5"
TIMEOUT_SECONDS="$6"
MAX_TAIL_CALL_DEPTH="$7"
MAX_PROGRAMS="$8"
MAX_PROG_ARRAY_MAPS="$9"
MAX_TC_DEVS="${10}"
BPFTOOL_VALUE="${11}"
SUDO_VALUE="${12}"
INCLUDE_XLATED="${13}"
INCLUDE_TEXT="${14}"
INCLUDE_JITED="${15}"
DUMP_PROG_ARRAY_MAPS="${16}"
SNAPSHOT_DUMP_MAPS="${17}"
SNAPSHOT_MAX_MAPS="${18}"
KEEP_REMOTE="${19}"

q() {
  printf "%q" "$1"
}

TARGET_SCRIPT="/tmp/ebpf-viz-prod-collector-$$.sh"
TARGET_OUT="/tmp/ebpf-viz-prod-capture-$$"
TARGET_ARCHIVE="/tmp/ebpf-viz-prod-capture-$$.tar.gz"
SSH_TARGET_ARGS=(
  -o ControlMaster=auto
  -o ControlPath="$TARGET_CONTROL_PATH"
  -o ControlPersist=10m
  -o LogLevel=ERROR
  -o BatchMode=yes
)

cleanup_target_mux() {
  if [ -S "$TARGET_CONTROL_PATH" ]; then
    ssh "${SSH_TARGET_ARGS[@]}" -O exit "$TARGET" >/dev/null 2>&1 || true
  fi
  rm -f "$TARGET_CONTROL_PATH" 2>/dev/null || true
}
trap cleanup_target_mux EXIT

echo "Checking pre-opened target SSH connection..." >&2
ssh "${SSH_TARGET_ARGS[@]}" -O check "$TARGET" 1>&2

echo "Uploading collector to target /tmp..." >&2
ssh "${SSH_TARGET_ARGS[@]}" "$TARGET" \
  "cat > $(q "$TARGET_SCRIPT") && chmod 700 $(q "$TARGET_SCRIPT")" \
  <"$REMOTE_SCRIPT" 1>&2

echo "Running target collector and streaming archive back..." >&2
SNAPSHOT_NO_SUDO_ARG=""
if [ -z "$SUDO_VALUE" ]; then
  SNAPSHOT_NO_SUDO_ARG="--no-sudo"
fi
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
mkdir -p $(q "$TARGET_OUT")
if [ "$(q "$COLLECTOR_MODE")" = "snapshot" ]; then
  SNAPSHOT_ARGS="-o $(q "$TARGET_OUT/snapshot.json")"
  SNAPSHOT_NO_SUDO_ARG=$(q "$SNAPSHOT_NO_SUDO_ARG")
  if [ -n "\$SNAPSHOT_NO_SUDO_ARG" ]; then
    SNAPSHOT_ARGS="\$SNAPSHOT_ARGS \$SNAPSHOT_NO_SUDO_ARG"
  fi
  if [ "$(q "$SNAPSHOT_DUMP_MAPS")" = "1" ]; then
    SNAPSHOT_ARGS="\$SNAPSHOT_ARGS --dump-maps --dump-output $(q "$TARGET_OUT/mapdumps.json") --max-maps $(q "$SNAPSHOT_MAX_MAPS")"
  fi
  BPFTOOL_PATH=$(q "$BPFTOOL_VALUE") SUDO=$(q "$SUDO_VALUE") bash $(q "$TARGET_SCRIPT") \$SNAPSHOT_ARGS >&2
  status=\$?
  if [ "\$status" -ne 0 ]; then
    echo "Target collector failed with status \$status" >&2
    exit "\$status"
  fi
  if [ ! -s $(q "$TARGET_OUT/snapshot.json") ]; then
    echo "Target snapshot collector did not create snapshot.json" >&2
    exit 1
  fi
  if [ "$(q "$SNAPSHOT_DUMP_MAPS")" = "1" ] && [ -s $(q "$TARGET_OUT/mapdumps.json") ]; then
    tar -C $(q "$TARGET_OUT") -czf $(q "$TARGET_ARCHIVE") snapshot.json mapdumps.json
  else
    tar -C $(q "$TARGET_OUT") -czf $(q "$TARGET_ARCHIVE") snapshot.json
  fi
else
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
fi
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
  if [ "$COLLECTOR_MODE" = "snapshot" ]; then
    TMP_EXTRACT="$(mktemp -d "${TMPDIR:-/tmp}/evz-snapshot.XXXXXX")"
    tar -xzf "$TMP_OUTPUT" -C "$TMP_EXTRACT"
    if [ ! -s "$TMP_EXTRACT/snapshot.json" ]; then
      echo "Collection failed: streamed archive did not contain snapshot.json." >&2
      exit 1
    fi
    mv "$TMP_EXTRACT/snapshot.json" "$OUTPUT"
    if [ "$SNAPSHOT_DUMP_MAPS" = "1" ]; then
      if [ -s "$TMP_EXTRACT/mapdumps.json" ]; then
        mv "$TMP_EXTRACT/mapdumps.json" "$MAP_OUTPUT"
      else
        echo "Warning: snapshot map dumps were requested, but mapdumps.json was not produced." >&2
      fi
    fi
    rm -rf "$TMP_EXTRACT"
    TMP_EXTRACT=""
    rm -f "$TMP_OUTPUT"
    TMP_OUTPUT=""
  else
    mv "$TMP_OUTPUT" "$OUTPUT"
    TMP_OUTPUT=""
  fi
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
  if [ -n "$MAP_OUTPUT" ] && [ -f "$MAP_OUTPUT" ]; then
    du -h "$MAP_OUTPUT" 2>/dev/null || true
  fi
fi

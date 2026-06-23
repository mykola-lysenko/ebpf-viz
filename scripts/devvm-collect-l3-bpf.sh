#!/usr/bin/env bash
# Upload the L3/cgroup networking BPF collector to a dev VM, run it there, and download results.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COLLECTOR="$ROOT_DIR/scripts/collect-l3-bpf.sh"

REMOTE=""
REMOTE_SCRIPT="/tmp/ebpf-viz-collect-l3-bpf.sh"
REMOTE_ARCHIVE="/tmp/ebpf-viz-l3-latest.tar.gz"
OUTPUT="$ROOT_DIR/ebpf-viz-l3-latest.tar.gz"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-45}"
MAX_TAIL_CALL_DEPTH="${MAX_TAIL_CALL_DEPTH:-8}"
BPFTOOL_VALUE="${BPFTOOL:-bpftool}"
SUDO_VALUE="${SUDO:-sudo}"
SSH_CONTROL_PATH=""
SSH_COMMON_ARGS=()
SCP_COMMON_ARGS=()

usage() {
  cat <<'USAGE'
Usage:
  scripts/devvm-collect-l3-bpf.sh [options] user@devvm

Uploads scripts/collect-l3-bpf.sh to the dev VM, executes it there, and
downloads the resulting tarball locally. The archive includes L3 programs,
cgroup networking chains, prog-array maps, and followed tail-call targets.

Options:
  --output PATH          Local tarball path (default: ./ebpf-viz-l3-latest.tar.gz)
  --remote-archive PATH  Remote tarball path (default: /tmp/ebpf-viz-l3-latest.tar.gz)
  --remote-script PATH   Remote script path (default: /tmp/ebpf-viz-collect-l3-bpf.sh)
  --timeout SECONDS      Per-bpftool command timeout on the dev VM (default: 45)
  --max-depth N          Tail-call prog-array discovery depth (default: 8)
  --bpftool PATH         bpftool path on the dev VM (default: bpftool)
  --no-sudo              Run bpftool/tc without sudo on the dev VM
  -h, --help             Show this help

Examples:
  scripts/devvm-collect-l3-bpf.sh user@devvm.example.com
  scripts/devvm-collect-l3-bpf.sh --output ./captures/l3.tar.gz user@devvm.example.com
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

shell_quote() {
  printf "%q" "$1"
}

setup_ssh_mux() {
  # OpenSSH Unix-domain socket paths have a small platform-dependent limit.
  # macOS TMPDIR is often under /var/folders/... and can exceed that limit.
  SSH_CONTROL_PATH="/tmp/ebpf-viz-l3-$$.ssh"
  SSH_COMMON_ARGS=(
    -o ControlMaster=auto
    -o ControlPath="$SSH_CONTROL_PATH"
    -o ControlPersist=10m
  )
  SCP_COMMON_ARGS=(
    -o ControlMaster=auto
    -o ControlPath="$SSH_CONTROL_PATH"
    -o ControlPersist=10m
  )
}

cleanup_ssh_mux() {
  if [ -n "$SSH_CONTROL_PATH" ]; then
    ssh "${SSH_COMMON_ARGS[@]}" -O exit "$REMOTE" >/dev/null 2>&1 || true
    rm -f "$SSH_CONTROL_PATH" 2>/dev/null || true
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      require_arg "$1" "${2:-}"
      OUTPUT="$2"
      shift 2
      ;;
    --remote-archive)
      require_arg "$1" "${2:-}"
      REMOTE_ARCHIVE="$2"
      shift 2
      ;;
    --remote-script)
      require_arg "$1" "${2:-}"
      REMOTE_SCRIPT="$2"
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
    --bpftool)
      require_arg "$1" "${2:-}"
      BPFTOOL_VALUE="$2"
      shift 2
      ;;
    --no-sudo)
      SUDO_VALUE=""
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      ;;
    --*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [ -n "$REMOTE" ]; then
        echo "Unexpected extra argument: $1" >&2
        usage >&2
        exit 2
      fi
      REMOTE="$1"
      shift
      ;;
  esac
done

if [ -z "$REMOTE" ]; then
  usage >&2
  exit 2
fi

if ! [[ "$TIMEOUT_SECONDS" =~ ^[0-9]+$ && "$MAX_TAIL_CALL_DEPTH" =~ ^[0-9]+$ ]]; then
  echo "--timeout and --max-depth must be numeric." >&2
  exit 2
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

mkdir -p "$(dirname "$OUTPUT")"
setup_ssh_mux
trap cleanup_ssh_mux EXIT

echo "=== Opening shared SSH connection ==="
echo "One SSH auth prompt is expected here; upload/download reuse this connection."
ssh "${SSH_COMMON_ARGS[@]}" -fN "$REMOTE"

echo ""
echo "=== Uploading collector ==="
scp "${SCP_COMMON_ARGS[@]}" "$COLLECTOR" "$REMOTE:$REMOTE_SCRIPT"

echo ""
echo "=== Running remote collection ==="
REMOTE_COMMAND="$(
  printf 'chmod +x %s && ARCHIVE=%s TIMEOUT_SECONDS=%s MAX_TAIL_CALL_DEPTH=%s BPFTOOL=%s SUDO=%s bash %s' \
    "$(shell_quote "$REMOTE_SCRIPT")" \
    "$(shell_quote "$REMOTE_ARCHIVE")" \
    "$(shell_quote "$TIMEOUT_SECONDS")" \
    "$(shell_quote "$MAX_TAIL_CALL_DEPTH")" \
    "$(shell_quote "$BPFTOOL_VALUE")" \
    "$(shell_quote "$SUDO_VALUE")" \
    "$(shell_quote "$REMOTE_SCRIPT")"
)"
SSH_TTY_ARGS=()
if [ -t 0 ]; then
  SSH_TTY_ARGS=(-tt)
fi
ssh "${SSH_COMMON_ARGS[@]}" "${SSH_TTY_ARGS[@]}" "$REMOTE" "$REMOTE_COMMAND"

echo ""
echo "=== Downloading archive ==="
scp "${SCP_COMMON_ARGS[@]}" "$REMOTE:$REMOTE_ARCHIVE" "$OUTPUT"

echo ""
echo "Downloaded: $OUTPUT"
if command -v du >/dev/null 2>&1; then
  du -h "$OUTPUT" 2>/dev/null || true
fi

#!/usr/bin/env bash
# Build, upload, run, and tunnel a standalone eBPF Viz package on a dev VM.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARBALL="$ROOT_DIR/ebpf-viz-standalone.tar.gz"

REMOTE=""
REMOTE_DIR="~/ebpf-viz-standalone"
REMOTE_PORT="3000"
LOCAL_PORT="3000"
REMOTE_HOST="127.0.0.1"
BUILD=1
START=1
TUNNEL=1
DEMO_MODE_VALUE="${DEMO_MODE:-0}"
BPFTOOL_PATH_VALUE="${BPFTOOL_PATH:-}"
SSH_CONTROL_PATH=""
SSH_COMMON_ARGS=()
SCP_COMMON_ARGS=()

shell_quote() {
  printf "%q" "$1"
}

usage() {
  cat <<'USAGE'
Usage:
  scripts/devvm-standalone.sh [options] user@devvm

Builds the standalone tarball locally, uploads it to the dev VM, extracts it,
starts the app on the dev VM, then opens an SSH tunnel.

Options:
  --remote-dir DIR     Remote install dir (default: ~/ebpf-viz-standalone)
  --remote-port PORT   Port on the dev VM (default: 3000)
  --local-port PORT    Local tunnel port (default: 3000)
  --remote-host HOST   Host/IP to bind on the dev VM (default: 127.0.0.1)
  --bpftool-path PATH  Set BPFTOOL_PATH for the remote app
  --demo               Start in demo mode
  --no-build           Reuse existing ebpf-viz-standalone.tar.gz
  --no-start           Upload/extract only, do not restart the remote app
  --no-tunnel          Do not open an SSH tunnel
  -h, --help           Show this help

Examples:
  scripts/devvm-standalone.sh user@devvm.example.com
  scripts/devvm-standalone.sh --local-port 3300 user@devvm.example.com
  scripts/devvm-standalone.sh --no-build --no-tunnel user@devvm.example.com
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

while [ "$#" -gt 0 ]; do
  case "$1" in
    --remote-dir)
      require_arg "$1" "${2:-}"
      REMOTE_DIR="$2"
      shift 2
      ;;
    --remote-port)
      require_arg "$1" "${2:-}"
      REMOTE_PORT="$2"
      shift 2
      ;;
    --local-port)
      require_arg "$1" "${2:-}"
      LOCAL_PORT="$2"
      shift 2
      ;;
    --remote-host)
      require_arg "$1" "${2:-}"
      REMOTE_HOST="$2"
      shift 2
      ;;
    --bpftool-path)
      require_arg "$1" "${2:-}"
      BPFTOOL_PATH_VALUE="$2"
      shift 2
      ;;
    --demo)
      DEMO_MODE_VALUE=1
      shift
      ;;
    --no-build)
      BUILD=0
      shift
      ;;
    --no-start)
      START=0
      shift
      ;;
    --no-tunnel)
      TUNNEL=0
      shift
      ;;
    --)
      shift
      ;;
    -h|--help)
      usage
      exit 0
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

if ! [[ "$REMOTE_PORT" =~ ^[0-9]+$ && "$LOCAL_PORT" =~ ^[0-9]+$ ]]; then
  echo "Ports must be numeric." >&2
  exit 2
fi

for tool in ssh scp; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required." >&2
    exit 1
  fi
done

setup_ssh_mux() {
  # OpenSSH Unix-domain socket paths have a small platform-dependent limit.
  # macOS TMPDIR is often under /var/folders/... and can exceed that limit.
  SSH_CONTROL_PATH="/tmp/ebpf-viz-standalone-$$.ssh"
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

cleanup() {
  cleanup_ssh_mux
}

health_check_local() {
  local port="$1"
  local url="http://127.0.0.1:${port}/healthz"
  if command -v curl >/dev/null 2>&1; then
    curl --fail --silent --connect-timeout 1 --max-time 1 "$url" >/dev/null
    return $?
  fi

  node - "$port" <<'NODE'
const http = require("http");
const port = process.argv[2];
const request = http.get(
  {
    hostname: "127.0.0.1",
    port,
    path: "/healthz",
    timeout: 1000,
  },
  (response) => {
    response.resume();
    process.exit(response.statusCode === 200 ? 0 : 1);
  },
);

request.on("timeout", () => {
  request.destroy();
  process.exit(2);
});
request.on("error", () => process.exit(1));
NODE
}

SSH_TTY_ARGS=()
if [ -t 0 ]; then
  # Remote start uses sudo; allocate a TTY so password prompts still work.
  SSH_TTY_ARGS=(-tt)
fi

if [ "$BUILD" -eq 1 ]; then
  echo "=== Building standalone tarball ==="
  (cd "$ROOT_DIR" && bash build-standalone.sh)
elif [ ! -f "$TARBALL" ]; then
  echo "Missing $TARBALL. Run without --no-build first." >&2
  exit 1
fi

setup_ssh_mux
trap cleanup EXIT

echo ""
echo "=== Opening shared SSH connection ==="
echo "One SSH auth prompt is expected here; later ssh/scp steps reuse this connection."
ssh "${SSH_COMMON_ARGS[@]}" -fN "$REMOTE"

echo ""
echo "=== Preparing remote directory ==="
REMOTE_DIR_ABS="$(
  ssh "${SSH_COMMON_ARGS[@]}" "$REMOTE" "bash -s -- $(shell_quote "$REMOTE_DIR")" <<'REMOTE_PREP'
set -euo pipefail
dir="$1"
if [ "$dir" = "~" ]; then
  dir="$HOME"
elif [ "${dir:0:2}" = "~/" ]; then
  dir="$HOME/${dir:2}"
fi
mkdir -p "$dir"
cd "$dir"
pwd
REMOTE_PREP
)"
echo "Remote directory: $REMOTE:$REMOTE_DIR_ABS"
echo "Local URL after tunnel starts: http://127.0.0.1:$LOCAL_PORT"
echo "Preferred remote port: $REMOTE_HOST:$REMOTE_PORT"

echo ""
echo "=== Uploading standalone tarball ==="
scp "${SCP_COMMON_ARGS[@]}" "$TARBALL" "$REMOTE:$REMOTE_DIR_ABS/ebpf-viz-standalone.tar.gz"

echo ""
echo "=== Extracting on remote ==="
ssh "${SSH_COMMON_ARGS[@]}" "$REMOTE" "bash -s -- $(shell_quote "$REMOTE_DIR_ABS")" <<'REMOTE_EXTRACT'
set -euo pipefail
REMOTE_DIR_ABS="$1"
cd "$REMOTE_DIR_ABS"
rm -rf standalone
tar -xzf ebpf-viz-standalone.tar.gz
cat > .ebpf-viz-start.sh <<'REMOTE_START_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

REMOTE_DIR_ABS="$1"
REMOTE_PORT="$2"
REMOTE_HOST="$3"
DEMO_MODE_VALUE="$4"
BPFTOOL_PATH_VALUE="$5"

cd "$REMOTE_DIR_ABS"
LOG_FILE="$REMOTE_DIR_ABS/ebpf-viz.log"
PID_FILE="$REMOTE_DIR_ABS/ebpf-viz.pid"

run_privileged() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

pid_is_alive() {
  local pid="$1"
  if [ -z "$pid" ]; then
    return 1
  fi

  if [ "$(id -u)" -eq 0 ]; then
    kill -0 "$pid" 2>/dev/null
  else
    sudo kill -0 "$pid" 2>/dev/null
  fi
}

stop_pid() {
  local pid="$1"
  if ! pid_is_alive "$pid"; then
    return 0
  fi

  echo "Stopping previous eBPF Viz process: $pid"
  run_privileged kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    if ! pid_is_alive "$pid"; then
      return 0
    fi
    sleep 0.25
  done

  echo "Previous process $pid did not exit; sending SIGKILL"
  run_privileged kill -9 "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    if ! pid_is_alive "$pid"; then
      return 0
    fi
    sleep 0.25
  done
}

if [ -f "$PID_FILE" ]; then
  old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  stop_pid "$old_pid"
  rm -f "$PID_FILE" 2>/dev/null || sudo rm -f "$PID_FILE" 2>/dev/null || true
fi

if command -v pgrep >/dev/null 2>&1; then
  for orphan_pid in $(pgrep -f "$REMOTE_DIR_ABS/standalone/server.js" 2>/dev/null || true); do
    if [ "$orphan_pid" != "$$" ]; then
      stop_pid "$orphan_pid"
    fi
  done
fi

cat > standalone/.env <<ENV
NODE_ENV=production
PORT=$REMOTE_PORT
HOST=$REMOTE_HOST
DEMO_MODE=$DEMO_MODE_VALUE
ENV

if [ -n "$BPFTOOL_PATH_VALUE" ]; then
  printf 'BPFTOOL_PATH=%s\n' "$BPFTOOL_PATH_VALUE" >> standalone/.env
fi

if [ "$(id -u)" -eq 0 ]; then
  env \
    NODE_ENV=production \
    PORT="$REMOTE_PORT" \
    HOST="$REMOTE_HOST" \
    DEMO_MODE="$DEMO_MODE_VALUE" \
    BPFTOOL_PATH="$BPFTOOL_PATH_VALUE" \
    bash -c 'cd "$0"; nohup ./standalone/start.sh > "$1" 2>&1 & echo $! > "$2"' \
    "$REMOTE_DIR_ABS" "$LOG_FILE" "$PID_FILE"
else
  sudo env \
    NODE_ENV=production \
    PORT="$REMOTE_PORT" \
    HOST="$REMOTE_HOST" \
    DEMO_MODE="$DEMO_MODE_VALUE" \
    BPFTOOL_PATH="$BPFTOOL_PATH_VALUE" \
    bash -c 'cd "$0"; nohup ./standalone/start.sh > "$1" 2>&1 & echo $! > "$2"' \
    "$REMOTE_DIR_ABS" "$LOG_FILE" "$PID_FILE"
fi

echo "PID: $(cat "$PID_FILE")"
echo "Log: $LOG_FILE"

extract_bound_port() {
  sed -n 's/.*Server running on http:\/\/.*:\([0-9][0-9]*\)\/.*/\1/p' "$LOG_FILE" 2>/dev/null | tail -1 || true
}

echo "Waiting for server to bind..."
for _ in $(seq 1 30); do
  actual_port="$(extract_bound_port)"
  if [ -n "$actual_port" ]; then
    echo ""
    if [ "$actual_port" != "$REMOTE_PORT" ]; then
      echo "Requested remote port $REMOTE_PORT was busy; server bound to $actual_port."
    fi
    echo "BOUND_PORT=$actual_port"
    exit 0
  fi

  server_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -n "$server_pid" ] && ! pid_is_alive "$server_pid"; then
    echo "" >&2
    echo "Remote app exited before reporting a bound port." >&2
    echo "Last log lines:" >&2
    tail -80 "$LOG_FILE" >&2 || sudo tail -80 "$LOG_FILE" >&2 || true
    exit 1
  fi

  printf "."
  sleep 1
done

echo ""
echo "Remote app did not report a bound port." >&2
echo "Last log lines:" >&2
tail -80 "$LOG_FILE" >&2 || sudo tail -80 "$LOG_FILE" >&2 || true
exit 1
REMOTE_START_SCRIPT
chmod +x .ebpf-viz-start.sh
REMOTE_EXTRACT

ACTUAL_REMOTE_PORT="$REMOTE_PORT"

if [ "$START" -eq 1 ]; then
  echo ""
  echo "=== Restarting remote standalone server ==="
  START_OUTPUT_FILE="$(mktemp -t ebpf-viz-devvm-start.XXXXXX)"
  if ! ssh "${SSH_COMMON_ARGS[@]}" "${SSH_TTY_ARGS[@]}" "$REMOTE" \
    "bash $(shell_quote "$REMOTE_DIR_ABS/.ebpf-viz-start.sh") $(shell_quote "$REMOTE_DIR_ABS") $(shell_quote "$REMOTE_PORT") $(shell_quote "$REMOTE_HOST") $(shell_quote "$DEMO_MODE_VALUE") $(shell_quote "$BPFTOOL_PATH_VALUE")" \
    | tee "$START_OUTPUT_FILE"; then
    rm -f "$START_OUTPUT_FILE"
    exit 1
  fi

  detected_port="$(sed -n 's/.*BOUND_PORT=\([0-9][0-9]*\).*/\1/p' "$START_OUTPUT_FILE" | tail -1 | tr -d '\r')"
  rm -f "$START_OUTPUT_FILE"
  if [ -z "$detected_port" ]; then
    echo "Remote start did not report BOUND_PORT." >&2
    exit 1
  fi
  ACTUAL_REMOTE_PORT="$detected_port"
else
  echo "Skipping remote restart (--no-start)."
fi

echo ""
echo "Remote app: $REMOTE_HOST:$ACTUAL_REMOTE_PORT"
echo "Remote log: $REMOTE:$REMOTE_DIR_ABS/ebpf-viz.log"
echo "Local URL: http://127.0.0.1:$LOCAL_PORT"
echo "Tunnel: 127.0.0.1:$LOCAL_PORT -> $REMOTE:127.0.0.1:$ACTUAL_REMOTE_PORT"

if [ "$TUNNEL" -eq 1 ]; then
  echo ""
  echo "=== Opening SSH tunnel ==="
  if ! ssh "${SSH_COMMON_ARGS[@]}" -o ExitOnForwardFailure=yes -O forward -L "$LOCAL_PORT:127.0.0.1:$ACTUAL_REMOTE_PORT" "$REMOTE"; then
    echo "SSH tunnel failed to start. Local port $LOCAL_PORT may already be in use." >&2
    exit 1
  fi

  echo "Waiting for local health check: http://127.0.0.1:$LOCAL_PORT/healthz"
  for _ in $(seq 1 15); do
    if health_check_local "$LOCAL_PORT"; then
      echo ""
      echo "Health check passed: http://127.0.0.1:$LOCAL_PORT/healthz"
      echo "Open: http://127.0.0.1:$LOCAL_PORT"
      echo "Press Ctrl+C to close the tunnel. The remote server keeps running."
      while true; do
        sleep 3600
      done
    fi

    printf "."
    sleep 1
  done

  echo ""
  echo "Local health check failed through the SSH tunnel." >&2
  echo "Remote log: $REMOTE:$REMOTE_DIR_ABS/ebpf-viz.log" >&2
  exit 1
else
  echo ""
  echo "Tunnel skipped. Open one manually with:"
  echo "  ssh -N -L $LOCAL_PORT:127.0.0.1:$ACTUAL_REMOTE_PORT $REMOTE"
fi

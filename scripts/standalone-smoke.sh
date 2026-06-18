#!/usr/bin/env bash
# Smoke-test the generated standalone package.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STANDALONE_DIR="${STANDALONE_DIR:-$ROOT_DIR/standalone}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
LOG_FILE="${LOG_FILE:-$(mktemp -t ebpf-viz-standalone-smoke.XXXXXX.log)}"

if [ -n "${EXPECTED_NODE_MAJOR:-}" ]; then
  actual_major="$(node -e "process.stdout.write(String(process.versions.node.split('.')[0]))")"
  if [ "$actual_major" != "$EXPECTED_NODE_MAJOR" ]; then
    echo "Expected Node.js major $EXPECTED_NODE_MAJOR, found $(node --version)" >&2
    exit 1
  fi
fi

if [ ! -x "$STANDALONE_DIR/start.sh" ]; then
  echo "Standalone package not found at $STANDALONE_DIR. Run build-standalone.sh first." >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required for the standalone smoke test." >&2
  exit 1
fi

PORT="${PORT:-$(node - <<'NODE'
const server = require("net").createServer();
server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  console.log(address.port);
  server.close();
});
NODE
)}"

cleanup() {
  if [ -n "${server_pid:-}" ] && kill -0 "$server_pid" >/dev/null 2>&1; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "Starting standalone smoke test with Node.js $(node --version) on port $PORT"
(
  cd "$STANDALONE_DIR"
  HOST=127.0.0.1 PORT="$PORT" ./start.sh --demo
) >"$LOG_FILE" 2>&1 &
server_pid="$!"

health_url="http://127.0.0.1:$PORT/healthz"
status_url="http://127.0.0.1:$PORT/api/trpc/ebpf.status?batch=1"

for _ in $(seq 1 "$TIMEOUT_SECONDS"); do
  if ! kill -0 "$server_pid" >/dev/null 2>&1; then
    echo "Standalone server exited before becoming healthy." >&2
    cat "$LOG_FILE" >&2
    exit 1
  fi

  if curl -fsS "$health_url" >/dev/null 2>&1; then
    status_body="$(curl -fsS "$status_url")"
    if [[ "$status_body" == *'"running":true'* && "$status_body" == *'"demoMode":true'* ]]; then
      echo "Standalone smoke test passed."
      exit 0
    fi

    echo "Unexpected tRPC status response:" >&2
    echo "$status_body" >&2
    cat "$LOG_FILE" >&2
    exit 1
  fi

  sleep 1
done

echo "Standalone server did not become healthy within ${TIMEOUT_SECONDS}s." >&2
cat "$LOG_FILE" >&2
exit 1

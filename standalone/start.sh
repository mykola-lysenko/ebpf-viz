#!/usr/bin/env bash
# start.sh — run on the devserver (requires Node.js >= 18 only, no npm needed)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load .env if present
if [ -f "$SCRIPT_DIR/.env" ]; then
  set -o allexport
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/.env"
  set +o allexport
fi

# Defaults
export NODE_ENV="${NODE_ENV:-production}"
export PORT="${PORT:-3000}"

echo "Starting eBPF Viz on port $PORT..."
echo "Open http://localhost:$PORT in your browser."
echo "Press Ctrl+C to stop."
echo ""

exec node "$SCRIPT_DIR/server.js"

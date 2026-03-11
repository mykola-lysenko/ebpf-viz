#!/usr/bin/env bash
# start.sh — run on the devserver (requires Node.js >= 16 only, no npm needed)
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
# HOST controls the network interface to bind on.
#   Unset (default) → 0.0.0.0  (all IPv4 interfaces)
#   HOST=::          → all IPv6 interfaces (dual-stack: also accepts IPv4)
#   HOST=0.0.0.0     → all IPv4 interfaces (explicit)
#   HOST=::1         → loopback IPv6 only
export HOST="${HOST:-}"

if [ -n "$HOST" ]; then
  DISPLAY_HOST="$HOST"
  # Wrap bare IPv6 addresses in brackets for display
  if [[ "$HOST" == *:* && "$HOST" != \[* ]]; then
    DISPLAY_HOST="[$HOST]"
  fi
  echo "Starting eBPF Viz on http://${DISPLAY_HOST}:${PORT}/"
else
  echo "Starting eBPF Viz on http://localhost:${PORT}/"
fi
echo "Press Ctrl+C to stop."
echo ""

exec node "$SCRIPT_DIR/server.js"

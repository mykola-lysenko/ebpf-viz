#!/usr/bin/env bash
# start.sh — run on the devserver (requires Node.js >= 16 only, no npm needed)
#
# Usage:
#   ./start.sh           — normal mode (reads .env)
#   ./start.sh --demo    — force DEMO_MODE=1 (synthetic data, no bpftool needed)
#   ./start.sh --help    — show this message
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Parse flags ────────────────────────────────────────────────────────────────
DEMO_FLAG=0
for arg in "$@"; do
  case "$arg" in
    --demo)   DEMO_FLAG=1 ;;
    --help|-h)
      echo "Usage: $0 [--demo] [--help]"
      echo ""
      echo "  --demo   Start in demo mode (synthetic data, no bpftool required)"
      echo "  --help   Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      echo "Run '$0 --help' for usage." >&2
      exit 1
      ;;
  esac
done

# ── Check Node.js version ──────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  echo "ERROR: Node.js is not installed or not on PATH." >&2
  echo "Install Node.js >= 16 from https://nodejs.org/" >&2
  exit 1
fi

NODE_MAJOR=$(node -e "process.stdout.write(String(process.versions.node.split('.')[0]))")
if [ "$NODE_MAJOR" -lt 16 ]; then
  echo "ERROR: Node.js >= 16 is required (found: $(node --version))." >&2
  echo "Upgrade Node.js from https://nodejs.org/" >&2
  exit 1
fi

# ── Load .env if present ───────────────────────────────────────────────────────
if [ -f "$SCRIPT_DIR/.env" ]; then
  set -o allexport
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/.env"
  set +o allexport
fi

# ── Apply defaults and flag overrides ─────────────────────────────────────────
export NODE_ENV="${NODE_ENV:-production}"
export PORT="${PORT:-3000}"
# HOST controls the network interface to bind on.
#   Unset (default) → 0.0.0.0  (all IPv4 interfaces)
#   HOST=::          → all IPv6 interfaces (dual-stack: also accepts IPv4)
#   HOST=0.0.0.0     → all IPv4 interfaces (explicit)
#   HOST=::1         → loopback IPv6 only
export HOST="${HOST:-}"

if [ "$DEMO_FLAG" -eq 1 ]; then
  export DEMO_MODE=1
  echo "[demo] Starting in demo mode (synthetic data — no bpftool required)"
fi

# ── Print startup info ─────────────────────────────────────────────────────────
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
echo "Node.js $(node --version)"
echo "Press Ctrl+C to stop."
echo ""

# ── Launch server ──────────────────────────────────────────────────────────────
# --no-warnings suppresses Node 16 ESM/experimental API warnings that are
# harmless but noisy (e.g. ExperimentalWarning: The Fetch API is an experimental
# feature). Remove this flag if you want to see all Node.js warnings.
exec node --no-warnings "$SCRIPT_DIR/server.js"

#!/usr/bin/env bash
# build-standalone.sh
# Run this on your Mac (or any machine with Node.js + pnpm/npm).
# Produces ebpf-viz-standalone.tar.gz — copy it to the devserver and run ./start.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/standalone"
TARBALL="$SCRIPT_DIR/ebpf-viz-standalone.tar.gz"
STUB_DIR="$SCRIPT_DIR/.standalone-stubs"

echo "=== eBPF Viz — Standalone Build ==="
echo ""

# ── Pre-flight: check Node.js version ─────────────────────────────────────────
if ! command -v node &>/dev/null; then
  echo "ERROR: Node.js is not installed or not on PATH." >&2
  exit 1
fi

NODE_MAJOR=$(node -e "process.stdout.write(String(process.versions.node.split('.')[0]))")
if [ "$NODE_MAJOR" -lt 20 ]; then
  echo "ERROR: Node.js >= 20 is required to BUILD the standalone package (found: $(node --version))." >&2
  echo "The built package will still run on Node.js >= 16 on the target server." >&2
  echo "Use nvm, fnm, or asdf to install a newer Node.js for building." >&2
  exit 1
fi

# ── 1. Install dependencies ────────────────────────────────────────────────────
echo "[1/6] Installing dependencies..."
cd "$SCRIPT_DIR"
if ! command -v pnpm &>/dev/null; then
  echo "  pnpm not found — enabling corepack..."
  corepack enable
fi
pnpm install --frozen-lockfile

# ── 2. Build the frontend (Vite) ───────────────────────────────────────────────
echo "[2/6] Building frontend (Vite)..."
NODE_ENV=production npx vite build

# ── 3. Create stubs for dev-only packages ─────────────────────────────────────
# vite and its plugins are dev-only; the server never calls setupVite() in
# production (guarded by NODE_ENV === "development"), but esbuild still sees
# the static imports in vite.ts and vite.config.ts.
# We replace them with no-op ESM stubs so the bundle has no runtime dependency
# on vite packages, and avoids import.meta.dirname (Node 21+ only) at startup.
echo "[3/6] Creating dev-dependency stubs..."
rm -rf "$STUB_DIR"
mkdir -p "$STUB_DIR"

# vite — ESM stub
cat > "$STUB_DIR/vite.mjs" << 'STUB'
// Standalone build stub — vite is dev-only and never called in production.
export async function createServer() { throw new Error("Vite not available in standalone mode"); }
export function defineConfig(c) { return c; }
export function mergeConfig(a, b) { return Object.assign({}, a, b); }
const vite = { createServer, defineConfig, mergeConfig };
export default vite;
STUB

# vite-plugin-manus-runtime — ESM stub
cat > "$STUB_DIR/vite-plugin-manus-runtime.mjs" << 'STUB'
export function vitePluginManusRuntime() { return { name: 'manus-runtime-stub' }; }
export default vitePluginManusRuntime;
STUB

# @builder.io/vite-plugin-jsx-loc — ESM stub
cat > "$STUB_DIR/vite-plugin-jsx-loc.mjs" << 'STUB'
export function jsxLocPlugin() { return { name: 'jsx-loc-stub' }; }
export default jsxLocPlugin;
STUB

# @tailwindcss/vite — ESM stub (default export only)
cat > "$STUB_DIR/tailwindcss-vite.mjs" << 'STUB'
function tailwindcss() { return { name: 'tailwindcss-stub' }; }
export default tailwindcss;
STUB

# @vitejs/plugin-react — ESM stub (default export only)
cat > "$STUB_DIR/vitejs-plugin-react.mjs" << 'STUB'
function react() { return { name: 'react-stub' }; }
export default react;
STUB

# vite.config.ts stub — replaces the local vite.config.ts which uses
# import.meta.dirname at module level (only available in Node 21.2+).
# In production the viteConfig object is only used inside setupVite() which
# is never called, so an empty object is a safe replacement.
cat > "$STUB_DIR/vite-config.mjs" << 'STUB'
// Standalone build stub — vite.config.ts is dev-only.
export default {};
STUB

# ── 4. Bundle the server + ALL runtime deps into one file ─────────────────────
# Uses the esbuild JS API (scripts/bundle-server.mjs) which adds a plugin to
# intercept the vite.config.ts import and replace it with the stub above.
# The banner adds a createRequire shim for CJS modules (dotenv, mysql2, etc.).
echo "[4/6] Bundling server (esbuild, all deps inlined)..."
node "$SCRIPT_DIR/scripts/bundle-server.mjs"

# ── 5. Assemble the standalone directory ──────────────────────────────────────
echo "[5/6] Assembling standalone package..."
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# Copy built assets
cp -r "$SCRIPT_DIR/dist/public" "$OUT_DIR/public"
cp "$SCRIPT_DIR/dist/server.js" "$OUT_DIR/server.js"

# Write .env.example (generated so it always reflects current options)
cat > "$OUT_DIR/.env.example" << 'ENVEXAMPLE'
# eBPF Viz — Standalone Configuration
# Copy this file to .env and edit as needed.
# All settings are optional — the server starts with sensible defaults.

# ── Server ────────────────────────────────────────────────────────────────────
# Port to listen on (default: 3000)
PORT=3000

# Network interface / address to bind on.
#   Unset (default) → 0.0.0.0  (all IPv4 interfaces)
#   HOST=::          → all IPv6 interfaces; on dual-stack kernels this also
#                      accepts IPv4 connections via IPv4-mapped addresses
#   HOST=0.0.0.0     → all IPv4 interfaces (explicit)
#   HOST=::1         → loopback IPv6 only
#   HOST=192.168.1.5 → specific IPv4 address
# HOST=::

# Set to "production" (default when running via start.sh)
NODE_ENV=production

# ── bpftool ───────────────────────────────────────────────────────────────────
# Full path to the bpftool binary.
# If not set, the server searches: /usr/sbin/bpftool, /usr/local/sbin/bpftool,
# /sbin/bpftool, and whatever is on $PATH.
# BPFTOOL_PATH=/usr/sbin/bpftool

# How often (in milliseconds) to poll bpftool for new data (default: 5000)
# POLL_INTERVAL_MS=5000

# Set to "true" to start in demo mode (synthetic data, no bpftool required).
# Useful for testing the UI without a Linux kernel with BPF support.
# DEMO_MODE=false

# ── Authentication (optional) ─────────────────────────────────────────────────
# Leave these blank to run without authentication (all endpoints are public).
# All eBPF data procedures are public by default — auth is only needed if you
# want to restrict access to the settings/admin endpoints.
# JWT_SECRET=
# VITE_APP_ID=
# OAUTH_SERVER_URL=
# VITE_OAUTH_PORTAL_URL=

# ── Database (optional) ───────────────────────────────────────────────────────
# Only required if you enable authentication above.
# Without a DATABASE_URL the server skips DB init and runs in auth-less mode.
# DATABASE_URL=mysql://user:password@host:3306/ebpf_viz
ENVEXAMPLE

# Write the start script
cat > "$OUT_DIR/start.sh" << 'STARTSCRIPT'
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
STARTSCRIPT
chmod +x "$OUT_DIR/start.sh"

# Write a minimal package.json (ESM bundle)
cat > "$OUT_DIR/package.json" << 'PKGJSON'
{
  "name": "ebpf-viz-standalone",
  "version": "1.0.0",
  "type": "module"
}
PKGJSON

# ── 6. Create the tarball ──────────────────────────────────────────────────────
echo "[6/6] Creating tarball: $TARBALL"
cd "$SCRIPT_DIR"
tar -czf "$TARBALL" -C "$(dirname "$OUT_DIR")" "$(basename "$OUT_DIR")"

# Cleanup stubs
rm -rf "$STUB_DIR"

# Print sizes
echo ""
echo "=== Build complete ==="
echo "Tarball: $TARBALL"
du -sh "$TARBALL"
echo ""
echo "Contents:"
tar -tzf "$TARBALL" | head -20
echo ""
echo "To deploy (requires Node.js >= 16):"
echo "  scp ebpf-viz-standalone.tar.gz user@devserver:/opt/"
echo "  ssh user@devserver"
echo "  cd /opt && tar -xzf ebpf-viz-standalone.tar.gz"
echo "  cp standalone/.env.example standalone/.env && vi standalone/.env"
echo "  sudo ./standalone/start.sh"

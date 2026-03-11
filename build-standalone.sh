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

# ── 1. Install dependencies ────────────────────────────────────────────────────
echo "[1/6] Installing dependencies..."
cd "$SCRIPT_DIR"
if command -v pnpm &>/dev/null; then
  pnpm install --frozen-lockfile
elif command -v npm &>/dev/null; then
  npm ci
else
  echo "ERROR: neither pnpm nor npm found. Install Node.js first." >&2
  exit 1
fi

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

# Copy env example
cp "$SCRIPT_DIR/.env.example" "$OUT_DIR/.env.example" 2>/dev/null || true

# Write the start script
cat > "$OUT_DIR/start.sh" << 'STARTSCRIPT'
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

echo "Starting eBPF Viz on port $PORT..."
echo "Open http://localhost:$PORT in your browser."
echo "Press Ctrl+C to stop."
echo ""

exec node "$SCRIPT_DIR/server.js"
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

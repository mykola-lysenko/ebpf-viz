# Standalone Deployment Guide

This guide explains how to build a self-contained deployment package for the eBPF Visualizer and run it on a devserver that has only **Node.js ≥ 16** installed — no `npm`, `pnpm`, or Docker required.

---

## Prerequisites

| Machine | Requirements |
|---------|-------------|
| **Build machine** (your laptop) | Node.js ≥ 22, pnpm/corepack, internet access |
| **Target devserver** | Node.js ≥ 16, `bpftool` (for live mode), root/sudo access |

---

## Step 1 — Build the Standalone Package

Run the build script from the project root on your laptop:

```bash
bash build-standalone.sh
```

The script performs six steps automatically:

1. Installs all npm dependencies (`pnpm install --frozen-lockfile`).
2. Builds the React frontend with Vite into `dist/public/`.
3. Creates no-op stubs for dev-only packages (`vite`, `@vitejs/plugin-react`, etc.) so they are never executed at runtime.
4. Bundles the Express/tRPC server and all its runtime dependencies into a single `dist/server.js` file using esbuild (ESM format with a `createRequire` compatibility shim for CommonJS modules).
5. Assembles a `standalone/` directory containing `server.js`, the built `public/` assets, a `start.sh` launcher, a `package.json`, and the preinstalled `undici` Node 16 polyfill dependency.
6. Packages everything into `ebpf-viz-standalone.tar.gz`.

---

## Step 2 — Copy the Tarball to the Devserver

```bash
scp ebpf-viz-standalone.tar.gz user@devserver:/opt/
```

---

## Step 3 — Extract and Configure

On the devserver:

```bash
cd /opt
tar -xzf ebpf-viz-standalone.tar.gz
cd standalone

# Copy the environment template and edit it
cp .env.example .env
nano .env          # or vi .env
```

The `.env` file supports the following variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | TCP port the HTTP server listens on |
| `NODE_ENV` | `production` | Must be `production` for standalone mode |
| `DEMO_MODE` | _(unset)_ | Set to `1` to use mock data instead of calling `bpftool` |
| `POLL_INTERVAL_MS` | `5000` | How often (ms) to poll `bpftool` for updates |
| `BPF_STATS_ENABLED` | _(auto)_ | Set to `0` to skip enabling BPF runtime stats |
| `ADMIN_TOKEN` | _(unset)_ | Optional token for remote access to config changes and bpftool-heavy endpoints; enter it in Settings → Admin Access |

---

## Step 4 — Start the Server

```bash
sudo ./start.sh
```

`sudo` is required because reading BPF program information via `bpftool` needs root privileges. The server will print:

```
Starting eBPF Viz on port 3000...
Open http://localhost:3000 in your browser.
Press Ctrl+C to stop.
```

Open `http://<devserver-ip>:3000` in your browser.

### Running Without Root (Demo Mode)

If you do not have root access or `bpftool` is not installed, run in demo mode to explore the UI with realistic mock data:

```bash
DEMO_MODE=1 ./start.sh
```

---

## Step 5 — Optional: Run as a systemd Service

Create `/etc/systemd/system/ebpf-viz.service`:

```ini
[Unit]
Description=eBPF Visualizer Dashboard
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/standalone
ExecStart=/usr/bin/node /opt/standalone/server.js
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production
Environment=PORT=3000
# Uncomment to enable demo mode:
# Environment=DEMO_MODE=1

[Install]
WantedBy=multi-user.target
```

Then enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable ebpf-viz
sudo systemctl start ebpf-viz
sudo systemctl status ebpf-viz
```

---

## Verifying the Deployment

After starting the server, you can verify each component:

```bash
# Frontend HTML
curl -s http://localhost:3000/ | head -3

# tRPC snapshot endpoint (returns live BPF program data)
curl -s "http://localhost:3000/api/trpc/ebpf.snapshot?input=%7B%7D" | python3 -m json.tool | head -20

# SSE stream (streams snapshot/maps/history events)
curl -N http://localhost:3000/api/sse
```

---

## Troubleshooting

**`bpftool: command not found`**

Install `bpftool` for your distribution, or run with `DEMO_MODE=1`.

| Distribution | Install command |
|---|---|
| Fedora / RHEL 9+ | `sudo dnf install bpftool` |
| Debian / Ubuntu | `sudo apt install linux-tools-common linux-tools-$(uname -r)` |
| Arch Linux | `sudo pacman -S bpf` |

**`Permission denied` reading BPF maps**

The server must run as root (or with `CAP_BPF + CAP_SYS_ADMIN`). Use `sudo ./start.sh`.

**Port already in use**

Change the port: `PORT=8080 sudo ./start.sh`

**Server exits immediately with a module error**

Ensure Node.js ≥ 16 is installed: `node --version`. The standalone package includes the Node 16 Web API polyfill dependencies needed by the tRPC server.

---

## Package Contents

```
standalone/
├── server.js       ← Bundled Express + tRPC server (all deps inlined, ~3.5 MB)
├── public/         ← Built React SPA (HTML + JS + CSS)
│   ├── index.html
│   └── assets/
├── start.sh        ← Launcher script (loads .env, sets defaults, runs node)
├── package.json    ← Minimal ESM marker
└── .env.example    ← Environment variable template
```

The tarball includes the minimal `node_modules/undici` dependency required for Node 16. The target server still does not need npm, pnpm, Docker, or internet access.

---

## Snapshot Workflow: Capture, Transfer, and Visualize

The snapshot workflow lets you capture a point-in-time view of BPF programs from a production server and visualize it on your local machine — without installing the full eBPF Visualizer on the production host.

### How It Works

The three data modes are:

| Mode | Description | When to Use |
|------|-------------|-------------|
| **Live** | Polls `bpftool` every 5 seconds via SSE | Running on the target devserver |
| **Demo** | Synthetic mock data (no `bpftool` needed) | Exploring the UI offline |
| **Snapshot** | Uploaded JSON file (ephemeral, in-memory) | Inspecting production data locally |

### Step 1 — Capture a Snapshot on the Production Server

Copy `scripts/capture-snapshot.sh` to the production server and run it as root:

```bash
# On the production server
sudo bash capture-snapshot.sh
```

The script requires only `bash` and `bpftool` — no `jq`, Python, or Node.js. It auto-discovers `bpftool` via the `BPFTOOL_PATH` environment variable, `which bpftool`, or common install paths (`/usr/sbin`, `/usr/bin`, `/sbin`).

The script outputs a file named `ebpf-snapshot-<hostname>-<YYYYMMDD-HHMMSS>.json` in the current directory and prints the `scp` command to transfer it:

```
Snapshot saved to: ebpf-snapshot-myserver-20260312-151100.json
To transfer: scp ebpf-snapshot-myserver-20260312-151100.json user@laptop:/tmp/
```

### Step 2 — Transfer the Snapshot to Your Local Machine

```bash
scp user@myserver:/path/to/ebpf-snapshot-myserver-20260312-151100.json ~/Downloads/
```

### Step 3 — Load the Snapshot in the UI

1. Open the eBPF Visualizer in your browser.
2. Click the **Load Snapshot** button (folder icon) in the top-right toolbar.
3. Select the `.json` file you downloaded.
4. The UI switches to **Snapshot mode** — a `SNAPSHOT` badge appears in the toolbar with the capture timestamp and hostname.

All views (Dashboard, Programs, Maps, OS Map, Cgroups) render the snapshot data identically to live mode. The snapshot is held in memory and is lost on page reload.

### Step 4 — Clear the Snapshot

Click the **×** button next to the `SNAPSHOT` badge in the toolbar, or the **×** button next to the filename in the sidebar, to return to Live or Demo mode.

### Snapshot File Format

The snapshot file is a JSON object with the following structure:

```json
{
  "_ebpfVizSnapshot": true,
  "capturedAt": "2026-03-12T15:11:00Z",
  "hostname": "myserver",
  "kernelVersion": "6.8.0-51-generic",
  "bpftoolVersion": "7.4.0",
  "raw": {
    "progs": [ ... ],
    "maps":  [ ... ],
    "net":   [ ... ],
    "cgroups": [ ... ]
  }
}
```

The `raw` field contains the unprocessed output of `bpftool prog list`, `bpftool map list`, `bpftool net list`, and `bpftool cgroup tree`. The server-side `parseSnapshot` procedure converts this into the full `EbpfSnapshot` model when the file is uploaded.

Snapshots exported via the **Download Topology JSON** button in the OS Map toolbar use the same `_ebpfVizSnapshot: true` marker and can be re-uploaded directly.

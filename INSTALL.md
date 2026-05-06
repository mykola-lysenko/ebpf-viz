# eBPF Visualizer — Installation Guide

A real-time dashboard for visualizing BPF programs running on a Linux system.
Polls `bpftool` every 5 seconds and renders kernel attachment zones, network
interfaces with OSI layers, cgroup hierarchies, an OS Map canvas, and a Code
Inspector with BPF bytecode and control-flow graphs.

**No database. No authentication. No external services required.**

---

## Option C — Standalone Package (no npm on target)

If your devserver has **only Node.js** (no npm, no Docker, no internet access), use the standalone build script to produce a self-contained tarball on your Mac and copy it over.

### Build on your Mac

```bash
# From the project root (requires Node.js ≥ 18 + pnpm or npm)
./build-standalone.sh
```

This produces `ebpf-viz-standalone.tar.gz` (~4–6 MB). The tarball contains:
- `public/` — pre-compiled frontend (HTML, JS, CSS)
- `server.js` — Express server **with all runtime dependencies bundled** (single file, no `node_modules` needed)
- `start.sh` — launch script that loads `.env` and starts the server
- `.env.example` — configuration template

### Deploy to the devserver

```bash
# Copy the tarball
scp ebpf-viz-standalone.tar.gz user@devserver:/opt/

# On the devserver
ssh user@devserver
cd /opt
tar -xzf ebpf-viz-standalone.tar.gz
cd standalone

# Configure (all settings are optional — see .env.example for details)
cp .env.example .env
vi .env

# Start (requires Node.js ≥ 18 only)
sudo ./start.sh          # sudo needed for bpftool access
```

Open `http://devserver:3000` in your browser.

**To run in the background:**
```bash
nohup sudo ./start.sh > ebpf-viz.log 2>&1 &
echo $! > ebpf-viz.pid
# To stop: sudo kill $(cat ebpf-viz.pid)
```

**Key `.env` settings for standalone:**

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | TCP port to listen on |
| `BPFTOOL_PATH` | auto-detected | Full path to the `bpftool` binary |
| `POLL_INTERVAL_MS` | `5000` | Poll interval in milliseconds |
| `DEMO_MODE` | `false` | Set `true` for synthetic data (no kernel required) |

No database, no OAuth, no API keys required.

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| Linux kernel | ≥ 5.1 | For `run_time_ns`/`run_cnt` stats; ≥ 4.15 for basic operation |
| Node.js | ≥ 22 | See install instructions below |
| pnpm | ≥ 10 | `npm install -g pnpm` |
| bpftool | ≥ 7.x | See build instructions below |
| sudo | any | The server calls `sudo bpftool`; configure sudoers accordingly |

---

## Option A — Docker (recommended)

The included `Dockerfile` builds bpftool from source and bundles everything
into a single image. The container must run with elevated privileges so
bpftool can access the BPF subsystem of the **host** kernel.

```bash
# Build
docker build -t ebpf-viz .

# Run (privileged, host network so kernel/cgroup data is the host's)
docker run --rm \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -p 3000:3000 \
  ebpf-viz
```

Open `http://localhost:3000` in your browser.

> **Minimal-privilege alternative:** replace `--privileged` with
> `--cap-add=SYS_ADMIN --cap-add=SYS_PTRACE`. Some kernels also require
> `--cap-add=BPF` (Linux ≥ 5.8).

---

## Option B — Bare-metal / systemd

### Step 1 — Install system build dependencies

#### Fedora / RHEL 9+ / CentOS Stream / Rocky / AlmaLinux

```bash
sudo dnf install -y \
  git gcc make \
  elfutils-libelf-devel \
  zlib-devel \
  libcap-devel \
  libzstd-devel \
  pkgconf-pkg-config \
  binutils-devel \
  kernel-devel
```

> **Fedora 38+ / RHEL 9+:** a pre-built bpftool package is available.
> Try `sudo dnf install -y bpftool` first. If `bpftool version` reports ≥ 7.x,
> skip Step 2. On Fedora the binary lands at `/usr/sbin/bpftool` — set
> `BPFTOOL_PATH=/usr/sbin/bpftool` in your `.env` accordingly.

#### Debian / Ubuntu

```bash
sudo apt-get install -y \
  git build-essential \
  libelf-dev \
  zlib1g-dev \
  libcap-dev \
  libzstd-dev \
  pkg-config \
  binutils-dev
```

#### Arch Linux

```bash
sudo pacman -S --needed \
  git base-devel \
  libelf \
  zlib \
  libcap \
  zstd \
  pkgconf \
  binutils
```

---

### Step 2 — Build bpftool from source

> Skip if you installed a pre-built bpftool in Step 1 and `bpftool version` ≥ 7.x.

```bash
git clone --depth=1 https://github.com/libbpf/bpftool.git
cd bpftool
git submodule update --init
cd src
make -j$(nproc)
sudo cp bpftool /usr/local/sbin/bpftool
sudo chmod 755 /usr/local/sbin/bpftool
cd ../..
```

Verify:

```bash
sudo bpftool prog list
```

You should see a list of running BPF programs (or an empty list — that is
normal; the visualizer will show demo data in that case).

---

### Step 3 — Install Node.js ≥ 22

#### Fedora / RHEL 9+

```bash
sudo dnf install -y nodejs npm
node --version   # should print v22.x.x or higher
```

> If your distro ships an older Node.js, use nvm instead (see below).

#### Using nvm (any distro — recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
source ~/.bashrc          # or ~/.zshrc / ~/.profile
nvm install 22
nvm use 22
node --version
```

---

### Step 4 — Install pnpm

```bash
npm install -g pnpm
pnpm --version   # should print 10.x.x or higher
```

---

### Step 5 — Clone and build the app

```bash
git clone https://github.com/mykola-lysenko/ebpf-viz.git
cd ebpf-viz
pnpm install
pnpm build          # produces dist/
```

---

### Step 6 — Configure sudoers

The server runs as a non-root user but needs to invoke bpftool as root.
Replace `youruser` with the OS user that will run the Node.js process:

```bash
sudo visudo -f /etc/sudoers.d/ebpf-viz
```

Add this line (adjust the path if bpftool is installed elsewhere):

```
youruser ALL=(ALL) NOPASSWD: /usr/local/sbin/bpftool
```

Verify it works:

```bash
sudo -u youruser sudo /usr/local/sbin/bpftool prog list
```

> **Fedora SELinux note:** if you see `Permission denied` even with the
> sudoers entry, check `sudo ausearch -m avc -ts recent`. You may need:
> ```bash
> sudo setenforce 0   # temporary — confirm it fixes the issue first
> # then create a proper policy module for production
> ```

---

### Step 7 — Configure the app

Copy the sample config:

```bash
cp config.sample .env
```

Edit `.env` — only these four variables are needed, all have sensible defaults:

```bash
PORT=3000                                   # HTTP listen port
BPFTOOL_PATH=/usr/local/sbin/bpftool        # path to bpftool binary
DEMO_MODE=false                             # set true to force mock data
POLL_INTERVAL_MS=5000                       # polling interval (ms)
```

No database URL, no auth tokens, no API keys.

---

### Step 8 — Run

```bash
NODE_ENV=production node dist/index.js
```

Or with pnpm:

```bash
pnpm start
```

Open `http://localhost:3000`.

---

### Step 9 — systemd service (optional)

Create `/etc/systemd/system/ebpf-viz.service` (replace `youruser` and the
working directory path):

```ini
[Unit]
Description=eBPF Visualizer
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/opt/ebpf-viz
EnvironmentFile=/opt/ebpf-viz/.env
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ebpf-viz
sudo journalctl -u ebpf-viz -f
```

---

### Step 10 — nginx reverse proxy (optional)

```nginx
server {
    listen 80;
    server_name ebpf.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

Add TLS: `sudo certbot --nginx -d ebpf.yourdomain.com`

---

## Configuration reference

All settings live in `.env` (or as environment variables before starting the
process). No database or auth configuration is required.

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP listen port |
| `BPFTOOL_PATH` | `/usr/local/sbin/bpftool` | Absolute path to bpftool binary |
| `DEMO_MODE` | `false` | Use rich mock data instead of live bpftool |
| `POLL_INTERVAL_MS` | `5000` | Polling interval in milliseconds (1000–60000) |

---

## Enabling runtime statistics

To see calls/sec, avg latency, and CPU% per program, enable BPF stats:

```bash
# Immediate (lost on reboot)
sudo sysctl -w kernel.bpf_stats_enabled=1

# Persistent across reboots
echo 'kernel.bpf_stats_enabled=1' | sudo tee /etc/sysctl.d/90-bpf-stats.conf
sudo sysctl -p /etc/sysctl.d/90-bpf-stats.conf
```

The visualizer auto-enables this sysctl at startup when it has permission.
Stats only accumulate **after** the sysctl is set — programs loaded before
that point will show zero until they are reloaded.

---

## Troubleshooting

**"Demo mode" shows instead of live data**

The poller fell back to mock data. Check the server log:

```bash
journalctl -u ebpf-viz -n 50
# or when running directly:
NODE_ENV=production node dist/index.js 2>&1 | head -30
```

Common causes: bpftool not found at `BPFTOOL_PATH`, sudo permission denied,
kernel too old (< 4.15).

**bpftool: Permission denied**

Verify the sudoers entry matches the user running the Node.js process:

```bash
sudo -u youruser sudo /usr/local/sbin/bpftool prog list
```

**Fedora: bpftool not found after `dnf install bpftool`**

The package installs to `/usr/sbin/bpftool`. Set this in `.env`:

```bash
BPFTOOL_PATH=/usr/sbin/bpftool
```

**No programs visible**

Your system may have no BPF programs loaded. Verify directly:

```bash
sudo bpftool prog list
```

If the list is empty, the visualizer will automatically show demo data.
Trigger some cgroup programs by restarting a systemd service:

```bash
sudo systemctl restart systemd-resolved
sudo bpftool prog list
```

**Fedora SELinux blocking bpftool**

```bash
sudo ausearch -m avc -ts recent | grep bpftool
sudo setenforce 0   # temporary test
# If that fixes it, build a custom policy module for production
```

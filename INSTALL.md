# eBPF Visualizer — Self-Hosting Guide

A real-time dashboard for visualizing BPF programs running on a Linux system.
Polls `bpftool` every 5 seconds and renders kernel attachment zones, network
interfaces with OSI layers, cgroup hierarchies, an OS Map canvas, and a Code
Inspector with BPF bytecode and control-flow graphs.

**No database. No authentication. No external services required.**

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| Linux kernel | ≥ 5.1 | For `run_time_ns`/`run_cnt` stats; ≥ 4.15 for basic operation |
| Node.js | ≥ 22 | Use [nvm](https://github.com/nvm-sh/nvm) |
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

### 1. Build bpftool from source

```bash
sudo apt-get install -y git build-essential libelf-dev zlib1g-dev \
  libcap-dev libzstd-dev pkg-config binutils-dev

git clone --depth=1 https://github.com/libbpf/bpftool.git
cd bpftool && git submodule update --init
cd src && make -j$(nproc)
sudo cp bpftool /usr/local/sbin/bpftool
sudo chmod 755 /usr/local/sbin/bpftool
```

Verify: `sudo bpftool prog list` should list running BPF programs.

### 2. Clone and build the app

```bash
git clone https://github.com/YOUR_USERNAME/ebpf-viz.git
cd ebpf-viz
pnpm install
pnpm build          # produces dist/
```

### 3. Configure sudoers

The server process runs as a non-root user but needs to call bpftool as root:

```bash
sudo visudo -f /etc/sudoers.d/ebpf-viz
```

Add (replace `www-data` with the user that will run the Node.js process):

```
www-data ALL=(ALL) NOPASSWD: /usr/local/sbin/bpftool
```

### 4. Configure the app

Copy the sample config and edit as needed:

```bash
cp config.sample .env
# Edit PORT, BPFTOOL_PATH, DEMO_MODE, POLL_INTERVAL_MS as required
```

### 5. Run

```bash
NODE_ENV=production node dist/index.js
```

Or with pnpm:

```bash
pnpm start
```

Open `http://localhost:3000`.

### 6. systemd service (optional)

```ini
# /etc/systemd/system/ebpf-viz.service
[Unit]
Description=eBPF Visualizer
After=network.target

[Service]
Type=simple
User=www-data
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

### 7. nginx reverse proxy (optional)

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

Add TLS: `certbot --nginx -d ebpf.yourdomain.com`

---

## Configuration reference

All settings can be placed in a `.env` file in the project root, or set as
environment variables before starting the process.

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP listen port |
| `BPFTOOL_PATH` | `/usr/local/sbin/bpftool` | Absolute path to bpftool binary |
| `DEMO_MODE` | `false` | Use rich mock data instead of live bpftool |
| `POLL_INTERVAL_MS` | `5000` | Polling interval in milliseconds (1000–60000) |

---

## Enabling runtime statistics

To see calls/sec, avg latency, and CPU% per program, enable BPF stats at boot:

```bash
# Immediate (lost on reboot)
sudo sysctl -w kernel.bpf_stats_enabled=1

# Persistent
echo 'kernel.bpf_stats_enabled=1' | sudo tee /etc/sysctl.d/90-bpf-stats.conf
sudo sysctl -p /etc/sysctl.d/90-bpf-stats.conf
```

The visualizer auto-enables this sysctl at startup if it has permission.
Stats only accumulate **after** the sysctl is set — programs loaded before
that point will show zero until they are reloaded.

---

## Troubleshooting

**"Demo mode" shows instead of live data**
The poller fell back to mock data. Check the server log for the reason:
```bash
journalctl -u ebpf-viz -n 50
```
Common causes: bpftool not found, sudo permission denied, kernel too old.

**bpftool permission denied**
Verify the sudoers entry is correct and the process user matches.

**No programs visible**
Your system may have no BPF programs loaded. Load one to test:
```bash
sudo bpftool prog load /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/filter /sys/fs/bpf/test_prog 2>/dev/null || true
sudo bpftool prog list
```

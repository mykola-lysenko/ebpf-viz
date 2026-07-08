# ebpf-viz Lab — local BPF playground

Reproduces realistic BPF workloads locally (WSL2-friendly, kernel ≥ 5.15) so
the dashboard has real programs, maps, links, and traffic to visualize.

## 1. XDP + TC veth playground

Builds real network programs and attaches them to a veth pair into a
`bpflab` network namespace:

- `xdp_lab_filter` (XDP, generic mode) — per-protocol packet counters in a
  `percpu_array`, **drops ICMP** (ping shows 100% loss by design)
- `tc_lab_count` → `tc_lab_verdict` — a two-classifier TC **ingress chain**
  (`TC_ACT_UNSPEC` continue → `TC_ACT_OK` verdict) demonstrating chain
  ordering and short-circuit analysis
- `tc_lab_egress` — egress byte/packet counter

```bash
./build.sh                 # compile (clang, no libbpf-dev needed)
sudo ./setup.sh            # create netns/veth, load + attach everything
sudo ./traffic.sh          # curl + UDP + ping loop through the pair (Ctrl-C to stop)
sudo ./setup.sh --teardown # remove netns, veth, pinned programs
```

If your bpftool is not at `~/.local/bin/bpftool`, pass `BPFTOOL_PATH=... sudo -E ./setup.sh`.

What to look for in the dashboard: XDP zone + Network view for `veth-host`,
TC chain order with both classifiers, `xdp_lab_stats` / `tc_lab_stats` map
entry dumps (interpret values as U64), call-rate sparklines while traffic runs.

## 2. Tracing zoo (bpftrace one-liners)

Each loads real kprobe/uprobe/tracepoint programs attached via **perf_event
links** with ring-buffer/percpu maps. Run each in its own terminal, watch the
Programs view populate; Ctrl-C unloads.

```bash
# kprobe + kretprobe pair: file-open latency
sudo bpftrace -e 'kprobe:do_sys_openat2 { @start[tid] = nsecs; }
  kretprobe:do_sys_openat2 /@start[tid]/ { @us = hist((nsecs - @start[tid]) / 1000); delete(@start[tid]); }'

# tracepoint: context switches per process
sudo bpftrace -e 'tracepoint:sched:sched_switch { @[args->next_comm] = count(); }'

# uprobe on libc malloc (exercises the uprobe link refinement)
sudo bpftrace -e 'uprobe:/usr/lib/x86_64-linux-gnu/libc.so.6:malloc { @allocs[comm] = count(); }'

# profile timer (perf_event program)
sudo bpftrace -e 'profile:hz:99 { @stacks[kstack] = count(); }'
```

## 3. Tetragon (real Cilium-family sensors)

Requires Docker Desktop WSL integration enabled for this distro
(Docker Desktop → Settings → Resources → WSL integration). Runs standalone —
no Kubernetes needed — and loads the production Tetragon sensor programs
(kprobes via links, ringbuf event maps, process-exec tracking):

```bash
# NOTE: tetragon publishes versioned tags only — ":latest" does not exist.
# Mounting the host /sys/fs/bpf matters: bpffs instances are per-mount, so
# without it tetragon pins into a container-private bpffs and the pin paths
# are invisible to host-side bpftool (and to the dashboard).
docker run --name tetragon -d --pull always \
  --pid=host --cgroupns=host --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
  quay.io/cilium/tetragon:v1.7.0

docker exec tetragon tetra getevents -o compact   # live event feed
docker rm -f tetragon                             # cleanup
```

## 4. Cilium in kind (Phase 2)

Runs the real Cilium datapath in a two-node kind cluster. Because all kind
nodes are containers on the shared WSL kernel, every Cilium BPF program, map,
and link is visible to the host dashboard. Requires Docker + `kind`,
`kubectl`, `cilium` CLIs in `~/.local/bin` (no sudo).

```bash
cd kind
./setup.sh              # cluster + cilium + nginx/curl demo traffic
./setup.sh --teardown   # delete the cluster
```

What to look for: dozens of `cil_*` sched_cls/tcx programs (per-endpoint
datapath), `cgroup_sock_addr` connect/bind hooks from socket-LB in the
Cgroups view, lpm_trie policy maps and `cilium_*` maps in the Maps view.
Caveats: pod-veth attachments live in node netns, so the Network view won't
place them on NICs; Cilium pins into each node container's private bpffs, so
pin paths won't show (see the Tetragon note above for why).

## 5. netkit (Phase 3 — custom WSL kernel)

netkit is a compile-time kernel feature (`CONFIG_NETKIT=y`, bool — no module
possible) that stock WSL2 kernels ship disabled. To use it, rebuild the
matching Microsoft kernel with netkit (+ `CONFIG_FPROBE` for kprobe_multi):

```bash
# dwarves (pahole) MUST be installed BEFORE the config step — Kconfig probes
# for it and silently drops CONFIG_DEBUG_INFO_BTF (no BTF → no bpftrace, no
# fentry, no CO-RE) when it's missing at `make olddefconfig` time.
sudo apt-get install -y dwarves
git clone --depth 1 --branch linux-msft-wsl-$(uname -r | cut -d- -f1) \
  https://github.com/microsoft/WSL2-Linux-Kernel.git
cd WSL2-Linux-Kernel
cp Microsoft/config-wsl .config
./scripts/config --enable NETKIT --enable FPROBE
make olddefconfig
# The stock config builds ~1000 options as modules (incl. the netfilter/
# conntrack stack Docker needs), shipped in Microsoft's modules.vhd — which
# refuses to load into a rebuilt kernel. Fold them into the image instead:
make mod2yesconfig
make -j$(nproc)
cp arch/x86/boot/bzImage /mnt/c/Users/<you>/wsl-kernel-netkit
```

Sanity-check the config before building: `grep -E "DEBUG_INFO_BTF=|NETKIT=|PAHOLE_VERSION" .config`
should show both `=y` and a non-zero pahole version.

Then in `C:\Users\<you>\.wslconfig`:

```ini
[wsl2]
kernel=C:\\Users\\<you>\\wsl-kernel-netkit
```

`wsl --shutdown` from Windows, reopen, verify with
`zcat /proc/config.gz | grep NETKIT`. Revert anytime by removing the
`kernel=` line. Finally:

```bash
cd kind && ./setup.sh --teardown && ./setup.sh --netkit
```

Pods now get netkit devices instead of veth — the dashboard shows netkit
links and the `bpftool net` netkit section.

## Known stock-WSL2-kernel limits

- **netkit** needs kernel ≥ 6.7 (+ Cilium ≥ 1.16 netkit mode or iproute2 ≥ 6.7) — requires a custom WSL2 kernel; see the phased plan.
- **kprobe_multi** links need `CONFIG_FPROBE`, which the stock WSL2 kernel disables; bpftrace falls back to perf kprobes.
- `bpftool net` is netns-scoped: programs attached inside other namespaces show up in the Programs view but without NIC placement.

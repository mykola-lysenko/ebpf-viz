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
# NOTE: tetragon publishes versioned tags only — ":latest" does not exist
docker run --name tetragon -d --pull always \
  --pid=host --cgroupns=host --privileged \
  -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
  quay.io/cilium/tetragon:v1.7.0

docker exec tetragon tetra getevents -o compact   # live event feed
docker rm -f tetragon                             # cleanup
```

## Known WSL2 (kernel 6.6) limits

- **netkit** needs kernel ≥ 6.7 (+ Cilium ≥ 1.16 netkit mode or iproute2 ≥ 6.7) — requires a custom WSL2 kernel; see the phased plan.
- **kprobe_multi** links need `CONFIG_FPROBE`, which the stock WSL2 kernel disables; bpftrace falls back to perf kprobes.
- `bpftool net` is netns-scoped: programs attached inside other namespaces show up in the Programs view but without NIC placement.

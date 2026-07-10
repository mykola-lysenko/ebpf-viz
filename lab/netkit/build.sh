#!/usr/bin/env bash
# Build the netkit lab: the sched_cls BPF object and the Go netkit loader.
# No libbpf-dev needed for the BPF object (same self-contained headers as the
# rest of lab/bpf). The loader needs a Go toolchain (uses cilium/ebpf +
# vishvananda/netlink — the same libraries Cilium's own agent uses).
set -euo pipefail
cd "$(dirname "$0")"

ARCH=$(uname -m)
echo "==> Compiling BPF object (clang -target bpf)..."
clang -O2 -g -Wall -target bpf \
  -I"/usr/include/${ARCH}-linux-gnu" \
  -c bpf/netkit_lab.bpf.c -o netkit_lab.bpf.o
echo "    netkit_lab.bpf.o"

echo "==> Building the netkit loader (go build)..."
( cd loader && go build -o ../netkitctl . )
echo "    netkitctl"

echo "Done. Now run: sudo ./setup.sh"

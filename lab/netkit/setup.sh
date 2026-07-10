#!/usr/bin/env bash
# Netkit lab — reproduce Cilium's netkit datapath with no Kubernetes and no
# Cilium: named network namespaces wired by real netkit device pairs, each
# carrying a sched_cls BPF program attached via a netkit link.
#
#   netns "nklab-node"  (the "node")          named netns, host-reachable
#   ┌───────────────────────────────┐
#   │ nk-pod1  10.244.1.1/24  ══netkit══╗
#   │   primary: nk_to_pod             ║   netns "nklab-pod1"
#   │                                  ╚═ eth0 10.244.1.2/24  peer: nk_from_pod
#   │ nk-pod2  10.244.2.1/24  ══netkit══╗
#   │   primary: nk_to_pod             ║   netns "nklab-pod2"
#   │                                  ╚═ eth0 10.244.2.2/24  peer: nk_from_pod
#   │ ip_forward=1  → pods route to each other through the node
#   └───────────────────────────────┘
#
# Because these are NAMED namespaces (/var/run/netns), the dashboard reaches
# them via nsenter — the Topology view shows node ↔ pod netkit edges with the
# programs on them, fully attributed (no docker bridge, no ifindex ambiguity).
#
# Run as root. `--teardown` removes everything.
set -euo pipefail
cd "$(dirname "$0")"

NODE_NS=nklab-node
PODS=(pod1 pod2 pod3)
PIN_DIR=/sys/fs/bpf/nklab

teardown() {
  echo "Tearing down netkit lab..."
  for p in "${PODS[@]}"; do ip netns del "nklab-$p" 2>/dev/null || true; done
  ip netns del "$NODE_NS" 2>/dev/null || true
  rm -rf "$PIN_DIR" 2>/dev/null || true
  echo "Done."
}

if [[ "${1:-}" == "--teardown" ]]; then
  teardown
  exit 0
fi

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0 $*" >&2
  exit 1
fi

if [[ ! -f netkit_lab.bpf.o || ! -x netkitctl ]]; then
  echo "Build first: ./build.sh" >&2
  exit 1
fi

# Fresh start.
teardown >/dev/null 2>&1 || true
mount | grep -q '/sys/fs/bpf ' || mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

echo "==> Creating namespaces (node + ${#PODS[@]} pods)..."
ip netns add "$NODE_NS"
POD_ARGS=()
for p in "${PODS[@]}"; do
  ip netns add "nklab-$p"
  POD_ARGS+=(-pod "$p=/var/run/netns/nklab-$p")
done

echo "==> Creating netkit pairs + attaching sched_cls via netkit links..."
# The loader runs in the host mount namespace (NOT `ip netns exec`, which
# remounts /sys and would hide the bpffs the links pin into) and switches only
# the network namespace internally. It creates each netkit pair (primary in the
# node, peer in the pod), addresses both ends, and attaches + pins the programs.
./netkitctl \
  -obj "$PWD/netkit_lab.bpf.o" -pin "$PIN_DIR" \
  -node "/var/run/netns/$NODE_NS" "${POD_ARGS[@]}"

echo "==> Enabling forwarding in the node so pods can reach each other..."
ip netns exec "$NODE_NS" sysctl -q -w net.ipv4.ip_forward=1

echo
echo "netkit lab is up. Namespaces:"
ip netns list | sed 's/^/  /'
echo
echo "Pinned netkit links:"
ls -1 "$PIN_DIR" 2>/dev/null | sed 's/^/  /' || true
echo
echo "Generate traffic (pod1 -> pod2), in another terminal:"
echo "  sudo ip netns exec nklab-pod1 ping -c100 10.244.2.2"
echo
echo "Then open the dashboard's Topology view: nklab-node connected to each"
echo "nklab-pod by a netkit edge, nk_to_pod / nk_from_pod on the sides."
echo "Teardown: sudo $0 --teardown"

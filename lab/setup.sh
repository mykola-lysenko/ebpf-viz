#!/usr/bin/env bash
# Create the ebpf-viz lab: a veth pair into a network namespace with
# XDP + TC BPF programs attached. Run as root. `--teardown` removes it all.
#
#   host                          netns "bpflab"
#   ┌─────────────────┐           ┌──────────────────┐
#   │ veth-host       │ <-------> │ veth-lab         │
#   │  10.99.0.1/24   │           │  10.99.0.2/24    │
#   │  xdpgeneric: xdp_lab_filter (drops ICMP)       │
#   │  tc ingress: tc_lab_count -> tc_lab_verdict    │
#   │  tc egress:  tc_lab_egress                     │
#   └─────────────────┘           └──────────────────┘
set -euo pipefail
cd "$(dirname "$0")"

NS=bpflab
VETH_HOST=veth-host
VETH_LAB=veth-lab
HOST_IP=10.99.0.1
LAB_IP=10.99.0.2
PIN_DIR=/sys/fs/bpf/ebpfviz-lab
# Under sudo $HOME is /root — resolve the invoking user's home for the
# default ~/.local/bin/bpftool location.
USER_HOME=$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)
BPFTOOL="${BPFTOOL_PATH:-$USER_HOME/.local/bin/bpftool}"
[[ -x "$BPFTOOL" ]] || BPFTOOL=$(command -v bpftool || echo "$BPFTOOL")

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo BPFTOOL_PATH=... $0 $*" >&2
  exit 1
fi

teardown() {
  echo "Tearing down lab..."
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$VETH_HOST" 2>/dev/null || true
  rm -rf "$PIN_DIR" 2>/dev/null || true
  echo "Done."
}

if [[ "${1:-}" == "--teardown" ]]; then
  teardown
  exit 0
fi

[[ -f build/xdp_lab.bpf.o ]] || { echo "Run ./build.sh first" >&2; exit 1; }
[[ -x "$BPFTOOL" ]] || { echo "bpftool not found at $BPFTOOL (set BPFTOOL_PATH)" >&2; exit 1; }

# Clean slate if a previous lab exists
teardown >/dev/null 2>&1 || true

echo "Creating netns + veth pair..."
ip netns add "$NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_LAB"
ip link set "$VETH_LAB" netns "$NS"
ip addr add "$HOST_IP/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up
ip netns exec "$NS" ip addr add "$LAB_IP/24" dev "$VETH_LAB"
ip netns exec "$NS" ip link set "$VETH_LAB" up
ip netns exec "$NS" ip link set lo up

echo "Loading + pinning BPF programs..."
mkdir -p "$PIN_DIR"
"$BPFTOOL" prog load build/xdp_lab.bpf.o "$PIN_DIR/xdp_lab_filter"
"$BPFTOOL" prog loadall build/tc_lab.bpf.o "$PIN_DIR/tc" type classifier

echo "Attaching XDP (generic mode) to $VETH_HOST..."
"$BPFTOOL" net attach xdpgeneric pinned "$PIN_DIR/xdp_lab_filter" dev "$VETH_HOST"

echo "Attaching TC chain to $VETH_HOST..."
tc qdisc add dev "$VETH_HOST" clsact
tc filter add dev "$VETH_HOST" ingress pref 10 bpf da object-pinned "$PIN_DIR/tc/tc_lab_count"
tc filter add dev "$VETH_HOST" ingress pref 20 bpf da object-pinned "$PIN_DIR/tc/tc_lab_verdict"
tc filter add dev "$VETH_HOST" egress  pref 10 bpf da object-pinned "$PIN_DIR/tc/tc_lab_egress"

echo
echo "Lab is up. Programs:"
"$BPFTOOL" prog show | grep -A1 -E "xdp_lab|tc_lab" || true
echo
echo "Generate traffic with:  sudo ./traffic.sh"
echo "Tear down with:         sudo $0 --teardown"

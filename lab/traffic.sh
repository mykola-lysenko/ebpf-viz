#!/usr/bin/env bash
# Generate traffic through the lab veth pair so the dashboard shows live
# call rates and map counters. Run as root. Ctrl-C to stop.
set -euo pipefail

NS=bpflab
HOST_IP=10.99.0.1
LAB_IP=10.99.0.2
PORT=8099

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

ip netns list | grep -q "^$NS" || { echo "Lab not set up — run sudo ./setup.sh first" >&2; exit 1; }

echo "Starting HTTP server on $HOST_IP:$PORT (host side)..."
python3 -m http.server "$PORT" --bind "$HOST_IP" >/dev/null 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 0.5

echo "Traffic loop from netns $NS: TCP curl (passes) + ICMP ping (dropped by XDP)."
echo "Watch the dashboard: xdp_lab_filter / tc_lab_* sparklines and map entries."
echo

while true; do
  # TCP — passes XDP, traverses the TC ingress chain on veth-host
  ip netns exec "$NS" curl -s -o /dev/null --max-time 2 "http://$HOST_IP:$PORT/" || true
  # UDP — a small datagram via /dev/udp
  ip netns exec "$NS" bash -c "echo lab > /dev/udp/$HOST_IP/9" 2>/dev/null || true
  # ICMP — visibly dropped by xdp_lab_filter (100% loss is expected!)
  ip netns exec "$NS" ping -c 1 -W 1 "$HOST_IP" >/dev/null 2>&1 || true
  sleep 0.3
done

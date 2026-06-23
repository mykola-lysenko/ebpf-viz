#!/usr/bin/env bash
# Compatibility wrapper with clearer naming for the L3/cgroup networking collector.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARGS=("$@")
HAS_OUTPUT=0
HAS_REMOTE_ARCHIVE=0

for arg in "${ARGS[@]}"; do
  case "$arg" in
    --output)
      HAS_OUTPUT=1
      ;;
    --remote-archive)
      HAS_REMOTE_ARCHIVE=1
      ;;
  esac
done

DEFAULT_ARGS=()
if [ "$HAS_OUTPUT" -eq 0 ]; then
  DEFAULT_ARGS+=(--output "$ROOT_DIR/ebpf-viz-network-latest.tar.gz")
fi
if [ "$HAS_REMOTE_ARCHIVE" -eq 0 ]; then
  DEFAULT_ARGS+=(--remote-archive "/tmp/ebpf-viz-network-latest.tar.gz")
fi

exec "$ROOT_DIR/scripts/devvm-collect-l3-bpf.sh" "${DEFAULT_ARGS[@]}" "$@"

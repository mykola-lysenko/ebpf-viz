#!/usr/bin/env bash
# Reproduce the audit in a disposable UML guest, without host networking changes.
set -euo pipefail
script_dir=$(cd "$(dirname "$0")" && pwd)
uml_bin=${UML_BIN:-$HOME/.local/share/uml-veristat/linux}
bpftool_bin=${BPFTOOL_PATH:-$(command -v bpftool)}
audit_out=$(realpath -m "${1:-$script_dir/build/run}")
mkdir -p "$audit_out"
(
  cd "$script_dir/loader"
  GOCACHE=${GOCACHE:-/tmp/ebpf-viz-tcx-go-cache} go build -o "$audit_out/audit" .
)
{
  printf '#!/bin/bash\nexport PATH=/usr/sbin:/usr/bin:/sbin:/bin\n'
  printf 'mount -t proc proc /proc\nmount -t sysfs sysfs /sys\nmount -t devtmpfs devtmpfs /dev\nmount -t tmpfs tmpfs /run\nmount -t bpf bpf /sys/fs/bpf\n'
  printf '%q ' "$audit_out/audit" -out "$audit_out" -bpftool "$bpftool_bin"
  printf '> %q 2>&1\n' "$audit_out/audit.log"
  printf 'rc=$?\nprintf "%%s\\n" "$rc" > %q\nsync\nhalt -f\n' "$audit_out/result"
} > "$audit_out/init"
chmod +x "$audit_out/init"
# A fresh result is required even if this output directory was used before.
: > "$audit_out/result"
timeout --kill-after=10 120 "$uml_bin" mem=512M rootfstype=hostfs hostfs=/ rw \
  "init=$audit_out/init" quiet con=null con0=null > "$audit_out/boot.log" 2>&1 || {
  cat "$audit_out/boot.log"; exit 1;
}
cat "$audit_out/audit.log"
[[ $(cat "$audit_out/result") == 0 ]]

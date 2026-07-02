#!/usr/bin/env bash
# Compile the lab BPF programs. Requires: clang (with bpf target), linux-libc-dev.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p build
# -target bpf drops the arch-specific include path; add it back for asm/types.h
ARCH_INC="/usr/include/$(uname -m)-linux-gnu"
for src in bpf/*.bpf.c; do
  out="build/$(basename "${src%.c}").o"
  echo "  CLANG $src -> $out"
  clang -O2 -g -Wall -target bpf -I"$ARCH_INC" -c "$src" -o "$out"
done
echo "Done. Objects in lab/build/"

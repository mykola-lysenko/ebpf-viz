/* Minimal self-contained helpers for the lab BPF programs.
 * Deliberately avoids a libbpf-dev / bpf_helpers.h dependency — only
 * linux-libc-dev headers are needed. Compile with: clang -O2 -g -target bpf */
#pragma once

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))

/* linux/stddef.h defines a weaker variant; force the strong one */
#ifdef __always_inline
#undef __always_inline
#endif
#define __always_inline inline __attribute__((always_inline))

/* BTF-style map definition macros (same shape bpf_helpers.h provides) */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* Helper function stubs resolved by the verifier via their helper IDs */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
  (void *) BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) =
  (void *) BPF_FUNC_map_update_elem;

/* x86/arm64 are little-endian; constant network-order conversion */
#define htons_const(x) ((__u16)__builtin_bswap16(x))

char _license[] SEC("license") = "GPL";

/* XDP program for the ebpf-viz lab veth pair.
 * Counts packets per protocol in a per-CPU array and drops ICMP —
 * so `ping` through the pair visibly fails while TCP/UDP pass,
 * demonstrating XDP verdicts, live map entries, and call-rate sparklines. */
#include "lab_common.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

enum {
  IDX_TOTAL = 0,
  IDX_TCP = 1,
  IDX_UDP = 2,
  IDX_ICMP_DROPPED = 3,
  IDX_OTHER = 4,
  IDX_MAX = 5,
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, IDX_MAX);
  __type(key, __u32);
  __type(value, __u64);
} xdp_lab_stats SEC(".maps");

static __always_inline void bump(__u32 idx)
{
  __u64 *v = bpf_map_lookup_elem(&xdp_lab_stats, &idx);
  if (v)
    *v += 1;
}

SEC("xdp")
int xdp_lab_filter(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  bump(IDX_TOTAL);

  if (eth->h_proto != htons_const(ETH_P_IP)) {
    bump(IDX_OTHER);
    return XDP_PASS;
  }

  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end)
    return XDP_PASS;

  if (ip->protocol == IPPROTO_ICMP) {
    bump(IDX_ICMP_DROPPED);
    return XDP_DROP;
  }
  if (ip->protocol == IPPROTO_TCP)
    bump(IDX_TCP);
  else if (ip->protocol == IPPROTO_UDP)
    bump(IDX_UDP);
  else
    bump(IDX_OTHER);

  return XDP_PASS;
}

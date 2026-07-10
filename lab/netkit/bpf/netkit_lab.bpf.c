/* sched_cls programs for the netkit lab, attached via netkit links.
 *
 * netkit is the datapath device Cilium uses (bpf.datapathMode=netkit): a pair
 * whose "primary" lives in the node netns and whose "peer" lives in the pod.
 * These two programs mirror Cilium's cil_from_container / cil_to_container:
 *   nk_from_pod  — attached to the PEER  (pod side): packets leaving the pod
 *   nk_to_pod    — attached to the PRIMARY (node side): packets entering the pod
 * Both just count and return NETKIT_PASS so connectivity is unaffected.
 *
 * Compile with: clang -O2 -g -target bpf (see build.sh). No libbpf-dev needed.
 */
#include "../../bpf/lab_common.h"
#include <linux/if_link.h>

enum {
  SLOT_FROM_POD_PKTS = 0,
  SLOT_FROM_POD_BYTES = 1,
  SLOT_TO_POD_PKTS = 2,
  SLOT_TO_POD_BYTES = 3,
  SLOT_MAX = 4,
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, SLOT_MAX);
  __type(key, __u32);
  __type(value, __u64);
} netkit_lab_stats SEC(".maps");

static __always_inline void bump(__u32 slot, __u64 amount)
{
  __u64 *v = bpf_map_lookup_elem(&netkit_lab_stats, &slot);
  if (v)
    *v += amount;
}

/* Peer side (pod): every packet the pod sends. The "netkit/peer" section sets
 * the SCHED_CLS type + BPF_NETKIT_PEER expected attach type. */
SEC("netkit/peer")
int nk_from_pod(struct __sk_buff *skb)
{
  bump(SLOT_FROM_POD_PKTS, 1);
  bump(SLOT_FROM_POD_BYTES, skb->len);
  return NETKIT_PASS;
}

/* Primary side (node): every packet delivered toward the pod. */
SEC("netkit/primary")
int nk_to_pod(struct __sk_buff *skb)
{
  bump(SLOT_TO_POD_PKTS, 1);
  bump(SLOT_TO_POD_BYTES, skb->len);
  return NETKIT_PASS;
}

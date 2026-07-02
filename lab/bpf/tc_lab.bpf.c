/* TC programs for the ebpf-viz lab veth pair.
 * Two ingress classifiers demonstrate chain ordering:
 *   pref 10: tc_lab_count   — counts, returns TC_ACT_UNSPEC (continue chain)
 *   pref 20: tc_lab_verdict — counts, returns TC_ACT_OK (terminal verdict)
 * plus one egress counter. */
#include "lab_common.h"
#include <linux/pkt_cls.h>

enum {
  SLOT_INGRESS_SEEN = 0,
  SLOT_INGRESS_BYTES = 1,
  SLOT_VERDICT_OK = 2,
  SLOT_EGRESS_SEEN = 3,
  SLOT_EGRESS_BYTES = 4,
  SLOT_MAX = 5,
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, SLOT_MAX);
  __type(key, __u32);
  __type(value, __u64);
} tc_lab_stats SEC(".maps");

static __always_inline void add(__u32 slot, __u64 amount)
{
  __u64 *v = bpf_map_lookup_elem(&tc_lab_stats, &slot);
  if (v)
    *v += amount;
}

SEC("tc/count")
int tc_lab_count(struct __sk_buff *skb)
{
  add(SLOT_INGRESS_SEEN, 1);
  add(SLOT_INGRESS_BYTES, skb->len);
  return TC_ACT_UNSPEC; /* continue to the next classifier in the chain */
}

SEC("tc/verdict")
int tc_lab_verdict(struct __sk_buff *skb)
{
  add(SLOT_VERDICT_OK, 1);
  return TC_ACT_OK; /* terminal verdict — accept */
}

SEC("tc/egress")
int tc_lab_egress(struct __sk_buff *skb)
{
  add(SLOT_EGRESS_SEEN, 1);
  add(SLOT_EGRESS_BYTES, skb->len);
  return TC_ACT_OK;
}

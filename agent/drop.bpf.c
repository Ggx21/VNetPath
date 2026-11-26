#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "drop.h"

/* CO-RE resolves member offsets and enum values against the running kernel. */
struct net___drop { struct { unsigned int inum; } ns; };
struct net_device___drop {
    int ifindex;
    char name[16];
    struct { struct net___drop *net; } nd_net;
};
struct sk_buff___drop {
    struct net_device___drop *dev;
    char cb[48];
    int skb_iif;
    __be16 protocol;
    unsigned char *head;
    unsigned int tail, end;
    __u16 network_header;
};
struct skb_shared_info___drop { unsigned short gso_size; };
enum skb_drop_reason___drop { SKB_DROP_REASON_TC_INGRESS, SKB_DROP_REASON_NETFILTER_DROP };
enum ovs_drop_reason___drop { OVS_DROP_EXPLICIT, OVS_DROP_EXPLICIT_WITH_ERROR, OVS_DROP_LAST_ACTION };
struct vport___drop { struct net_device___drop *dev; };
struct ovs_skb_cb___drop { struct vport___drop *input_vport; __u16 acts_origlen; };

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct drop_scope);
} scope SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} probe_ids SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} drops SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lost SEC(".maps");

static __always_inline int drop_site(__u32 reason)
{
    if (bpf_core_enum_value_exists(enum skb_drop_reason___drop, SKB_DROP_REASON_TC_INGRESS) &&
        reason == bpf_core_enum_value(enum skb_drop_reason___drop, SKB_DROP_REASON_TC_INGRESS))
        return DROP_TC_INGRESS;
    if (bpf_core_enum_value_exists(enum skb_drop_reason___drop, SKB_DROP_REASON_NETFILTER_DROP) &&
        reason == bpf_core_enum_value(enum skb_drop_reason___drop, SKB_DROP_REASON_NETFILTER_DROP))
        return DROP_NETFILTER;
    if (bpf_core_enum_value_exists(enum ovs_drop_reason___drop, OVS_DROP_EXPLICIT) &&
        reason == bpf_core_enum_value(enum ovs_drop_reason___drop, OVS_DROP_EXPLICIT))
        return DROP_OVS_EXPLICIT;
    if (bpf_core_enum_value_exists(enum ovs_drop_reason___drop, OVS_DROP_EXPLICIT_WITH_ERROR) &&
        reason == bpf_core_enum_value(enum ovs_drop_reason___drop, OVS_DROP_EXPLICIT_WITH_ERROR))
        return DROP_OVS_EXPLICIT_ERROR;
    if (bpf_core_enum_value_exists(enum ovs_drop_reason___drop, OVS_DROP_LAST_ACTION) &&
        reason == bpf_core_enum_value(enum ovs_drop_reason___drop, OVS_DROP_LAST_ACTION))
        return DROP_OVS_EMPTY_ACTIONS;
    return 0;
}

static __always_inline struct net_device___drop *ingress_device(struct sk_buff___drop *skb, int site,
                                                                 __u32 expected_ifindex)
{
    if (site == DROP_TC_INGRESS || site == DROP_NETFILTER) {
        if (BPF_CORE_READ(skb, skb_iif) != expected_ifindex)
            return 0;
        return BPF_CORE_READ(skb, dev);
    }
    /* Only the OVS subsystem reasons above make its private skb->cb valid. */
    struct ovs_skb_cb___drop *cb = (void *)skb + bpf_core_field_offset(skb->cb);
    if (site == DROP_OVS_EMPTY_ACTIONS) {
        __u16 length;
        /* A nonempty action list can output a clone then free the original.
         * A bare LAST_ACTION reason alone cannot identify flow loss. */
        if (BPF_CORE_READ_INTO(&length, cb, acts_origlen) || length)
            return 0;
    }
    return BPF_CORE_READ(cb, input_vport, dev);
}

SEC("raw_tp/kfree_skb")
int trace_vnetpath_drop(struct bpf_raw_tracepoint_args *ctx)
{
    int site = drop_site(ctx->args[2]);
    if (!site)
        return 0;
    __u32 zero = 0;
    struct drop_scope *selected = bpf_map_lookup_elem(&scope, &zero);
    struct sk_buff___drop *skb = (void *)ctx->args[0];
    if (!selected || !selected->ifindex || BPF_CORE_READ(skb, protocol) != bpf_htons(ETH_P_IP))
        return 0;
    struct net_device___drop *dev = ingress_device(skb, site, selected->ifindex);
    if (!dev || BPF_CORE_READ(dev, ifindex) != selected->ifindex ||
        BPF_CORE_READ(dev, nd_net.net, ns.inum) != selected->netns)
        return 0;

    /* On 64-bit kernels tail/end are offsets from head. Never inspect bytes
     * beyond the linear data, fragments or aggregated packets. */
    if (bpf_core_field_size(skb->tail) != 4 || bpf_core_field_size(skb->end) != 4)
        return 0;
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u32 tail = BPF_CORE_READ(skb, tail), end = BPF_CORE_READ(skb, end);
    __u16 offset;
    if (!head || BPF_CORE_READ_INTO(&offset, skb, network_header) ||
        tail > end || (__u32)offset + 20 > tail)
        return 0;
    struct skb_shared_info___drop *shared = (void *)(head + end);
    __u16 gso;
    if (BPF_CORE_READ_INTO(&gso, shared, gso_size) || gso)
        return 0;
    __u8 ip[60] = {};
    if (bpf_probe_read_kernel(ip, 1, head + offset))
        return 0;
    __u32 len = (ip[0] & 15) * 4;
    if (len < 20 + VNETPATH_OPTION_LENGTH || len > sizeof(ip) || offset + len > tail ||
        bpf_probe_read_kernel(ip, len, head + offset))
        return 0;
    struct drop_event event = {};
    if (!decode_dropped_probe(ip, len, &event) || !bpf_map_lookup_elem(&probe_ids, &event.probe))
        return 0;
    if (bpf_core_read_str(event.ifname, sizeof(event.ifname), &dev->name) <= 1)
        return 0;
    event.tai_ns = bpf_ktime_get_tai_ns();
    event.site = site;
    if (bpf_ringbuf_output(&drops, &event, sizeof(event), 0)) {
        __u64 *n = bpf_map_lookup_elem(&lost, &zero);
        if (n)
            __sync_fetch_and_add(n, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

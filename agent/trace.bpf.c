#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include "trace.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct capture_stats);
} stats SEC(".maps");

static __always_inline __u16 read_be16(const __u8 *p)
{
    return ((__u16)p[0] << 8) | p[1];
}

/* IPv4 datagram in an Ethernet frame, optionally with up to two VLAN tags. */
static __always_inline int ipv4_offset(struct __sk_buff *skb, __u8 eth[14])
{
    if (bpf_skb_load_bytes(skb, 0, eth, ETH_HLEN))
        return -1;
    __u16 type = read_be16(eth + 12);
    int offset = ETH_HLEN;
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (type != ETH_P_8021Q && type != ETH_P_8021AD)
            break;
        __u8 tag[4];
        if (bpf_skb_load_bytes(skb, offset, tag, sizeof(tag)))
            return -1;
        type = read_be16(tag + 2);
        offset += sizeof(tag);
    }
    return type == ETH_P_IP ? offset : -1;
}

static __always_inline int find_mark(const __u8 ip[60], __u32 header_len)
{
    __u32 pos = 20;
#pragma clang loop unroll(disable)
    for (int i = 0; i < 40; i++) {
        if (pos >= header_len || pos >= 60 || ip[pos] == 0)
            break;
        if (ip[pos] == 1) {
            pos++;
            continue;
        }
        if (pos + 1 >= header_len || pos >= 59)
            break;
        __u32 len = ip[pos + 1];
        if (len < 2 || pos + len > header_len)
            break;
        if (ip[pos] == VNETPATH_OPTION_TYPE && len == VNETPATH_OPTION_LENGTH &&
            pos <= 60 - VNETPATH_OPTION_LENGTH &&
            ip[pos + 2] == 'V' && ip[pos + 3] == 'N' &&
            ip[pos + 4] == 'P' && ip[pos + 5] == 'T')
            return pos;
        pos += len;
    }
    return -1;
}

static __always_inline void checksum_ipv4(__u8 ip[60], __u32 header_len)
{
    __u32 sum = 0;
    ip[10] = ip[11] = 0;
#pragma unroll
    for (int i = 0; i < 60; i += 2) {
        if (i < header_len)
            sum += read_be16(ip + i);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    __u16 check = ~sum;
    ip[10] = check >> 8;
    ip[11] = check;
}

/* One observation means the forwarding skb reached this egress hook. It
 * cannot tell whether a later filter, NIC or physical link dropped it.
 */
SEC("tcx/egress")
int trace_forward(struct __sk_buff *skb)
{
    if (!skb->ingress_ifindex)
        return TCX_NEXT;
    __u8 eth[ETH_HLEN], ip[60] = {};
    int l3 = ipv4_offset(skb, eth);
    if (l3 < 0 || bpf_skb_load_bytes(skb, l3, ip, 20))
        return TCX_NEXT;
    __u32 header_len = (ip[0] & 15) * 4;
    if ((ip[0] >> 4) != 4 || header_len < 20 + VNETPATH_OPTION_LENGTH ||
        header_len > sizeof(ip) || bpf_skb_load_bytes(skb, l3, ip, header_len))
        return TCX_NEXT;
    int option = find_mark(ip, header_len);
    if (option < 20 || option > 60 - VNETPATH_OPTION_LENGTH)
        return TCX_NEXT;

    __u32 key = 0;
    struct capture_stats *counts = bpf_map_lookup_elem(&stats, &key);
    __u64 probe = 0;
    __u32 sequence = 0;
#pragma unroll
    for (int i = 0; i < 8; i++)
        probe = (probe << 8) | ip[option + 6 + i];
#pragma unroll
    for (int i = 0; i < 4; i++)
        sequence = (sequence << 8) | ip[option + 14 + i];
    if (sequence == (__u32)-1 || (read_be16(ip + 6) & 0x3fff) ||
        skb->gso_segs > 1) {
        /* A fragmented/segmented datagram has no single next event. */
        if (counts)
            __sync_fetch_and_add(&counts->invalid_mark, 1);
        return TCX_NEXT;
    }
    __u64 tai_ns = bpf_ktime_get_tai_ns();
    sequence++;
#pragma unroll
    for (int i = 0; i < 4; i++)
        ip[option + 14 + i] = sequence >> (24 - 8 * i);
    checksum_ipv4(ip, header_len);
    /* One write updates both the sequence and IPv4 header checksum. The
     * helper also adjusts skb checksum metadata for CHECKSUM_COMPLETE.
     */
    if (bpf_skb_store_bytes(skb, l3, ip, header_len, BPF_F_RECOMPUTE_CSUM)) {
        if (counts)
            __sync_fetch_and_add(&counts->write_failed, 1);
        return TCX_NEXT;
    }
    struct trace_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        if (counts)
            __sync_fetch_and_add(&counts->ring_full, 1);
        return TCX_NEXT;
    }
    event->probe_id = probe;
    event->sequence = sequence;
    event->tai_ns = tai_ns;
    event->ingress = skb->ingress_ifindex;
    event->egress = skb->ifindex;
    __builtin_memcpy(event->src_ip, ip + 12, 4);
    __builtin_memcpy(event->dst_ip, ip + 16, 4);
    __builtin_memcpy(event->src_mac, eth + 6, 6);
    __builtin_memcpy(event->dst_mac, eth, 6);
    bpf_ringbuf_submit(event, 0);
    return TCX_NEXT;
}

char LICENSE[] SEC("license") = "GPL";

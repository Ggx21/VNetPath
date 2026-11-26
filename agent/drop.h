#ifndef VNETPATH_DROP_H
#define VNETPATH_DROP_H

#include <linux/types.h>
#include "trace.h"

enum vnetpath_drop_site { DROP_TC_INGRESS = 1, DROP_NETFILTER, DROP_OVS_EXPLICIT,
                          DROP_OVS_EXPLICIT_ERROR, DROP_OVS_EMPTY_ACTIONS };
struct drop_scope { __u32 netns, ifindex; };
struct drop_event {
    __u64 probe, tai_ns;
    __u32 seq, site;
    __u8 src[4], dst[4];
    char ifname[16];
};

static inline const char *vnetpath_drop_name(unsigned site)
{
    switch (site) {
    case DROP_TC_INGRESS: return "TC_INGRESS";
    case DROP_NETFILTER: return "NETFILTER_DROP";
    case DROP_OVS_EXPLICIT: return "OVS_DROP_EXPLICIT";
    case DROP_OVS_EXPLICIT_ERROR: return "OVS_DROP_EXPLICIT_WITH_ERROR";
    case DROP_OVS_EMPTY_ACTIONS: return "OVS_DROP_LAST_ACTION";
    default: return (const char *)0;
    }
}

/* A dropped skb never leaves this observation point. Its terminal event is
 * the next sequence after the last forward recorded in the IPv4 option. */
static inline __attribute__((always_inline))
int decode_dropped_probe(const __u8 ip[60], __u32 len, struct drop_event *result)
{
    if (len < 20 + VNETPATH_OPTION_LENGTH || len > 60 ||
        ip[0] >> 4 != 4 || (ip[0] & 15) * 4U != len ||
        (((__u32)ip[2] << 8) | ip[3]) < len || (ip[6] & 0x3f) || ip[7])
        return 0;
    int offset = vnetpath_probe_id_offset(ip, len);
    if (offset < 24 || offset > 60 - VNETPATH_PROBE_FIELDS_LENGTH)
        return 0;
    __u64 id = 0;
    __u32 seq = 0;
    for (int i = 0; i < 8; i++)
        id = (id << 8) | ip[offset + i];
    for (int i = 0; i < 4; i++)
        seq = (seq << 8) | ip[offset + 8 + i];
    if (seq == (__u32)-1)
        return 0;
    result->probe = id;
    result->seq = seq + 1;
    __builtin_memcpy(result->src, ip + 12, 4);
    __builtin_memcpy(result->dst, ip + 16, 4);
    return 1;
}
#endif

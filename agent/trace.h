#ifndef VNETPATH_AGENT_TRACE_H
#define VNETPATH_AGENT_TRACE_H

#include <linux/types.h>

/* Experimental IPv4 option: type, length, "VNPT", u64 ID, u32 sequence.
 * Multibyte fields on the wire are in network order. The sender starts at 0.
 */
#define VNETPATH_OPTION_TYPE 0x1e
#define VNETPATH_OPTION_LENGTH 18

struct trace_event {
    __u64 probe_id;
    __u64 tai_ns;
    __u32 sequence;
    __u32 ingress;
    __u32 egress;
    __u8 src_ip[4];
    __u8 dst_ip[4];
    __u8 src_mac[6];
    __u8 dst_mac[6];
};

struct capture_stats {
    __u64 ring_full;
    __u64 invalid_mark;
    __u64 write_failed;
};

#endif

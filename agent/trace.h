#ifndef VNETPATH_AGENT_TRACE_H
#define VNETPATH_AGENT_TRACE_H

#include <linux/types.h>

/* The four-byte magic is the IPv4 option type, length, and 'V', 'N'.
 * Its eight-byte probe ID and four-byte sequence use network byte order. */
#define VNETPATH_OPTION_TYPE 0x1e
#define VNETPATH_OPTION_LENGTH 16
#define VNETPATH_PROBE_FIELDS_LENGTH 12

/* Return the ID offset for either the 16-byte mark or the earlier VNPT
 * encoding (18-byte option padded to 20 bytes by the original sender). */
static inline __attribute__((always_inline))
int vnetpath_probe_id_offset(const __u8 ip[60], __u32 header_len)
{
    __u32 pos = 20;
#ifdef __clang__
#pragma clang loop unroll(disable)
#endif
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
        if (ip[pos] == VNETPATH_OPTION_TYPE && pos <= 60 - VNETPATH_OPTION_LENGTH &&
            ip[pos + 2] == 'V' && ip[pos + 3] == 'N') {
            if (len == VNETPATH_OPTION_LENGTH)
                return pos + 4;
            if (len == 18 && pos <= 60 - 18 && ip[pos + 4] == 'P' && ip[pos + 5] == 'T')
                return pos + 6;
        }
        pos += len;
    }
    return -1;
}

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

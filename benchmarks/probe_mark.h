#ifndef VNETPATH_BENCHMARK_PROBE_MARK_H
#define VNETPATH_BENCHMARK_PROBE_MARK_H
#include <stdint.h>
#include <netinet/in.h>
#include "../agent/trace.h"

static inline void store_probe_id(uint8_t *output, uint64_t value)
{
    for (int i = 7; i >= 0; --i) {
        output[i] = (uint8_t)value;
        value >>= 8;
    }
}

static inline int mark_request(int fd, uint64_t id)
{
    uint8_t option[VNETPATH_OPTION_LENGTH] = {VNETPATH_OPTION_TYPE, VNETPATH_OPTION_LENGTH, 'V', 'N'};
    store_probe_id(option + 4, id);
    return setsockopt(fd, IPPROTO_IP, IP_OPTIONS, option, sizeof option);
}
#endif

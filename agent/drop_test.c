#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "drop.h"

int main(void)
{
    assert(strcmp(vnetpath_drop_name(DROP_OVS_EXPLICIT), "OVS_DROP_EXPLICIT") == 0);
    assert(strcmp(vnetpath_drop_name(DROP_OVS_EXPLICIT_ERROR), "OVS_DROP_EXPLICIT_WITH_ERROR") == 0);
    assert(strcmp(vnetpath_drop_name(DROP_OVS_EMPTY_ACTIONS), "OVS_DROP_LAST_ACTION") == 0);
    assert(vnetpath_drop_name(100) == NULL);
    unsigned char ip[60] = {0x49, 0, 0, 64, 0, 0, 0x40, 0, 64, 17,
                            0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
                            0x1e, 16, 'V', 'N', 0x80, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 2};
    struct drop_event result = {};
    assert(decode_dropped_probe(ip, 36, &result) == 1);
    assert(result.probe == UINT64_C(0x8000000000000001) && result.seq == 259);
    assert(memcmp(result.src, ip + 12, 4) == 0 && memcmp(result.dst, ip + 16, 4) == 0);
    assert(decode_dropped_probe(ip, 35, &result) == 0);
    ip[6] = 0x20;
    assert(decode_dropped_probe(ip, 36, &result) == 0);
    ip[6] = 0;
    ip[23] = 'X';
    assert(decode_dropped_probe(ip, 36, &result) == 0);
    ip[23] = 'N';
    memset(ip + 32, 0xff, 4);
    assert(decode_dropped_probe(ip, 36, &result) == 0);
    ip[0] = 0x4a;
    ip[21] = 18;
    ip[24] = 'P';
    ip[25] = 'T';
    memset(ip + 26, 0, 12);
    ip[33] = 77;
    assert(decode_dropped_probe(ip, 40, &result) == 1);
    assert(result.probe == 77 && result.seq == 1);
    return 0;
}

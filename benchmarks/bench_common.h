#ifndef VNETPATH_BENCH_COMMON_H
#define VNETPATH_BENCH_COMMON_H
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define MS_NS INT64_C(1000000)
static inline void die(const char *what)
{
    perror(what);
    exit(1);
}

static inline uint32_t number(const char *arg, uint32_t min, uint32_t max)
{
    char *end;
    errno = 0;
    unsigned long n = strtoul(arg, &end, 10);
    if (arg[0] < '0' || arg[0] > '9' || errno || *end || n < min || n > max) {
        fprintf(stderr, "expected an integer between %" PRIu32 " and %" PRIu32 ": %s\n", min, max, arg);
        exit(1);
    }
    return (uint32_t)n;
}

static inline struct sockaddr_in endpoint(const char *text, uint16_t port)
{
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
    if (inet_pton(AF_INET, text, &addr.sin_addr) != 1) {
        fprintf(stderr, "expected a literal IPv4 test address: %s\n", text);
        exit(1);
    }
    uint32_t ip = ntohl(addr.sin_addr.s_addr);
    if (ip >> 24 != 127 && ip >> 24 != 10 && ip >> 20 != 0xac1 &&
        ip >> 16 != 0xc0a8 && ip >> 16 != 0xa9fe) {
        fprintf(stderr, "use two explicit loopback, private or link-local test endpoints\n");
        exit(1);
    }
    return addr;
}

static inline int64_t now_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) die("clock_gettime");
    return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static inline void sleep_ms(uint32_t ms)
{
    struct timespec t = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * MS_NS };
    while (nanosleep(&t, &t)) if (errno != EINTR) die("nanosleep");
}

#endif

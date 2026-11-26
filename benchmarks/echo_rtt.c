/* One connected UDP flow, one outstanding request, one row per sample. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "probe_mark.h"

#define MAX_REQUESTS 1000
#define MESSAGE_LEN 12
#include "bench_common.h"

struct run {
    uint32_t number, count, interval_ms, timeout_ms;
    const char *mode;
    int trace;
};

static uint64_t probe_id(const struct run *run, uint32_t sample)
{
    return ((uint64_t)run->number << 32) | sample;
}

static uint64_t decode_id(const uint8_t *data)
{
    uint64_t id = 0;
    for (int i = 0; i < 8; ++i) id = (id << 8) | data[i];
    return id;
}

/* Return 1 on readable data, 0 at the deadline. An unrelated datagram or
 * interrupted system call must not restart a lone request's timeout. */
static int wait_packet(int fd, int64_t deadline)
{
    for (;;) {
        int64_t remaining = deadline - now_ns();
        if (remaining <= 0) return 0;
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int n = poll(&p, 1, (int)((remaining + MS_NS - 1) / MS_NS));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) die("poll");
        if (n && (p.revents & (POLLIN | POLLERR))) return 1;
        if (n) {
            fprintf(stderr, "unexpected poll events: %d\n", p.revents);
            exit(1);
        }
    }
}

static int client(int fd, const struct run *run)
{
    int failed = 0;
    puts("run,mode,sample,probe_id,status,send_mono_ns,receive_mono_ns,rtt_ns,ignored_replies");
    for (uint32_t i = 1; i <= run->count; ++i) {
        uint64_t id = probe_id(run, i);
        uint8_t message[MESSAGE_LEN] = { 'V','P','Q','1' }, reply[MESSAGE_LEN];
        store_probe_id(message + 4, id);
        if (run->trace) {
            if (mark_request(fd, id)) die("set probe IP_OPTIONS");
        }
        int64_t sent = now_ns();
        const char *status = "timeout";
        int64_t received = 0;
        unsigned ignored = 0;
        if (send(fd, message, sizeof message, 0) != sizeof message) {
            status = "send_error";
        } else {
            int64_t deadline = sent + run->timeout_ms * MS_NS;
            while (wait_packet(fd, deadline)) {
                ssize_t size = recv(fd, reply, sizeof reply, MSG_TRUNC);
                int64_t t = now_ns();
                if (size < 0 && errno == EINTR) continue;
                if (size < 0) { status = "receive_error"; break; }
                if (t > deadline) break;
                if (size == sizeof reply && !memcmp(reply, "VPA1", 4) && decode_id(reply + 4) == id) {
                    status = "ok";
                    received = t;
                    break;
                }
                ++ignored;
            }
        }
        printf("%" PRIu32 ",%s,%" PRIu32 ",%" PRIu64 ",%s,%" PRId64 ",",
               run->number, run->mode, i, id, status, sent);
        if (received) printf("%" PRId64 ",%" PRId64, received, received - sent);
        else { putchar(','); ++failed; }
        printf(",%u\n", ignored);
        if (i < run->count) sleep_ms(run->interval_ms);
    }
    return failed ? 2 : 0;
}

/* Check the kernel-delivered IP options. The forwarding agent can advance
 * the sequence in transit, so verify the mark and ID and record the sequence. */
static int mark_sequence(struct msghdr *msg, uint64_t id, uint32_t *sequence)
{
    for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c)) {
        if (c->cmsg_level != IPPROTO_IP || c->cmsg_type != IP_RECVOPTS) continue;
        size_t n = c->cmsg_len - CMSG_LEN(0);
        const uint8_t *options = CMSG_DATA(c);
        for (size_t pos = 0; pos < n && options[pos] != 0;) {
            if (options[pos] == 1) { ++pos; continue; }
            if (n - pos < 2 || options[pos + 1] < 2 || options[pos + 1] > n - pos) return -1;
            if (options[pos] == VNETPATH_OPTION_TYPE && options[pos + 1] == VNETPATH_OPTION_LENGTH &&
                !memcmp(options + pos + 2, "VN", 2)) {
                if (decode_id(options + pos + 4) != id) return -1;
                uint32_t wire;
                memcpy(&wire, options + pos + 12, sizeof wire);
                *sequence = ntohl(wire);
                return 1;
            }
            pos += options[pos + 1];
        }
    }
    return 0;
}

static int server(int fd, const struct run *run)
{
    uint8_t seen[MAX_REQUESTS + 1] = {0};
    int enabled = 1, failed = 0;
    if (setsockopt(fd, IPPROTO_IP, IP_RECVOPTS, &enabled, sizeof enabled)) die("enable IP_RECVOPTS");
    puts("run,mode,sample,probe_id,status,receive_mono_ns,reply_send_mono_ns,request_mark,mark_sequence");
    fprintf(stderr, "ready for %" PRIu32 " requests (%s)\n", run->count, run->mode);
    int64_t slot = (run->interval_ms + run->timeout_ms) * MS_NS;
    int64_t deadline = now_ns() + 60000 * MS_NS + run->count * slot;
    uint32_t latest = 0;
    for (uint32_t count = 0; count < run->count && wait_packet(fd, deadline);) {
        uint8_t data[MESSAGE_LEN];
        union { struct cmsghdr align; unsigned char bytes[128]; } control;
        struct iovec iov = { .iov_base = data, .iov_len = sizeof data };
        struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                              .msg_control = control.bytes, .msg_controllen = sizeof control.bytes };
        ssize_t size = recvmsg(fd, &msg, MSG_TRUNC);
        int64_t arrived = now_ns();
        if (size < 0 && errno == EINTR) continue;
        if (size < 0) { perror("receive request"); failed = 1; break; }
        if (size != sizeof data || memcmp(data, "VPQ1", 4)) continue;
        uint64_t id = decode_id(data + 4);
        uint32_t i = (uint32_t)id;
        if (id >> 32 != run->number || !i || i > run->count || seen[i]) continue;
        seen[i] = 1;
        ++count;
        /* Reply immediately; formatting and endpoint validation happen
         * after send so the peer's RTT excludes server-side CSV output. */
        data[2] = 'A';
        int64_t replied = now_ns();
        int ok = send(fd, data, sizeof data, 0) == sizeof data;
        uint32_t sequence = 0;
        int marked = (msg.msg_flags & MSG_CTRUNC) ? -1 : mark_sequence(&msg, id, &sequence);
        const char *status = !ok ? "send_error" : marked != run->trace ? "mark_mismatch" : "ok";
        if (!ok || marked != run->trace) failed = 1;
        printf("%" PRIu32 ",%s,%" PRIu32 ",%" PRIu64 ",%s,%" PRId64 ",",
               run->number, run->mode, i, id, status, arrived);
        if (ok) printf("%" PRId64, replied);
        printf(",%s,", marked == 1 ? "present" : marked == 0 ? "absent" : "invalid");
        if (marked == 1) printf("%" PRIu32, sequence);
        putchar('\n');
        if (i > latest) latest = i;
        /* Allow every outstanding planned trial its full timeout. */
        deadline = now_ns() + (run->count - latest) * slot + run->timeout_ms * MS_NS;
    }
    for (uint32_t i = 1; i <= run->count; ++i) {
        if (!seen[i]) {
            failed = 1;
            printf("%" PRIu32 ",%s,%" PRIu32 ",%" PRIu64 ",not_observed,,,,\n",
                   run->number, run->mode, i, probe_id(run, i));
        }
    }
    return failed ? 2 : 0;
}

int main(int argc, char **argv)
{
    if (argc != 11 || (strcmp(argv[1], "server") && strcmp(argv[1], "client"))) {
        fprintf(stderr, "Usage: %s server|client LOCAL_IP LOCAL_PORT PEER_IP PEER_PORT "
                "baseline|agent-only|trace RUN_ID COUNT INTERVAL_MS TIMEOUT_MS\n"
                "Start the server first with endpoints reversed. Only trace requests are marked. "
                "An attached agent is configured separately. Output is CSV; exit 2 means incomplete samples.\n",
                argv[0]);
        return argc == 2 && !strcmp(argv[1], "--help") ? 0 : 1;
    }
    const char *mode = argv[6];
    int trace = !strcmp(mode, "trace");
    if (!trace && strcmp(mode, "baseline") && strcmp(mode, "agent-only")) {
        fprintf(stderr, "unknown run mode: %s\n", mode);
        return 1;
    }
    struct run run = { .number = number(argv[7], 1, UINT32_MAX), .count = number(argv[8], 1, MAX_REQUESTS),
                       .interval_ms = number(argv[9], 1, 10000), .timeout_ms = number(argv[10], 1, 10000),
                       .mode = mode, .trace = trace };
    struct sockaddr_in local = endpoint(argv[2], number(argv[3], 1, 65535));
    struct sockaddr_in peer = endpoint(argv[4], number(argv[5], 1, 65535));
    if (local.sin_addr.s_addr == peer.sin_addr.s_addr && local.sin_port == peer.sin_port) {
        fprintf(stderr, "client and server endpoints must differ\n");
        return 1;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) die("socket");
    if (bind(fd, (struct sockaddr *)&local, sizeof local)) die("bind explicit local IPv4 endpoint");
    if (connect(fd, (struct sockaddr *)&peer, sizeof peer)) die("connect peer");
    int ret = !strcmp(argv[1], "server") ? server(fd, &run) : client(fd, &run);
    if (fflush(stdout)) die("write samples");
    close(fd);
    return ret;
}

/* HTTP/1.0 over a fresh, explicitly source-bound TCP connection per sample. */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>
#include "bench_common.h"
#include "probe_mark.h"

struct sample {
    int64_t started, sent, completed;
    int response_code, error;
    size_t body;
    uint16_t source_port;
};

static int ready(int fd, short events, int64_t deadline)
{
    struct pollfd desc = { .fd = fd, .events = events };
    for (;;) {
        int64_t ns = deadline - now_ns();
        if (ns <= 0) { errno = ETIMEDOUT; return 0; }
        int result = poll(&desc, 1, (int)((ns + MS_NS - 1) / MS_NS));
        if (result == 0 || (result < 0 && errno == EINTR)) continue;
        return result;
    }
}

static const char *wait_error(const char *operation)
{
    return errno == ETIMEDOUT ? "timeout" : operation;
}

static const char *headers(char *buf, int *code, int64_t *length)
{
    char *state = NULL;
    char *line = strtok_r(buf, "\r\n", &state);
    if (!line || strlen(line) < 12 || (strncmp(line, "HTTP/1.0 ", 9) && strncmp(line, "HTTP/1.1 ", 9)) ||
        line[9] < '0' || line[9] > '9' || line[10] < '0' || line[10] > '9' ||
        line[11] < '0' || line[11] > '9' || (line[12] && line[12] != ' ')) return "invalid_status_line";
    *code = 100 * (line[9] - '0') + 10 * (line[10] - '0') + line[11] - '0';
    *length = -1;
    while ((line = strtok_r(NULL, "\r\n", &state)) != NULL) {
        char *value = strchr(line, ':');
        if (!value) return "invalid_header";
        *value++ = 0;
        while (*value == ' ' || *value == '\t') ++value;
        if (!strcasecmp(line, "Transfer-Encoding")) return "unsupported_transfer_encoding";
        if (!strcasecmp(line, "Content-Length")) {
            if (*value < '0' || *value > '9') return "invalid_content_length";
            errno = 0;
            char *end;
            long long n = strtoll(value, &end, 10);
            while (*end == ' ' || *end == '\t') ++end;
            if (errno || *end || (*length != -1 && n != *length)) return "invalid_content_length";
            *length = n;
        }
    }
    if (*code == 204) {
        if (*length > 0) return "invalid_content_length";
        *length = 0;
    }
    return NULL;
}

static const char *response(int fd, int64_t deadline, struct sample *row)
{
    char header[8192], block[4096];
    size_t used = 0;
    int complete_header = 0;
    int64_t expected = -1;
    for (;;) {
        if (ready(fd, POLLIN, deadline) <= 0) return wait_error("receive_error");
        ssize_t n = recv(fd, block, sizeof block, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n < 0) return "receive_error";
        if (n == 0) {
            if (!complete_header || (expected >= 0 && (uint64_t)expected != row->body)) return "truncated_response";
            break;
        }
        size_t pos = 0;
        while (!complete_header && pos < (size_t)n) {
            if (used == sizeof header - 1) return "header_too_large";
            if (block[pos] == '\0') return "invalid_header";
            header[used++] = block[pos++];
            if (used >= 4 && !memcmp(header + used - 4, "\r\n\r\n", 4)) {
                header[used] = 0;
                const char *err = headers(header, &row->response_code, &expected);
                if (err) return err;
                complete_header = 1;
            }
        }
        row->body += (size_t)n - pos;
        if (row->body > 4 * 1024 * 1024) return "body_too_large";
        if (complete_header && expected >= 0) {
            if (row->body > (uint64_t)expected) return "content_length_mismatch";
            if (row->body == (uint64_t)expected) break;
        }
    }
    row->completed = now_ns();
    if (row->completed > deadline) return "timeout";
    return row->response_code >= 200 && row->response_code < 300 ? "ok" : "http_error";
}

static const char *request(int fd, const struct sockaddr_in *local, const struct sockaddr_in *peer,
                           const char *get, size_t size, int trace, uint64_t id, uint32_t timeout,
                           struct sample *row)
{
    if (bind(fd, (const struct sockaddr *)local, sizeof *local)) return "bind_error";
    struct sockaddr_in bound;
    socklen_t len = sizeof bound;
    if (getsockname(fd, (struct sockaddr *)&bound, &len)) return "bind_error";
    row->source_port = ntohs(bound.sin_port);
    int enabled = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof enabled)) return "socket_error";
    row->started = now_ns();
    int64_t deadline = row->started + timeout * MS_NS;
    if (connect(fd, (const struct sockaddr *)peer, sizeof *peer) < 0) {
        if (errno != EINPROGRESS) return "connect_error";
        if (ready(fd, POLLOUT, deadline) <= 0) return wait_error("connect_error");
        int error;
        socklen_t error_size = sizeof error;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_size)) return "connect_error";
        if (error) { errno = error; return "connect_error"; }
    }
    if (trace && mark_request(fd, id)) return "set_mark_error";
    row->sent = now_ns();
    ssize_t sent = send(fd, get, size, MSG_NOSIGNAL);
    int error = sent < 0 ? errno : 0;
    if (trace && setsockopt(fd, IPPROTO_IP, IP_OPTIONS, NULL, 0)) return "clear_mark_error";
    if (sent < 0) { errno = error; return "send_error"; }
    if ((size_t)sent != size) return "partial_send";
    return response(fd, deadline, row);
}

int main(int argc, char **argv)
{
    if (argc != 10) {
        fprintf(stderr, "Usage: %s SOURCE_IP HTTP_IP PORT /PATH baseline|agent-only|trace "
                "RUN_ID COUNT INTERVAL_MS TIMEOUT_MS\n"
                "Use a small HTTP resource. The sequence marks only the short GET, after connect. "
                "External instrumentation distinguishes baseline from agent-only. Output CSV, exit 2 on failed samples.\n",
                argv[0]);
        return argc == 2 && !strcmp(argv[1], "--help") ? 0 : 1;
    }
    struct sockaddr_in local = endpoint(argv[1], 0), peer = endpoint(argv[2], number(argv[3], 1, 65535));
    const char *path = argv[4], *mode = argv[5];
    int trace = !strcmp(mode, "trace");
    if (!trace && strcmp(mode, "baseline") && strcmp(mode, "agent-only")) {
        fprintf(stderr, "unknown mode\n"); return 1;
    }
    if (*path != '/' || strlen(path) > 256 || strspn(path, "/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            "0123456789-._~!$&'()*+,;=:@%?") != strlen(path)) {
        fprintf(stderr, "expected a short, URL-encoded origin path beginning with /\n"); return 1;
    }
    uint32_t run = number(argv[6], 1, UINT32_MAX), count = number(argv[7], 1, 1000);
    uint32_t interval = number(argv[8], 1, 10000), timeout = number(argv[9], 1, 10000);
    char get[512];
    int size = snprintf(get, sizeof get, "GET %s HTTP/1.0\r\nHost: %s:%s\r\nConnection: close\r\n\r\n",
                        path, argv[2], argv[3]);
    if (size < 0 || (size_t)size >= sizeof get) { fputs("GET too large\n", stderr); return 1; }
    puts("run,mode,sample,probe_id,status,source_port,http_status,body_bytes,connect_start_ns,"
         "request_send_ns,response_complete_ns,rtt_ns,total_ns,os_error");
    int failures = 0;
    for (uint32_t i = 1; i <= count; ++i) {
        uint64_t id = ((uint64_t)run << 32) | i;
        struct sample row = {0};
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
        if (fd < 0) die("socket");
        errno = 0;
        const char *status = request(fd, &local, &peer, get, (size_t)size, trace, id, timeout, &row);
        row.error = (!strcmp(status, "timeout") ? ETIMEDOUT :
                     (strstr(status, "_error") && strcmp(status, "http_error") ? errno : 0));
        close(fd);
        printf("%" PRIu32 ",%s,%" PRIu32 ",%" PRIu64 ",%s,%u,%d,%zu,",
               run, mode, i, id, status, (unsigned)row.source_port, row.response_code, row.body);
        if (row.started) printf("%" PRId64, row.started);
        putchar(',');
        if (row.sent) printf("%" PRId64, row.sent);
        putchar(',');
        if (row.completed) printf("%" PRId64, row.completed);
        if (!strcmp(status, "ok")) {
            printf(",%" PRId64 ",%" PRId64, row.completed - row.sent, row.completed - row.started);
        } else {
            fputs(",,", stdout); ++failures;
        }
        printf(",%d\n", row.error);
        if (i < count) sleep_ms(interval);
    }
    if (fflush(stdout)) die("write CSV");
    return failures ? 2 : 0;
}

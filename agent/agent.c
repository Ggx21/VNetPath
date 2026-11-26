#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <json-c/json.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/timex.h>
#include <sys/un.h>
#include <unistd.h>
#include "trace.h"

struct attachment {
    int lock;
    struct bpf_link *link;
};

static volatile sig_atomic_t stopping;

static void stop(int signum)
{
    (void)signum;
    stopping = 1;
}

static void usage(FILE *out, const char *name)
{
    fprintf(out, "Usage: %s --device HOST [--object trace.bpf.o] IFACE [IFACE ...]\n"
            "Trace marked IPv4 forwarding at the TCX egress hook of Ethernet interfaces\n"
            "in the current network namespace. Use a unique HOST for each host/namespace.\n"
            "Writes JSONL to stdout with HOST/IFACE port IDs; SIGINT or SIGTERM detaches.\n"
            "Requires Linux 6.6+, libbpf 1.3+, and permission to attach TCX programs.\n", name);
}

static int ethernet_index(const char *name)
{
    if (strlen(name) >= IFNAMSIZ) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct ifreq req = {};
    strcpy(req.ifr_name, name);
    int ret = ioctl(fd, SIOCGIFHWADDR, &req);
    if (ret == 0 && req.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        errno = EPROTONOSUPPORT;
        ret = -1;
    }
    if (ret == 0)
        ret = ioctl(fd, SIOCGIFINDEX, &req);
    int saved = errno;
    close(fd);
    errno = saved;
    return ret < 0 ? -1 : req.ifr_ifindex;
}

/* An abstract Unix socket releases the lock on process exit and is scoped
 * to the network namespace. Two agents must not increment one mark twice.
 */
static int lock_interface(unsigned int index)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    int len = snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1,
                       "vnetpath-tcx-egress-%u", index);
    if (bind(fd, (struct sockaddr *)&addr,
             offsetof(struct sockaddr_un, sun_path) + 1 + len) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static json_object *port_id(const char *host, unsigned int index)
{
    char name[IFNAMSIZ], id[256 + IFNAMSIZ + 1];
    if (!if_indextoname(index, name))
        return NULL;
    snprintf(id, sizeof(id), "%s/%s", host, name);
    return json_object_new_string(id);
}

static json_object *mac_address(const unsigned char mac[6])
{
    char value[18];
    snprintf(value, sizeof(value), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return json_object_new_string(value);
}

static int emit_event(void *context, void *data, size_t size)
{
    if (size != sizeof(struct trace_event)) {
        fprintf(stderr, "incompatible event record size: %zu\n", size);
        return -EBADMSG;
    }
    const struct trace_event *e = data;
    const char *host = context;
    /* The kernel timestamps the event in TAI. Linux maintains the current
     * integral TAI-UTC offset (zero on hosts with no configured offset).
     */
    struct timex clock = {};
    if (adjtimex(&clock) < 0) {
        perror("read TAI-UTC offset");
        return -EIO;
    }
    int64_t unix_ms = (int64_t)(e->tai_ns / 1000000) - (int64_t)clock.tai * 1000;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, e->src_ip, src, sizeof(src)) ||
        !inet_ntop(AF_INET, e->dst_ip, dst, sizeof(dst)))
        return -EIO;
    json_object *in = port_id(host, e->ingress), *out = port_id(host, e->egress);
    if (!in || !out) {
        fprintf(stderr, "cannot resolve observed interfaces %u -> %u in this namespace\n",
                e->ingress, e->egress);
        json_object_put(in);
        json_object_put(out);
        return -ENODEV;
    }
    json_object *event = json_object_new_object(), *packet = json_object_new_object();
    json_object *eth = json_object_new_object(), *ip = json_object_new_object();
    if (!event || !packet || !eth || !ip) {
        json_object_put(in);
        json_object_put(out);
        json_object_put(event);
        json_object_put(packet);
        json_object_put(eth);
        json_object_put(ip);
        return -ENOMEM;
    }
    json_object_object_add(event, "probe_ID", json_object_new_uint64(e->probe_id));
    json_object_object_add(event, "sequence_num", json_object_new_int64(e->sequence));
    json_object_object_add(event, "phy_device_ID", json_object_new_string(host));
    json_object_object_add(event, "in_port_name", in);
    json_object_object_add(event, "out_port_name", out);
    json_object_object_add(event, "action", json_object_new_string("forward"));
    json_object_object_add(event, "timestamp", json_object_new_int64(unix_ms));
    json_object_object_add(eth, "src_mac", mac_address(e->src_mac));
    json_object_object_add(eth, "dst_mac", mac_address(e->dst_mac));
    json_object_object_add(ip, "src_IP", json_object_new_string(src));
    json_object_object_add(ip, "dst_IP", json_object_new_string(dst));
    json_object_object_add(packet, "ethernet", eth);
    json_object_object_add(packet, "IP", ip);
    json_object_object_add(event, "packet_info", packet);
    int ret = puts(json_object_to_json_string_ext(event, JSON_C_TO_STRING_PLAIN));
    json_object_put(event);
    if (ret == EOF || fflush(stdout) == EOF) {
        perror("write event stream");
        return -EIO;
    }
    return 0;
}

static int check_capture(int stats_fd)
{
    unsigned int key = 0;
    struct capture_stats stats = {};
    if (bpf_map_lookup_elem(stats_fd, &key, &stats) < 0) {
        perror("read capture statistics");
        return -1;
    }
    if (stats.ring_full || stats.invalid_mark || stats.write_failed) {
        fprintf(stderr, "incomplete capture: ring full=%llu, fragmented/segmented/overflowed marks=%llu, "
                "mark write failures=%llu\n", stats.ring_full, stats.invalid_mark, stats.write_failed);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *path = "trace.bpf.o", *host = NULL;
    const struct option options[] = {
        {"object", required_argument, NULL, 'o'}, {"device", required_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'}, {}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "o:d:h", options, NULL)) != -1) {
        if (opt == 'o') path = optarg;
        else if (opt == 'd') host = optarg;
        else {
            usage(opt == 'h' ? stdout : stderr, argv[0]);
            return opt == 'h' ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }
    int count = argc - optind;
    if (!host || !*host || strlen(host) > 255 || strchr(host, '/') || count == 0) {
        usage(stderr, argv[0]);
        return EXIT_FAILURE;
    }
    struct sigaction action = { .sa_handler = stop };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL) ||
        signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("set signal handler");
        return EXIT_FAILURE;
    }
    struct attachment *attachments = calloc(count, sizeof(*attachments));
    if (!attachments)
        return EXIT_FAILURE;
    for (int i = 0; i < count; i++)
        attachments[i].lock = -1;
    struct ring_buffer *ring = NULL;
    int status = EXIT_FAILURE, stats_fd = -1;
    bool running = false;
    struct bpf_object *object = bpf_object__open_file(path, NULL);
    if (!object || bpf_object__load(object))
        goto done;
    struct bpf_program *program = bpf_object__find_program_by_name(object, "trace_forward");
    int events_fd = bpf_object__find_map_fd_by_name(object, "events");
    stats_fd = bpf_object__find_map_fd_by_name(object, "stats");
    if (!program || events_fd < 0 || stats_fd < 0) {
        fprintf(stderr, "object lacks the VNetPath program or maps\n");
        goto done;
    }
    ring = ring_buffer__new(events_fd, emit_event, (void *)host, NULL);
    if (!ring) {
        perror("open event ring");
        goto done;
    }
    for (int i = 0; i < count; i++) {
        const char *name = argv[optind + i];
        int index = ethernet_index(name);
        if (index < 0 || (attachments[i].lock = lock_interface(index)) < 0) {
            perror(name);
            goto done;
        }
        attachments[i].link = bpf_program__attach_tcx(program, index, NULL);
        if (!attachments[i].link) {
            perror(name);
            goto done;
        }
    }
    running = true;
    status = EXIT_SUCCESS;
    fprintf(stderr, "attached to %d egress interface(s) on %s\n", count, host);
    while (!stopping) {
        int ret = ring_buffer__poll(ring, 250);
        if (ret == -EINTR)
            continue;
        if (ret < 0 || check_capture(stats_fd)) {
            status = EXIT_FAILURE;
            break;
        }
    }

done:
    for (int i = 0; i < count; i++) {
        if (attachments[i].link && bpf_link__destroy(attachments[i].link))
            status = EXIT_FAILURE;
    }
    if (running && status == EXIT_SUCCESS &&
        (ring_buffer__consume(ring) < 0 || check_capture(stats_fd)))
        status = EXIT_FAILURE;
    for (int i = 0; i < count; i++) {
        if (attachments[i].lock >= 0)
            close(attachments[i].lock);
    }
    ring_buffer__free(ring);
    bpf_object__close(object);
    free(attachments);
    return status;
}

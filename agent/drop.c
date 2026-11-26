#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <json-c/json.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/timex.h>
#include "drop.h"

struct observer { const char *host, *interface; };
static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping = 1; }

static void usage(FILE *out, const char *exe)
{
    fprintf(out, "Usage: %s --device HOST --interface IFACE [--object drop.bpf.o] PROBE_ID [...]\n"
            "Report TC ingress, netfilter and explicit/empty-action OVS drops of marked IPv4 probes.\n"
            "PROBE_IDs are unsigned decimal IDs from the replay manifest; output is event JSONL.\n",
            exe);
}

static int emit_drop(void *context, void *data, size_t size)
{
    const struct observer *selected = context;
    const struct drop_event *e = data;
    if (size != sizeof(*e) || !memchr(e->ifname, 0, sizeof(e->ifname)) ||
        strcmp(e->ifname, selected->interface))
        return -EBADMSG;
    const char *reason = vnetpath_drop_name(e->site);
    struct timex offset = {};
    if (!reason || adjtimex(&offset) < 0)
        return -EIO;
    char port[256 + IFNAMSIZ + 1], src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    snprintf(port, sizeof(port), "%s/%s", selected->host, e->ifname);
    if (!inet_ntop(AF_INET, e->src, src, sizeof(src)) || !inet_ntop(AF_INET, e->dst, dst, sizeof(dst)))
        return -EINVAL;
    json_object *row = json_object_new_object(), *packet = json_object_new_object(), *ip = json_object_new_object();
    if (!row || !packet || !ip) {
        json_object_put(row);
        json_object_put(packet);
        json_object_put(ip);
        return -ENOMEM;
    }
    json_object_object_add(row, "probe_ID", json_object_new_uint64(e->probe));
    json_object_object_add(row, "sequence_num", json_object_new_int64(e->seq));
    json_object_object_add(row, "phy_device_ID", json_object_new_string(selected->host));
    json_object_object_add(row, "in_port_name", json_object_new_string(port));
    json_object_object_add(row, "out_port_name", json_object_new_string("dropped"));
    json_object_object_add(row, "action", json_object_new_string("drop"));
    json_object_object_add(row, "timestamp", json_object_new_int64((int64_t)(e->tai_ns / 1000000) -
                                                                    (int64_t)offset.tai * 1000));
    json_object_object_add(row, "drop_reason", json_object_new_string(reason));
    if (e->site == DROP_OVS_EMPTY_ACTIONS)
        json_object_object_add(row, "ovs_original_actions_bytes", json_object_new_int(0));
    json_object_object_add(ip, "src_IP", json_object_new_string(src));
    json_object_object_add(ip, "dst_IP", json_object_new_string(dst));
    json_object_object_add(packet, "IP", ip);
    json_object_object_add(row, "packet_info", packet);
    int ret = puts(json_object_to_json_string_ext(row, JSON_C_TO_STRING_PLAIN));
    json_object_put(row);
    return ret == EOF || fflush(stdout) == EOF ? -EIO : 0;
}

static int add_probes(int fd, char **ids, int count)
{
    __u8 enabled = 1;
    for (int i = 0; i < count; i++) {
        const char *id = ids[i];
        if (!*id || strspn(id, "0123456789") != strlen(id))
            return -EINVAL;
        errno = 0;
        uint64_t parsed = strtoull(id, NULL, 10);
        if (errno || bpf_map_update_elem(fd, &parsed, &enabled, BPF_NOEXIST))
            return -errno;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct observer selected = {};
    const char *path = "drop.bpf.o";
    const struct option options[] = {{"device", required_argument, NULL, 'd'},
                                     {"interface", required_argument, NULL, 'i'},
                                     {"object", required_argument, NULL, 'o'},
                                     {"help", no_argument, NULL, 'h'}, {}};
    int opt;
    while ((opt = getopt_long(argc, argv, "d:i:o:h", options, NULL)) != -1) {
        if (opt == 'd') selected.host = optarg;
        else if (opt == 'i') selected.interface = optarg;
        else if (opt == 'o') path = optarg;
        else { usage(opt == 'h' ? stdout : stderr, argv[0]); return opt == 'h' ? 0 : 2; }
    }
    if (argc == optind || argc - optind > 1024 || !selected.host || !*selected.host ||
        strlen(selected.host) > 255 || strchr(selected.host, '/') || !selected.interface) {
        usage(stderr, argv[0]);
        return 2;
    }
    struct stat namespace;
    struct drop_scope filter = { .ifindex = if_nametoindex(selected.interface) };
    if (!filter.ifindex || stat("/proc/self/ns/net", &namespace)) {
        perror("resolve interface and network namespace");
        return 2;
    }
    if (namespace.st_ino == 0 || namespace.st_ino > UINT32_MAX) {
        fprintf(stderr, "network namespace inode is out of range\n");
        return 2;
    }
    filter.netns = namespace.st_ino;
    struct sigaction action = { .sa_handler = stop };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL) ||
        signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        return 1;

    int status = 1;
    __u32 zero = 0;
    struct bpf_link *link = NULL;
    struct ring_buffer *ring = NULL;
    struct bpf_object *obj = bpf_object__open_file(path, NULL);
    if (!obj || bpf_object__load(obj))
        goto done;
    int scope_fd = bpf_object__find_map_fd_by_name(obj, "scope");
    int ids_fd = bpf_object__find_map_fd_by_name(obj, "probe_ids");
    int lost_fd = bpf_object__find_map_fd_by_name(obj, "lost");
    int events_fd = bpf_object__find_map_fd_by_name(obj, "drops");
    struct bpf_program *program = bpf_object__find_program_by_name(obj, "trace_vnetpath_drop");
    if (!program || scope_fd < 0 || ids_fd < 0 || lost_fd < 0 || events_fd < 0 ||
        bpf_map_update_elem(scope_fd, &zero, &filter, BPF_ANY)) {
        fprintf(stderr, "cannot configure drop observation\n");
        goto done;
    }
    int ret = add_probes(ids_fd, argv + optind, argc - optind);
    if (ret) {
        fprintf(stderr, "cannot register probe IDs: %s\n", strerror(-ret));
        goto done;
    }
    ring = ring_buffer__new(events_fd, emit_drop, &selected, NULL);
    if (!ring || !(link = bpf_program__attach_raw_tracepoint(program, "kfree_skb")))
        goto done;
    fprintf(stderr, "observing kernel drops on %s/%s for %d probe ID(s)\n",
            selected.host, selected.interface, argc - optind);
    while (!stopping) {
        ret = ring_buffer__poll(ring, 250);
        if (ret < 0 && ret != -EINTR)
            goto done;
    }
    ret = bpf_link__destroy(link);
    link = NULL;
    __u64 lost_count;
    if (ret || ring_buffer__consume(ring) < 0 || bpf_map_lookup_elem(lost_fd, &zero, &lost_count))
        goto done;
    if (lost_count) {
        fprintf(stderr, "incomplete capture: lost %" PRIu64 " marked drop events\n", (uint64_t)lost_count);
        goto done;
    }
    status = 0;
done:
    bpf_link__destroy(link);
    ring_buffer__free(ring);
    bpf_object__close(obj);
    return status;
}

#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>

#include <argparse.h>
#include <net/if.h>

#include "log.h"

#include "conntrack_if_helper.h"
#include "conntrack.skel.h"
#include "ebpf/conntrack_structs.h"

static __u32 xdp_flags = 0;
static int ifindex_if1 = 0;
static int ifindex_if2 = 0;
static int connections_map_fd = 0;

static const char *const usages[] = {
    "conntrack [options] [[--] args]",
    "conntrack [options]",
    NULL,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static void cleanup_ifaces() {
    __u32 curr_prog_id = 0;

    if (!bpf_xdp_query_id(ifindex_if1, xdp_flags, &curr_prog_id)) {
        if (curr_prog_id) {
            bpf_xdp_detach(ifindex_if1, xdp_flags, NULL);
        }
    }

    if (!bpf_xdp_query_id(ifindex_if2, xdp_flags, &curr_prog_id)) {
        if (curr_prog_id) {
            bpf_xdp_detach(ifindex_if2, xdp_flags, NULL);
        }
    }
}

void sigint_handler(int sig_no) {
    log_debug("Closing program...");
    cleanup_ifaces();
    exit(0);
}

static void poll_stats(int map_fd, int interval) {
    unsigned int nr_cpus = libbpf_num_possible_cpus();
    struct pkt_md values[nr_cpus];
    __u64 prev[2] = {0};
    int i;

    while (1) {
        __u32 key = 0;

        sleep(interval);

        __u64 sum[2] = {0};

        assert(bpf_map_lookup_elem(map_fd, &key, values) == 0);
        for (i = 0; i < nr_cpus; i++) {
            sum[0] += values[i].cnt;
            sum[1] += values[i].bytes_cnt;
        }
        if (sum[0] > prev[0])
            log_info("%10llu pkt/s", (sum[0] - prev[0]) / interval);
        if (sum[1] > prev[1])
            log_info("%10llu byte/s", (sum[1] - prev[1]) / interval);
        prev[0] = sum[0];
        prev[1] = sum[1];
    }
}

int main(int argc, const char **argv) {
    struct conntrack_bpf *skel;
    int err;
    const char *if1 = NULL;
    const char *if2 = NULL;
    int metadata_map_fd;

    // Disabled by default. 5 is the debug (max) level
    int log_level = 0;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('1', "iface1", &if1, "Interface to receive packet from", NULL, 0, 0),
        OPT_STRING('2', "iface2", &if2, "Interface to redirect packet to", NULL, 0, 0),
        OPT_INTEGER('l', "log_level", &log_level, "Log level", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse,
                      "\nThis software attaches an XDP program that emulates the behavior of Linux conntrack.\n", 
                      "The iface1 and iface2 arguments are used to specify the interfaces where to attach the program");
    argc = argparse_parse(&argparse, argc, argv);

    if (if1 != NULL) {
        log_info("XDP program will be attached to %s interface", if1);
        ifindex_if1 = if_nametoindex(if1);
        if (!ifindex_if1) {
            log_fatal("Error while retrieving the ifindex of %s", if1);
            exit(1);
        } else {
            log_info("Got ifindex for iface: %s, which is %d", if1, ifindex_if1);
        }
    } else {
        log_error("Error, you must specify the 1st interface where to attach the XDP program");
        exit(1);
    }

    if (if2 != NULL) {
        log_info("XDP program will be attached to %s interface", if2);
        ifindex_if2 = if_nametoindex(if2);
        if (!ifindex_if2) {
            log_fatal("Error while retrieving the ifindex of %s", if2);
            exit(1);
        } else {
            log_info("Got ifindex for iface: %s, which is %d", if2, ifindex_if2);
        }
    } else {
        log_error("Error, you must specify the 2nd interface where to attach the XDP program");
        exit(1);
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (log_level > 0) {
        /* Set up libbpf errors and debug info callback */
        libbpf_set_print(libbpf_print_fn);
    }

    /* Open BPF application */
    skel = conntrack_bpf__open();
    if (!skel) {
        log_error("Failed to open BPF skeleton");
        return 1;
    }

    // Setup config for this program
    skel->rodata->conntrack_cfg.log_level = log_level;
    skel->rodata->conntrack_cfg.if_index_if1 = ifindex_if1;
    skel->rodata->conntrack_cfg.if_index_if2 = ifindex_if2;

    bpf_program__set_type(skel->progs.xdp_conntrack_prog, BPF_PROG_TYPE_XDP);

    err = conntrack_bpf__load(skel);
    if (err) {
        log_error("Failed to load XDP program");
        goto cleanup;
    }

    metadata_map_fd = bpf_map__fd(skel->maps.metadata);
    connections_map_fd = bpf_map__fd(skel->maps.connections);

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &sigint_handler;

    if (sigaction(SIGINT, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    if (sigaction(SIGTERM, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;
    set_iface_up(if1);

    err = bpf_xdp_attach(ifindex_if1, bpf_program__fd(skel->progs.xdp_conntrack_prog), xdp_flags,
                         NULL);
    if (err) {
        log_error("Failed to attach XDP program on: %s", if1);
        goto cleanup;
    }

    set_iface_up(if2);
    err = bpf_xdp_attach(ifindex_if2, bpf_program__fd(skel->progs.xdp_conntrack_prog),
                            xdp_flags, NULL);
    if (err) {
        log_error("Failed to attach XDP program on: %s", if2);
        goto cleanup;
    }

    log_info("Successfully started!");

    sleep(1);
    poll_stats(metadata_map_fd, 1);

cleanup:
    cleanup_ifaces();
    bpf_object__close(skel->obj);
    conntrack_bpf__destroy(skel);
    return -err;
}

#ifndef __CONNTRACK_MAPS_H
#define __CONNTRACK_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdint.h>

#include "conntrack_structs.h"

#define CONNTRACK_MAP_MAX_SIZE 65536

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ct_k);
    __type(value, struct ct_v);
    __uint(max_entries, CONNTRACK_MAP_MAX_SIZE);
} connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct pkt_md);
    __uint(max_entries, 1);
} metadata SEC(".maps");

#endif // of __CONNTRACK_MAPS_H
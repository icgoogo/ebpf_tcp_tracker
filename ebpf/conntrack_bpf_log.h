#ifndef BPF_LOG_H_
#define BPF_LOG_H_

#include <stddef.h>
#include <string.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "conntrack_common.h"

#define DISABLED (0)
#define ERR (1)
#define WARNING (2)
#define NOTICE (3)
#define INFO (4)
#define DEBUG (5)

#define bpf_log_err(...) (conntrack_cfg.log_level < ERR ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_warning(...) (conntrack_cfg.log_level < WARNING ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_notice(...) (conntrack_cfg.log_level < NOTICE ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_info(...) (conntrack_cfg.log_level < INFO ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_debug(...) (conntrack_cfg.log_level < DEBUG ? (0) : bpf_printk(__VA_ARGS__))

#endif // BPF_LOG_H_
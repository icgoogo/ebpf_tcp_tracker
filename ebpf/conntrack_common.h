#ifndef CONNTRACK_COMMON_H_
#define CONNTRACK_COMMON_H_

#define IF_INDEX_IF1 1
#define IF_INDEX_IF2 2

#define CONNTRACK_DROP -1

#define FORCE_INLINE inline __attribute__((__always_inline__))

#include <stddef.h>
#include <stdint.h>
#include <linux/types.h>

#define ICMP_ECHOREPLY 0       /* Echo Reply			*/
#define ICMP_ECHO 8            /* Echo Request			*/
#define ICMP_TIMESTAMP 13      /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply		*/
#define ICMP_INFO_REQUEST 15   /* Information Request		*/
#define ICMP_INFO_REPLY 16     /* Information Reply		*/
#define ICMP_ADDRESS 17        /* Address Mask Request		*/
#define ICMP_ADDRESSREPLY 18   /* Address Mask Reply		*/

// ns
#define UDP_ESTABLISHED_TIMEOUT 180000000000
#define UDP_NEW_TIMEOUT 30000000000
#define ICMP_TIMEOUT 30000000000
#define TCP_ESTABLISHED 432000000000000
#define TCP_SYN_SENT 120000000000
#define TCP_SYN_RECV 60000000000
#define TCP_LAST_ACK 30000000000
#define TCP_FIN_WAIT 120000000000
#define TCP_TIME_WAIT 120000000000

#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_ACK 0x10

#define HEX_BE_ONE 0x1000000
#define MAX_UDP_HOPS 4

const volatile struct {
    __u8 log_level;
    __u32 if_index_if1;
    __u32 if_index_if2;
} conntrack_cfg = {};

typedef __u8 __attribute__((__may_alias__)) __u8_alias_t;
typedef __u16 __attribute__((__may_alias__)) __u16_alias_t;
typedef __u32 __attribute__((__may_alias__)) __u32_alias_t;
typedef __u64 __attribute__((__may_alias__)) __u64_alias_t;

#endif // CONNTRACK_COMMON_H_
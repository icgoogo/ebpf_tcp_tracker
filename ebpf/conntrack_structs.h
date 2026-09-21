#ifndef __CONNTRACK_STRUCTS_H
#define __CONNTRACK_STRUCTS_H

#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>

enum udp_conn_status {
    UDP_REQUEST = 1,     
    UDP_ESTABLISHED = 2,    
    UDP_EXPIRED = 3          
};

typedef enum {
    NEW,
    ESTABLISHED,
    RELATED,
    INVALID,
    SYN_SENT,
    SYN_RECV,
    FIN_WAIT_1,
    FIN_WAIT_2,
    LAST_ACK,
    TIME_WAIT
} conntrack_states_t;

struct packetHeaders {
    uint32_t srcIp;
    uint32_t dstIp;
    uint8_t l4proto;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t flags;
    uint32_t seqN;
    uint32_t ackN;
    uint8_t connStatus;
};

struct ct_k {
    uint32_t srcIp;
    uint32_t dstIp;
    uint8_t l4proto;
    uint16_t srcPort;
    uint16_t dstPort;
} __attribute__((packed));

struct ct_v {
    uint64_t ttl;
    uint8_t state;
    uint8_t ipRev;
    uint8_t portRev;
    uint32_t sequence;
    uint8_t hopCount;
    struct bpf_spin_lock lock;
};

struct pkt_md {
    uint64_t cnt;
    uint64_t bytes_cnt;
} __attribute__((packed));

struct icmphdr {
    u_int8_t type; /* message type */
    u_int8_t code; /* type sub-code */
    u_int16_t checksum;
    union {
        struct {
            u_int16_t id;
            u_int16_t sequence;
        } echo;            /* echo datagram */
        u_int32_t gateway; /* gateway address */
        struct {
            u_int16_t __unused;
            u_int16_t mtu;
        } frag; /* path mtu discovery */
    } un;
};

/*The struct defined in tcp.h lets flags be accessed only one by one,
 *it is not needed here.*/
struct tcp_hdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u8 res1 : 4, doff : 4;
    __u8 flags;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((packed));

struct _vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#endif // of __CONNTRACK_STRUCTS_H
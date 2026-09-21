#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/if_vlan.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "conntrack_structs.h"
#include "conntrack_maps.h"
#include "conntrack_bpf_log.h"
#include "conntrack_parser.h"

int my_pid = 0;

SEC("xdp")
int xdp_conntrack_prog(struct xdp_md *ctx) {
    int rc;
    struct packetHeaders pkt;
    __builtin_memset(&pkt, 0, sizeof(pkt));

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bpf_printk("Packet received from interface (ifindex) %d", ctx->ingress_ifindex);
    if (parse_packet(data, data_end, &pkt) < 0) {
        bpf_log_debug("Failed to parse packet\n");
        return XDP_DROP;
    }

    bpf_log_debug("Packet parsed, now starting the conntrack.\n");
    bpf_log_debug("[START] initial packet: \n"
                    "srcIp: %d, dstIp: %d, l4proto: %d, \n"
                    "srcport: %d, dstPort: %d, flags: %d, \n"
                    "seqN: 0x%08X, ackN: 0x%08X, connstatus: %d [END]", 
        pkt.srcIp, pkt.dstIp, pkt.l4proto, pkt.srcPort, pkt.dstPort, pkt.flags, pkt.seqN, pkt.ackN, pkt.connStatus);

    struct ct_k key;
    __builtin_memset(&key, 0, sizeof(key));
    uint8_t ipRev = 0;
    uint8_t portRev = 0;

    if (pkt.srcIp <= pkt.dstIp) {
        key.srcIp = pkt.srcIp;
        key.dstIp = pkt.dstIp;
        ipRev = 0;
    } else {
        key.srcIp = pkt.dstIp;
        key.dstIp = pkt.srcIp;
        ipRev = 1;
    }

    key.l4proto = pkt.l4proto;

    if (pkt.srcPort < pkt.dstPort) {
        key.srcPort = pkt.srcPort;
        key.dstPort = pkt.dstPort;
        portRev = 0;
    } else if (pkt.srcPort > pkt.dstPort) {
        key.srcPort = pkt.dstPort;
        key.dstPort = pkt.srcPort;
        portRev = 1;
    } else {
        key.srcPort = pkt.srcPort;
        key.dstPort = pkt.dstPort;
        portRev = ipRev;
    }

    struct ct_v newEntry;
    __builtin_memset(&newEntry, 0, sizeof(newEntry));
    struct ct_v *value;

    uint64_t timestamp;
    timestamp = bpf_ktime_get_ns();

    /* == UDP  == */
    if(pkt.l4proto == IPPROTO_UDP){
        value = bpf_map_lookup_elem(&connections, &key);
        if (value != NULL) {
            // Check for flow timeout
            if (timestamp > value->ttl || value->state == UDP_EXPIRED) {
                newEntry.state = UDP_REQUEST;
                newEntry.ttl = timestamp + UDP_NEW_TIMEOUT;
                newEntry.ipRev = ipRev;
                newEntry.portRev = portRev;
                newEntry.hopCount = 1;
                pkt.connStatus = NEW;

                bpf_log_debug("[UDP] flow expired, resetting\n");
                bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
                goto PASS_ACTION;
            }

            bpf_log_debug("[UDP] initial details: ttl: %d, status: %d, hopCount: %d\n", value->ttl, value->state, value->hopCount);
            bpf_spin_lock(&value->lock);

            if (value->hopCount >= MAX_UDP_HOPS) {
                pkt.connStatus = INVALID;
                bpf_spin_unlock(&value->lock);
                bpf_map_delete_elem(&connections, &key);
                bpf_log_err("[UDP]reaches MAX hops, dropping...\n");
                goto PASS_ACTION;
            }

            if ((value->ipRev != ipRev) && (value->portRev != portRev) ) {
                if (value->state == UDP_REQUEST) {
                        value->state = UDP_ESTABLISHED;
                } else if (value->state != UDP_ESTABLISHED) {
                    pkt.connStatus = INVALID;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_err("[UDP] suspicious packet in reverse direction, dropping...\n");
                    goto PASS_ACTION;            
                }
            } else if ((value->ipRev == ipRev) && (value->portRev == portRev) && (value->state == UDP_REQUEST || value->state == UDP_ESTABLISHED)) {
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[UDP] packet is still valid\n");
                bpf_spin_lock(&value->lock);
            } else { 
                pkt.connStatus = INVALID;
                bpf_spin_unlock(&value->lock);
                bpf_log_err("[UDP] suspicious packet, dropping...\n");
                goto PASS_ACTION;
            }

            value->hopCount++;
            value->ttl = timestamp + UDP_ESTABLISHED_TIMEOUT;

            bpf_spin_unlock(&value->lock);
            bpf_log_debug("[UDP] flow marked established\n");

            goto PASS_ACTION;
        } else {
            // New flow from client: supposed to be request-only
            newEntry.state = UDP_REQUEST;
            newEntry.ttl = timestamp + UDP_NEW_TIMEOUT;
            newEntry.ipRev = ipRev;
            newEntry.portRev = portRev; 
            newEntry.hopCount = 1;

            // bpf_spin_unlock(&value->lock);
            bpf_log_debug("[UDP]New packet detected\n");
            bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
            goto PASS_ACTION;
        }
    } else if (pkt.l4proto == IPPROTO_TCP) {
        /* == TCP  == */
        if ((pkt.flags & TCPHDR_RST) != 0) {
            bpf_map_delete_elem(&connections, &key);
            bpf_log_debug("Connection removed from tracking. Dropping...\n");
            goto DROP; 
        }

        value = bpf_map_lookup_elem(&connections, &key);
        if (value != NULL) {

            bpf_log_debug("state %d iprev %d port rev %d value sequence 0x%08X", value->state, value->ipRev, value->portRev, value->sequence);
            bpf_log_debug("iprev %d port rev %d", ipRev, portRev);

            bpf_spin_lock(&value->lock);
            if (timestamp > value->ttl) {
                bpf_spin_unlock(&value->lock);
                goto TCP_MISS;
            } else if ((value->ipRev == ipRev) && (value->portRev == portRev)) {
                goto TCP_FORWARD;
            } else if ((value->ipRev != ipRev) && (value->portRev != portRev)) {
                goto TCP_REVERSE;
            } else {
                bpf_spin_unlock(&value->lock);
                goto TCP_MISS;
            }

        TCP_FORWARD:;
            if (value->state == SYN_SENT) {
                //retries syn
                if(pkt.flags == TCPHDR_SYN) {
                    value->ttl = timestamp + TCP_SYN_SENT;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("SYN_SENT FW DIRECTION");
                    goto PASS_ACTION;
                } else {
                    pkt.connStatus = INVALID;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Failed ACK "
                                  "check in "
                                  "SYN_SENT state. Flags: %x\n",
                                  pkt.flags);
                    goto PASS_ACTION;
                }
            }

            if (value->state == SYN_RECV) {
                if (pkt.flags == TCPHDR_ACK && (pkt.ackN == value->sequence)) {                   
                    value->state = ESTABLISHED;
                    value->ttl = timestamp + TCP_ESTABLISHED;

                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Changing "
                                  "state from "
                                  "SYN_RECV to ESTABLISHED\n");

                    goto PASS_ACTION;
                } else {
                    pkt.connStatus = INVALID;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW_DIRECTION] Failed ACK "
                                  "check in "
                                  "SYN_RECV state. Flags: %x\n",
                                  pkt.flags);
                    goto PASS_ACTION;
                }
            }

            if (value->state == ESTABLISHED) {
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[TCP] Connnection is ESTABLISHED. FW direction\n");
                goto TCP_ESTABLISHED_STATE;
            }

            if (value->state == FIN_WAIT_1) {
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[TCP] FIN_WAIT_1 FW direction\n");
                goto TCP_FIN_WAIT_ONE_STATE;
                
            }

            if (value->state == FIN_WAIT_2) {
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[TCP] FIN_WAIT_2 FW direction\n");
                goto TCP_FIN_WAIT_TWO_STATE;
            }

            if (value->state == LAST_ACK) {
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[TCP] LAST_ACK REV direction\n");
                goto TCP_LAST_ACK_STATE;
            }

            if (value->state == TIME_WAIT) {
                if (pkt.connStatus == NEW) {
                    bpf_spin_unlock(&value->lock);
                    goto TCP_MISS;
                } else {
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[FW TIME_WAIT] connstatus %d", pkt.connStatus);
                    goto PASS_ACTION;
                }
            }

            pkt.connStatus = INVALID;
            bpf_spin_unlock(&value->lock);
            bpf_log_debug("[FW_DIRECTION] Should not get here. "
                          "Flags: %x. State: %d. \n",
                          pkt.flags, value->state);
            goto PASS_ACTION;

        TCP_REVERSE:;
            if (value->state == SYN_SENT) {
                if (pkt.flags == TCPHDR_ACK+TCPHDR_SYN && pkt.ackN == value->sequence + HEX_BE_ONE) {
                    value->state = SYN_RECV;
                    value->ttl = timestamp + TCP_SYN_RECV;
                    value->sequence = pkt.seqN + HEX_BE_ONE;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION] Changing "
                                  "state from "
                                  "SYN_SENT to SYN_RECV\n");

                    goto PASS_ACTION;
                }
                pkt.connStatus = INVALID;
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[REV_DIRECTION] Failed "
                                  "state from "
                                  "SYN_SENT to SYN_RECV\n");
                bpf_log_debug("connstatus %d", pkt.connStatus);
                goto PASS_ACTION;
            }

            if (value->state == SYN_RECV) {
                if ((pkt.flags & (TCPHDR_SYN | TCPHDR_ACK)) == (TCPHDR_SYN | TCPHDR_ACK)) {
                    value->ttl = timestamp + TCP_SYN_RECV;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV_DIRECTION]"
                                  "state "
                                  "SYN_RECV SYN+ACK retransmission Seq: 0x%08X\n",
                                  value->sequence);
                    goto PASS_ACTION;
                }
                pkt.connStatus = INVALID;
                bpf_spin_unlock(&value->lock);
                
                goto PASS_ACTION;
            }

            if (value->state == ESTABLISHED) {
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[TCP] Connnection is ESTABLISHED. Rev direction\n");
                goto TCP_ESTABLISHED_STATE;
            }

            if (value->state == FIN_WAIT_1) {
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[TCP] FIN_WAIT_1 REV direction\n");
                goto TCP_FIN_WAIT_ONE_STATE;
            }

            if (value->state == FIN_WAIT_2) {
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[TCP] FIN_WAIT_2 REV direction\n");
                goto TCP_FIN_WAIT_TWO_STATE;
            }

            if (value->state == LAST_ACK) {
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[TCP] LAST_ACK REV direction\n");
                goto TCP_LAST_ACK_STATE;
            }

            if (value->state == TIME_WAIT) {
                if (pkt.connStatus == NEW) {
                    bpf_spin_unlock(&value->lock);
                    goto TCP_MISS;
                } else {
                    // Let the packet go, but do not update timers.
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("[REV TIME_WAIT] connstatus %d", pkt.connStatus);
                    goto PASS_ACTION;
                }
            }

            pkt.connStatus = INVALID;
            bpf_spin_unlock(&value->lock);
            bpf_log_debug("[REV_DIRECTION] Should not get here. "
                          "Flags: %d. "
                          "State: %d. \n",
                          pkt.flags, value->state);
            goto PASS_ACTION;

        TCP_ESTABLISHED_STATE:;
            bpf_spin_lock(&value->lock);
            if ((pkt.flags & TCPHDR_FIN) != 0) {
                // initiates the closing
                value->state = FIN_WAIT_1;
                value->ttl = timestamp + TCP_FIN_WAIT;
                value->sequence = pkt.seqN;

                bpf_spin_unlock(&value->lock);
                bpf_log_debug("[TCP] Changing "
                                "state from "
                                "ESTABLISHED to FIN_WAIT_1. Seq: 0x%08X\n",
                                value->sequence);

                goto PASS_ACTION;
            } else {
                // maybe just handshake of accepting data, pass it
                value->ttl = timestamp + TCP_ESTABLISHED;
                bpf_spin_unlock(&value->lock);
                goto PASS_ACTION;
            }

        TCP_FIN_WAIT_ONE_STATE:;
            bpf_spin_lock(&value->lock);
            if ((pkt.flags & TCPHDR_ACK) != 0) {
                if (pkt.ackN == value->sequence + HEX_BE_ONE) {
                    value->state = FIN_WAIT_2;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("Changing "
                                "state from "
                                "FIN_WAIT_1 to FIN_WAIT_2\n");
                    goto PASS_ACTION;
                } else if ((pkt.flags & TCPHDR_FIN) != 0) {
                    value->state = LAST_ACK;
                    value->ttl = timestamp + TCP_FIN_WAIT;
                    value->sequence = pkt.seqN;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("Changing "
                                    "state from "
                                    "FIN_WAIT_1 to LAST_ACK\n");

                    goto PASS_ACTION;
                }

                bpf_spin_unlock(&value->lock);
                bpf_log_debug("Failed FIN or ACK "
                                "check in "
                                "FIN_WAIT_1 state. Flags: %x. AckSeq: 0x%08X\n",
                                pkt.flags, pkt.ackN);
                goto PASS_ACTION;
            } else {
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("Failed ACK "
                                "check in "
                                "FIN_WAIT_1 state. Flags: %x. AckSeq: 0x%08X\n",
                                pkt.flags, pkt.ackN);
                goto PASS_ACTION;
            }

        TCP_FIN_WAIT_TWO_STATE:;
            bpf_spin_lock(&value->lock);
            if ((pkt.flags & TCPHDR_FIN) != 0) {
                value->state = LAST_ACK;
                value->ttl = timestamp + TCP_FIN_WAIT;
                value->sequence = pkt.seqN;
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("Changing "
                                "state from "
                                "FIN_WAIT_2 to LAST_ACK\n");

                goto PASS_ACTION;
            } else {
                value->ttl = timestamp + TCP_FIN_WAIT;
                bpf_spin_unlock(&value->lock);
                bpf_log_debug("Failed FIN "
                                "check in "
                                "FIN_WAIT_2 state. Flags: %d. Seq: 0x%08X\n",
                                pkt.flags, value->sequence);

                goto PASS_ACTION;
            }
        
        TCP_LAST_ACK_STATE:;
            bpf_spin_lock(&value->lock);
            if ((pkt.flags & TCPHDR_ACK) != 0 && pkt.ackN == value->sequence + HEX_BE_ONE) {
                    value->state = TIME_WAIT;
                    //set 2 MSL for TIME_WAIT state
                    value->ttl = timestamp + 2 * TCP_TIME_WAIT;
                    bpf_spin_unlock(&value->lock);
                    bpf_log_debug("Changing "
                                  "state from "
                                  "LAST_ACK to TIME_WAIT\n");

                    goto PASS_ACTION;
                }
            // Still receiving packets
            value->ttl = timestamp + TCP_LAST_ACK;
            bpf_spin_unlock(&value->lock);
            goto PASS_ACTION;
        }

    TCP_MISS:;
        if ((pkt.flags & TCPHDR_SYN) != 0) {
            newEntry.state = SYN_SENT;
            newEntry.ttl = timestamp + TCP_SYN_SENT;
            newEntry.sequence = pkt.seqN;

            newEntry.ipRev = ipRev;
            newEntry.portRev = portRev;
            pkt.connStatus = NEW;
            bpf_log_debug("[TCP] TCP_MISS new incoming packet %d\n", pkt.flags);

            bpf_map_update_elem(&connections, &key, &newEntry, BPF_ANY);
            goto PASS_ACTION;
        } else if (value != NULL && value->state == TIME_WAIT) {
            // Check if the connection has been in TIME_WAIT for 2 * MSL 
            if (timestamp > value->ttl) { 
                pkt.connStatus = INVALID;
                bpf_map_delete_elem(&connections, &key);
                bpf_log_debug("[TCP] Packet expired, dropping...");
            } else {
                bpf_log_debug("[TCP] Packet still waiting to drop, pass it");
            }
            
            goto PASS_ACTION;
        } else {
            // Unexpected packet, drop this
            bpf_log_debug("[TCP] TCP_MISS unexpected packet, dropping... %d\n", pkt.flags);
            goto DROP;
        }
    }

PASS_ACTION:;
    int status = pkt.connStatus;

    bpf_log_debug("status after pass_action %d", status);
    struct pkt_md *md;
    __u32 md_key = 0;
    // get metadata
    md = bpf_map_lookup_elem(&metadata, &md_key);
    if (md == NULL) {
        bpf_log_err("No elements found in metadata map\n");
        goto DROP;
    }

    uint16_t pkt_len = (uint16_t)(data_end - data);

    //increment metadata for valid packets
    __sync_fetch_and_add(&md->cnt, 1);
    __sync_fetch_and_add(&md->bytes_cnt, pkt_len);
    if (status == INVALID) {
        bpf_log_err("Connection status is invalid\n");
        goto DROP;
    }

    if (ctx->ingress_ifindex == conntrack_cfg.if_index_if1) {
        bpf_log_debug("Redirect pkt to IF2 iface with ifindex: %d\n", conntrack_cfg.if_index_if2);
        return bpf_redirect(conntrack_cfg.if_index_if2, 0);
    } else if (ctx->ingress_ifindex == conntrack_cfg.if_index_if2) {
        bpf_log_debug("Redirect pkt to IF1 iface with ifindex: %d\n", conntrack_cfg.if_index_if1);
        return bpf_redirect(conntrack_cfg.if_index_if1, 0);
    } else {
        bpf_log_err("Unknown interface. Dropping packet\n");
        goto DROP;
    }

DROP:;
    bpf_log_debug("Dropping packet!\n");
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
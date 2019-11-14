//
// Created by postolka on 1.7.19.
//

#ifndef DPDK_TCP_GENERATOR_CONN_H
#define DPDK_TCP_GENERATOR_CONN_H

#include <stdint.h>

void tcp4_open(unsigned portid, struct app_config *app_config);
void tcp6_open(unsigned portid, struct app_config *app_config);
void handle_incoming(struct rte_mbuf *m, unsigned portid, struct app_config *app_config);

#define MAC_ADDR_XOR(addr1, addr2) \
do { \
    *((uint64_t *)(addr1)) ^= *((uint64_t *)(addr2)) & 0x0000FFFFFFFFFFFF; \
} while (0)

#define IPv6_ADDR_XOR(addr1, addr2) \
do { \
    *((uint64_t *)(addr1)) ^= *((uint64_t *)(addr2)); \
    *((uint64_t *)((addr1) + 8)) ^= *((uint64_t *)((addr2) + 8)); \
} while (0)

#define IP4_SYN_MBUF_DATALEN ( \
    sizeof(struct ether_hdr) + \
    sizeof(struct ipv4_hdr) + \
    sizeof(struct tcp_hdr) )
#define IP6_SYN_MBUF_DATALEN ( \
    sizeof(struct ether_hdr) + \
    sizeof(struct ipv6_hdr) + \
    sizeof(struct tcp_hdr) )
#define IP4_ACK_MBUF_DATALEN IP4_SYN_MBUF_DATALEN
#define IP6_ACK_MBUF_DATALEN IP6_SYN_MBUF_DATALEN
#define IP4_MIN_PKT_LEN IP4_SYN_MBUF_DATALEN
#define IP6_MIN_PKT_LEN IP6_SYN_MBUF_DATALEN
#define MIN_PKT_LEN IP4_MIN_PKT_LEN
#define IP4_DNS_PACKET_MIN_LEN (IP4_MIN_PKT_LEN + sizeof(struct dns_hdr))
#define IP6_DNS_PACKET_MIN_LEN (IP6_MIN_PKT_LEN + sizeof(struct dns_hdr))

#endif //DPDK_TCP_GENERATOR_CONN_H

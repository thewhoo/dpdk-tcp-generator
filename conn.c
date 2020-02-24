/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Brno University of Technology
 *
 * tcpgen - a simple DPDK TCP DNS traffic generator
 * Author: Matej Postolka <xposto02@stud.fit.vutbr.cz>
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "dns.h"
#include "pcap.h"
#include "common.h"
#include "wyrand.h"
#include "conn.h"

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
#define IP4_UDP_MBUF_DATALEN ( \
    sizeof(struct ether_hdr) + \
    sizeof(struct ipv4_hdr) + \
    sizeof(struct udp_hdr) )
#define IP6_UDP_MBUF_DATALEN ( \
    sizeof(struct ether_hdr) + \
    sizeof(struct ipv6_hdr) + \
    sizeof(struct udp_hdr) )

#define IP4_ACK_MBUF_DATALEN IP4_SYN_MBUF_DATALEN
#define IP6_ACK_MBUF_DATALEN IP6_SYN_MBUF_DATALEN
#define IP4_MIN_TCP_PKT_LEN IP4_SYN_MBUF_DATALEN
#define IP6_MIN_TCP_PKT_LEN IP6_SYN_MBUF_DATALEN
#define IP4_MIN_UDP_PKT_LEN (IP4_UDP_MBUF_DATALEN + sizeof(struct dns_hdr))
#define IP6_MIN_UDP_PKT_LEN (IP6_UDP_MBUF_DATALEN + sizeof(struct dns_hdr))
#define IP4_MIN_PKT_LEN IP4_MIN_UDP_PKT_LEN
#define IP6_MIN_PKT_LEN IP6_MIN_UDP_PKT_LEN
#define MIN_PKT_LEN IP4_MIN_PKT_LEN
#define IP4_TCP_DNS_PACKET_MIN_LEN (IP4_MIN_TCP_PKT_LEN + sizeof(struct tcp_dns_hdr))
#define IP6_TCP_DNS_PACKET_MIN_LEN (IP6_MIN_TCP_PKT_LEN + sizeof(struct tcp_dns_hdr))
#define IP4_UDP_DNS_PACKET_MIN_LEN IP4_MIN_UDP_PKT_LEN
#define IP6_UDP_DNS_PACKET_MIN_LEN IP6_MIN_UDP_PKT_LEN

#define MBUF_HAS_MIN_TCP_DNS_LEN(ether_type, data_len) ( \
        ((ether_type) == ETHER_TYPE_IPv4 && (data_len) >= IP4_TCP_DNS_PACKET_MIN_LEN) || \
        ((ether_type) == ETHER_TYPE_IPv6 && (data_len) >= IP6_TCP_DNS_PACKET_MIN_LEN) )
#define MBUF_HAS_MIN_UDP_DNS_LEN(ether_type, data_len) ( \
        ((ether_type) == ETHER_TYPE_IPv4 && (data_len) >= IP4_UDP_DNS_PACKET_MIN_LEN) || \
        ((ether_type) == ETHER_TYPE_IPv6 && (data_len) >= IP6_UDP_DNS_PACKET_MIN_LEN) )

#define ETHER_FRAME_MIN_LEN 60
#define ETHER_FRAME_L1_EXTRA_BYTES 24

static void send_ack(struct rte_mbuf *m, unsigned portid, uint16_t queue_id, struct app_config *app_config, bool fin);

static void generate_tcp_query(struct rte_mbuf *m, unsigned portid, uint16_t queue_id, struct app_config *app_config);

static struct rte_mbuf *mbuf_clone(struct rte_mbuf *m, const struct app_config *app_config);

static void response_classify(struct app_config *app_config, const struct dns_hdr *dns_hdr);

static void init_ether_hdr(const struct app_config *app_config, struct ether_hdr *eth, uint16_t type);

static void
init_ip4_hdr(const struct app_config *app_config, struct ipv4_hdr *ip, uint16_t total_len, uint8_t next_proto);

static void
init_ip6_hdr(const struct app_config *app_config, struct ipv6_hdr *ip, uint16_t payload_len, uint8_t next_proto);

static inline void emplace_pcap_payload(struct app_config *app_config, struct rte_mbuf *m, bool include_len);

static inline void init_ether_hdr(const struct app_config *app_config, struct ether_hdr *eth, uint16_t type) {
    memcpy(eth->d_addr.addr_bytes, app_config->user_config.dst_mac, ETHER_ADDR_LEN);
    memcpy(eth->s_addr.addr_bytes, app_config->user_config.src_mac, ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(type);
}

static inline void
init_ip4_hdr(const struct app_config *app_config, struct ipv4_hdr *ip, uint16_t total_len, uint8_t next_proto) {
    uint32_t src_ip_rand_bits;
    do {
        src_ip_rand_bits = wyrand() & app_config->user_config.ip4_src_rand_bit_mask;
    }
        // Eliminate network and broadcast addrs
    while (unlikely(src_ip_rand_bits == 0 || src_ip_rand_bits == app_config->user_config.ip4_src_rand_bit_mask));

    ip->version_ihl = 0x45; // Version 4 HL 20 (multiplier 5)
    ip->type_of_service = 0;
    ip->total_length = rte_cpu_to_be_16(total_len);
    ip->packet_id = 0;
    ip->fragment_offset = rte_cpu_to_be_16(0x4000); // Don't fragment flag set
    ip->time_to_live = 64;
    ip->next_proto_id = next_proto;
    ip->hdr_checksum = 0;
    ip->src_addr = *(const uint32_t *) app_config->user_config.ip4_src_subnet | rte_cpu_to_be_32(src_ip_rand_bits);
    ip->dst_addr = *(const uint32_t *) app_config->user_config.ip4_dst_addr;

    ip->hdr_checksum = rte_ipv4_cksum(ip);
}

static inline void
init_ip6_hdr(const struct app_config *app_config, struct ipv6_hdr *ip, uint16_t payload_len, uint8_t next_proto) {
    uint64_t src_ip_rand_bits[2];
    do {
        src_ip_rand_bits[0] = wyrand() & app_config->user_config.ip6_src_rand_bit_mask[0];
        src_ip_rand_bits[1] = wyrand() & app_config->user_config.ip6_src_rand_bit_mask[1];
    }
        // Eliminate network and broadcast addrs
    while (unlikely(
            memcmp(src_ip_rand_bits, app_config->user_config.ip6_src_rand_bit_mask, IPv6_ADDR_LEN) == 0 ||
            (src_ip_rand_bits[0] == 0 && src_ip_rand_bits[1] == 0)));

    ip->vtc_flow = rte_cpu_to_be_32(0x60000000); // version 6 + no flow id
    ip->payload_len = rte_cpu_to_be_16(payload_len);
    ip->proto = next_proto;
    ip->hop_limits = 64;
    *(uint64_t *) &ip->src_addr[0] =
            *(const uint64_t *) &app_config->user_config.ip6_src_subnet[0] | rte_cpu_to_be_64(src_ip_rand_bits[0]);
    *(uint64_t *) &ip->src_addr[8] =
            *(const uint64_t *) &app_config->user_config.ip6_src_subnet[8] | rte_cpu_to_be_64(src_ip_rand_bits[1]);
    memcpy(ip->dst_addr, app_config->user_config.ip6_dst_addr, IPv6_ADDR_LEN);
}

static inline void emplace_pcap_payload(struct app_config *app_config, struct rte_mbuf *m, bool include_len) {
    unsigned lcore_id = rte_lcore_id();

    const struct pcap_list_entry *ref_pcap = pcap_list_get(&app_config->pcap_lists[lcore_id]);
    // Move forward in PCAP list
    pcap_list_next(&app_config->pcap_lists[lcore_id]);

    // Emplace PCAP payload at end of mbuf
    if (include_len) {
        memcpy(rte_pktmbuf_mtod_offset(m, void *, m->data_len), ref_pcap->pcap_payload, ref_pcap->payload_len);
        m->pkt_len = m->data_len = m->data_len + ref_pcap->payload_len;
    } else {
        // Skip length word
        memcpy(rte_pktmbuf_mtod_offset(m, void *, m->data_len), ref_pcap->pcap_payload + 2, ref_pcap->payload_len - 2);
        m->pkt_len = m->data_len = m->data_len + ref_pcap->payload_len - 2;
    }
}

void generate_udp4_query(unsigned portid, uint16_t queue_id, struct app_config *app_config) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(app_config->dpdk_config.pktmbuf_pool);
    if (m == NULL) {
        RTE_LOG(CRIT, TCPGEN, "generate_udp4_query: failed to allocate mbuf for new tcp connection\n");
        rte_exit(EXIT_FAILURE, "mbuf allocation failed");
    }

    m->pkt_len = m->data_len = IP4_UDP_MBUF_DATALEN;

    // Emplace PCAP payload at end of mbuf
    emplace_pcap_payload(app_config, m, false);

    // Initialize L2 header
    struct ether_hdr *eth = mbuf_eth_ptr(m);
    init_ether_hdr(app_config, eth, ETHER_TYPE_IPv4);

    // Initialize L3 header
    struct ipv4_hdr *ip = mbuf_ip4_ip_ptr(m);
    // IPv4 total packet len without L2 header
    init_ip4_hdr(app_config, ip, m->data_len - sizeof(struct ether_hdr), IPPROTO_UDP);

    // Initialize L4 header
    struct udp_hdr *udp = mbuf_ip4_udp_ptr(m);
    udp->src_port = wyrand();
    udp->dst_port = rte_cpu_to_be_16(app_config->user_config.dst_port);
    udp->dgram_len = rte_cpu_to_be_16(m->data_len - sizeof(struct ether_hdr) - sizeof(struct ipv4_hdr));
    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

    // Update counters
    app_config->lcore_stats[rte_lcore_id()].tx_bytes +=
            RTE_MAX(m->data_len, ETHER_FRAME_MIN_LEN) + ETHER_FRAME_L1_EXTRA_BYTES; // L1 rate
    app_config->lcore_stats[rte_lcore_id()].tx_packets++;
    app_config->lcore_stats[rte_lcore_id()].tx_queries++;

    // Send
    rte_eth_tx_burst(portid, queue_id, &m, 1);
}

void generate_udp6_query(unsigned portid, uint16_t queue_id, struct app_config *app_config) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(app_config->dpdk_config.pktmbuf_pool);
    if (m == NULL) {
        RTE_LOG(CRIT, TCPGEN, "generate_udp4_query: failed to allocate mbuf for new tcp connection\n");
        rte_exit(EXIT_FAILURE, "mbuf allocation failed");
    }

    m->pkt_len = m->data_len = IP6_UDP_MBUF_DATALEN;

    // Emplace PCAP payload at end of mbuf
    emplace_pcap_payload(app_config, m, false);

    // Initialize L2 header
    struct ether_hdr *eth = mbuf_eth_ptr(m);
    init_ether_hdr(app_config, eth, ETHER_TYPE_IPv6);

    // Initialize L3 header
    struct ipv6_hdr *ip = mbuf_ip6_ip_ptr(m);
    // IPv4 total packet len without L2 header
    init_ip6_hdr(app_config, ip, m->data_len - sizeof(struct ether_hdr) - sizeof(struct ipv6_hdr), IPPROTO_UDP);

    // Initialize L4 header
    struct udp_hdr *udp = mbuf_ip6_udp_ptr(m);
    udp->src_port = wyrand();
    udp->dst_port = rte_cpu_to_be_16(app_config->user_config.dst_port);
    udp->dgram_len = rte_cpu_to_be_16(m->data_len - sizeof(struct ether_hdr) - sizeof(struct ipv6_hdr));
    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv6_udptcp_cksum(ip, udp);

    // Update counters
    app_config->lcore_stats[rte_lcore_id()].tx_bytes += m->data_len + ETHER_FRAME_L1_EXTRA_BYTES; // L1 rate
    app_config->lcore_stats[rte_lcore_id()].tx_packets++;
    app_config->lcore_stats[rte_lcore_id()].tx_queries++;

    // Send
    rte_eth_tx_burst(portid, queue_id, &m, 1);
}

// Open new IPv4 TCP connection
void tcp4_open(unsigned portid, uint16_t queue_id, struct app_config *app_config) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(app_config->dpdk_config.pktmbuf_pool);
    if (m == NULL) {
        RTE_LOG(CRIT, TCPGEN, "tcp4_open: failed to allocate mbuf for new tcp connection\n");
        rte_exit(EXIT_FAILURE, "mbuf allocation failed");
    }

    m->pkt_len = m->data_len = IP4_SYN_MBUF_DATALEN;

    // Initialize L2 header
    struct ether_hdr *eth = mbuf_eth_ptr(m);
    init_ether_hdr(app_config, eth, ETHER_TYPE_IPv4);

    // Initialize L3 header
    struct ipv4_hdr *ip = mbuf_ip4_ip_ptr(m);
    init_ip4_hdr(app_config, ip, m->data_len - sizeof(struct ether_hdr), IPPROTO_TCP);

    // Initialize L4 header
    struct tcp_hdr *tcp = mbuf_ip4_tcp_ptr(m);
    tcp->src_port = wyrand();
    tcp->dst_port = rte_cpu_to_be_16(app_config->user_config.dst_port);
    tcp->sent_seq = 0;
    tcp->recv_ack = 0;
    tcp->data_off = 0x50; // 20 byte (5 * 4) header
    tcp->tcp_flags = 0x02; // SYN flag
    tcp->rx_win = rte_cpu_to_be_16(0xfaf0);
    tcp->tcp_urp = 0;
    tcp->cksum = 0;
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

    // Update counters
    app_config->lcore_stats[rte_lcore_id()].tx_bytes += ETHER_FRAME_MIN_LEN + ETHER_FRAME_L1_EXTRA_BYTES; // L1 rate
    app_config->lcore_stats[rte_lcore_id()].tx_packets++;

    // Send
    rte_eth_tx_burst(portid, queue_id, &m, 1);
}

// Open new IPv6 TCP connection
void tcp6_open(unsigned portid, uint16_t queue_id, struct app_config *app_config) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(app_config->dpdk_config.pktmbuf_pool);
    if (m == NULL) {
        RTE_LOG(CRIT, TCPGEN, "tcp6_open: failed to allocate mbuf for new tcp connection\n");
        rte_exit(EXIT_FAILURE, "mbuf allocation failed");
    }

    m->pkt_len = m->data_len = IP6_SYN_MBUF_DATALEN;

    // Initialize L2 header
    struct ether_hdr *eth = mbuf_eth_ptr(m);
    init_ether_hdr(app_config, eth, ETHER_TYPE_IPv6);

    // Initialize L3 header
    struct ipv6_hdr *ip = mbuf_ip6_ip_ptr(m);
    init_ip6_hdr(app_config, ip, m->data_len - sizeof(struct ether_hdr) - sizeof(struct ipv6_hdr), IPPROTO_TCP);

    // Initialize L4 header
    struct tcp_hdr *tcp = mbuf_ip6_tcp_ptr(m);
    tcp->src_port = wyrand();
    tcp->dst_port = rte_cpu_to_be_16(app_config->user_config.dst_port);
    tcp->sent_seq = 0;
    tcp->recv_ack = 0;
    tcp->data_off = 0x50; // 20 byte (5 * 4) header
    tcp->tcp_flags = 0x02; // SYN flag
    tcp->rx_win = rte_cpu_to_be_16(0xfaf0);
    tcp->tcp_urp = 0;
    tcp->cksum = 0;
    tcp->cksum = rte_ipv6_udptcp_cksum(ip, tcp);

    // Update counters
    app_config->lcore_stats[rte_lcore_id()].tx_bytes += m->data_len + ETHER_FRAME_L1_EXTRA_BYTES; // L1 rate
    app_config->lcore_stats[rte_lcore_id()].tx_packets++;

    // Send
    rte_eth_tx_burst(portid, queue_id, &m, 1);
}

static void send_ack(struct rte_mbuf *m, unsigned portid, uint16_t queue_id, struct app_config *app_config, bool fin) {
    // Pointers to headers
    struct ether_hdr *eth_hdr = mbuf_eth_ptr(m);
    struct ipv4_hdr *ip4_hdr = NULL;
    struct ipv6_hdr *ip6_hdr = NULL;
    struct tcp_hdr *tcp_hdr = NULL;

    int16_t payload_len;

    // Swap MAC addresses
    MAC_ADDR_XOR(eth_hdr->d_addr.addr_bytes, eth_hdr->s_addr.addr_bytes);
    MAC_ADDR_XOR(eth_hdr->s_addr.addr_bytes, eth_hdr->d_addr.addr_bytes);
    MAC_ADDR_XOR(eth_hdr->d_addr.addr_bytes, eth_hdr->s_addr.addr_bytes);

    uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
    if (ether_type == ETHER_TYPE_IPv4) {
        ip4_hdr = mbuf_ip4_ip_ptr(m);
        tcp_hdr = mbuf_ip4_tcp_ptr(m);

        // Original payload length
        payload_len = rte_be_to_cpu_16(ip4_hdr->total_length) - sizeof(struct ipv4_hdr) - (tcp_hdr->data_off >> 2);

        // Swap IP addresses
        ip4_hdr->src_addr ^= ip4_hdr->dst_addr;
        ip4_hdr->dst_addr ^= ip4_hdr->src_addr;
        ip4_hdr->src_addr ^= ip4_hdr->dst_addr;

        ip4_hdr->packet_id = 0;
        ip4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
        ip4_hdr->hdr_checksum = 0;

        m->pkt_len = m->data_len = IP4_ACK_MBUF_DATALEN;
    } else if (ether_type == ETHER_TYPE_IPv6) {
        ip6_hdr = mbuf_ip6_ip_ptr(m);
        tcp_hdr = mbuf_ip6_tcp_ptr(m);

        // Original payload length
        payload_len = rte_be_to_cpu_16(ip6_hdr->payload_len) - (tcp_hdr->data_off >> 2);

        // Swap IP addresses
        IPv6_ADDR_XOR(ip6_hdr->src_addr, ip6_hdr->dst_addr);
        IPv6_ADDR_XOR(ip6_hdr->dst_addr, ip6_hdr->src_addr);
        IPv6_ADDR_XOR(ip6_hdr->src_addr, ip6_hdr->dst_addr);

        ip6_hdr->payload_len = rte_cpu_to_be_16(sizeof(struct tcp_hdr));

        m->pkt_len = m->data_len = IP6_ACK_MBUF_DATALEN;
    } else {
        RTE_LOG(CRIT, TCPGEN, "invalid packet ether_type in send_ack\n");
        rte_pktmbuf_free(m);
        return;
    }

    // Update TCP header
    tcp_hdr->src_port ^= tcp_hdr->dst_port;
    tcp_hdr->dst_port ^= tcp_hdr->src_port;
    tcp_hdr->src_port ^= tcp_hdr->dst_port;

    tcp_hdr->sent_seq ^= tcp_hdr->recv_ack;
    tcp_hdr->recv_ack ^= tcp_hdr->sent_seq;
    tcp_hdr->sent_seq ^= tcp_hdr->recv_ack;

    if (payload_len > 0)
        tcp_hdr->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->recv_ack) + payload_len);
    else
        tcp_hdr->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->recv_ack) + 1); // ACK sender's seq +1

    tcp_hdr->tcp_flags = 0x10; // set ACK
    if (fin)
        tcp_hdr->tcp_flags |= 0x01;

    tcp_hdr->data_off = 0x50; // 20 byte (5 * 4) header
    tcp_hdr->cksum = 0;

    // Update cksums and counters
    app_config->lcore_stats[rte_lcore_id()].tx_packets++;
    if (ether_type == ETHER_TYPE_IPv4) {
        ip4_hdr->hdr_checksum = rte_ipv4_cksum(ip4_hdr);
        tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ip4_hdr, tcp_hdr);
        app_config->lcore_stats[rte_lcore_id()].tx_bytes += ETHER_FRAME_MIN_LEN + ETHER_FRAME_L1_EXTRA_BYTES;
    } else {
        tcp_hdr->cksum = rte_ipv6_udptcp_cksum(ip6_hdr, tcp_hdr);
        app_config->lcore_stats[rte_lcore_id()].tx_bytes += m->data_len + ETHER_FRAME_L1_EXTRA_BYTES;
    }

    // Send
    rte_eth_tx_burst(portid, queue_id, &m, 1);
}

static void generate_tcp_query(struct rte_mbuf *m, unsigned portid, uint16_t queue_id, struct app_config *app_config) {
    // Emplace PCAP payload after reference SYN/ACK mbuf
    emplace_pcap_payload(app_config, m, true);

    // Pointers to headers
    struct ether_hdr *eth_hdr = mbuf_eth_ptr(m);
    struct ipv4_hdr *ip4_hdr = NULL;
    struct ipv6_hdr *ip6_hdr = NULL;
    struct tcp_hdr *tcp_hdr = NULL;

    uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    if (ether_type == ETHER_TYPE_IPv4) {
        ip4_hdr = mbuf_ip4_ip_ptr(m);
        tcp_hdr = mbuf_ip4_tcp_ptr(m);

        ip4_hdr->total_length = rte_cpu_to_be_16(m->data_len - sizeof(struct ether_hdr));
        ip4_hdr->hdr_checksum = 0;
    } else if (ether_type == ETHER_TYPE_IPv6) {
        ip6_hdr = mbuf_ip6_ip_ptr(m);
        tcp_hdr = mbuf_ip6_tcp_ptr(m);

        ip6_hdr->payload_len = rte_cpu_to_be_16(m->data_len - sizeof(struct ether_hdr) - sizeof(struct ipv6_hdr));
    } else {
        RTE_LOG(CRIT, TCPGEN, "generate_tcp_query: invalid ether_type\n");
        rte_pktmbuf_free(m);
        return;
    }

    tcp_hdr->tcp_flags = 0x18; // ACK + PSH
    tcp_hdr->cksum = 0;

    if (ether_type == ETHER_TYPE_IPv4) {
        ip4_hdr->hdr_checksum = rte_ipv4_cksum(ip4_hdr);
        tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ip4_hdr, tcp_hdr);
    } else {
        tcp_hdr->cksum = rte_ipv6_udptcp_cksum(ip6_hdr, tcp_hdr);
    }

    app_config->lcore_stats[rte_lcore_id()].tx_bytes += m->data_len + ETHER_FRAME_L1_EXTRA_BYTES;
    app_config->lcore_stats[rte_lcore_id()].tx_packets++;
    app_config->lcore_stats[rte_lcore_id()].tx_queries++;

    // Send
    rte_eth_tx_burst(portid, queue_id, &m, 1);
}

static struct rte_mbuf *mbuf_clone(struct rte_mbuf *m, const struct app_config *app_config) {
    struct rte_mbuf *clone = rte_pktmbuf_alloc(app_config->dpdk_config.pktmbuf_pool);
    if (clone == NULL)
        rte_exit(EXIT_FAILURE, "mbuf clone: mbuf alloc failed\n");

    clone->pkt_len = clone->data_len = m->data_len;
    rte_memcpy(rte_pktmbuf_mtod(clone, void *), rte_pktmbuf_mtod(m, const void *), m->data_len);

    return clone;
}

static inline void response_classify(struct app_config *app_config, const struct dns_hdr *dns_hdr) {
    uint8_t rcode = rte_be_to_cpu_16(dns_hdr->flags) & 0xf;
    app_config->lcore_stats[rte_lcore_id()].rx_rcode[rcode]++;
}

// Incoming packet handler
void handle_incoming(struct rte_mbuf *m, unsigned portid, uint16_t queue_id, struct app_config *app_config) {

    app_config->lcore_stats[rte_lcore_id()].rx_bytes += m->pkt_len;

    if (m->pkt_len < MIN_PKT_LEN) {
        rte_pktmbuf_free(m);
        return;
    }

    // Pointers to headers
    struct ether_hdr *eth_hdr = mbuf_eth_ptr(m);
    struct tcp_hdr *tcp_hdr = NULL;
    struct udp_hdr *udp_hdr = NULL;
    struct dns_hdr *dns_hdr = NULL;

    uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    // Min packet length for IPv4 already checked
    if (ether_type == ETHER_TYPE_IPv4) {
        struct ipv4_hdr *ip4_hdr = mbuf_ip4_ip_ptr(m);

        if (ip4_hdr->next_proto_id == IPPROTO_TCP && m->pkt_len >= IP4_MIN_TCP_PKT_LEN) {
            tcp_hdr = mbuf_ip4_tcp_ptr(m);
            dns_hdr = &mbuf_ip4_tcp_dns_header_ptr(m)->hdr;
        } else if (ip4_hdr->next_proto_id == IPPROTO_UDP && m->pkt_len >= IP4_MIN_UDP_PKT_LEN) {
            udp_hdr = mbuf_ip4_udp_ptr(m);
            dns_hdr = mbuf_ip4_udp_dns_header_ptr(m);
        } else {
            rte_pktmbuf_free(m);
            return;
        }

    } else if (ether_type == ETHER_TYPE_IPv6 && m->pkt_len >= IP6_MIN_PKT_LEN) {
        struct ipv6_hdr *ip6_hdr = mbuf_ip6_ip_ptr(m);

        if (ip6_hdr->proto == IPPROTO_TCP && m->pkt_len >= IP6_MIN_TCP_PKT_LEN) {
            tcp_hdr = mbuf_ip6_tcp_ptr(m);
            dns_hdr = &mbuf_ip6_tcp_dns_header_ptr(m)->hdr;
        } else if (ip6_hdr->proto == IPPROTO_UDP && m->pkt_len >= IP6_MIN_UDP_PKT_LEN) {
            udp_hdr = mbuf_ip6_udp_ptr(m);
            dns_hdr = mbuf_ip6_udp_dns_header_ptr(m);
        } else {
            rte_pktmbuf_free(m);
            return;
        }

    } else {
        rte_pktmbuf_free(m);
        return;
    }

    // TCP flow or response
    if (tcp_hdr) {
        if (rte_be_to_cpu_16(tcp_hdr->src_port) != app_config->user_config.dst_port) {
            rte_pktmbuf_free(m);
            return;
        }

        // If this is a SYN-ACK, generate ACK and DNS query
        if ((tcp_hdr->tcp_flags & 0x12) == 0x12) {
            rte_mbuf_refcnt_update(m, 1); // Keep mbuf for cloning into query

            send_ack(m, portid, queue_id, app_config, false);

            struct rte_mbuf *m_clone = mbuf_clone(m, app_config);
            rte_mbuf_refcnt_update(m, -1);

            generate_tcp_query(m_clone, portid, queue_id, app_config);
        }
            // Generate ACK if SYN or FIN is set
        else if (tcp_hdr->tcp_flags & 0x03) {
            send_ack(m, portid, queue_id, app_config, false);
        }
            // Handle DNS query response
        else if (MBUF_HAS_MIN_TCP_DNS_LEN(ether_type, m->data_len)) {
            app_config->lcore_stats[rte_lcore_id()].rx_responses++;

            rte_mbuf_refcnt_update(m, 1); // Keep mbuf for RCODE classification

            send_ack(m, portid, queue_id, app_config, true);

            response_classify(app_config, dns_hdr);

            rte_mbuf_refcnt_update(m, -1);
        } else {
            rte_pktmbuf_free(m);
        }
    }
        // UDP response
    else {
        if (rte_be_to_cpu_16(udp_hdr->src_port) != app_config->user_config.dst_port) {
            rte_pktmbuf_free(m);
            return;
        }

        if (MBUF_HAS_MIN_UDP_DNS_LEN(ether_type, m->data_len)) {
            app_config->lcore_stats[rte_lcore_id()].rx_responses++;

            response_classify(app_config, dns_hdr);
        }

        rte_pktmbuf_free(m);
    }
}
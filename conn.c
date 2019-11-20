/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Brno University of Technology
 *
 * tcpgen - a simple DPDK TCP DNS traffic generator
 * Author: Matej Postolka <xposto02@stud.fit.vutbr.cz>
 */

// TODO prune and cleanup

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_branch_prediction.h>
#include <rte_random.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "dns.h"
#include "qname_table.h"
#include "pcap.h"
#include "common.h"
#include "args.h"
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

#define IP4_ACK_MBUF_DATALEN IP4_SYN_MBUF_DATALEN
#define IP6_ACK_MBUF_DATALEN IP6_SYN_MBUF_DATALEN
#define IP4_MIN_PKT_LEN IP4_SYN_MBUF_DATALEN
#define IP6_MIN_PKT_LEN IP6_SYN_MBUF_DATALEN
#define MIN_PKT_LEN IP4_MIN_PKT_LEN
#define IP4_DNS_PACKET_MIN_LEN (IP4_MIN_PKT_LEN + sizeof(struct dns_hdr))
#define IP6_DNS_PACKET_MIN_LEN (IP6_MIN_PKT_LEN + sizeof(struct dns_hdr))
#define MBUF_HAS_MIN_DNS_LEN(m) ( (rte_be_to_cpu_16(rte_pktmbuf_mtod(m, struct ether_hdr *)->ether_type) == ETHER_TYPE_IPv4 && (m)->pkt_len >= IP4_DNS_PACKET_MIN_LEN) || (rte_be_to_cpu_16(rte_pktmbuf_mtod(m, struct ether_hdr *)->ether_type) == ETHER_TYPE_IPv6 && (m)->pkt_len >= IP6_DNS_PACKET_MIN_LEN))

static void send_ack(struct rte_mbuf *m, unsigned portid, struct app_config *app_config, bool fin);

static void generate_query_pcap(struct rte_mbuf *m, unsigned portid, struct app_config *app_config);

static struct rte_mbuf *mbuf_clone(struct rte_mbuf *m, const struct app_config *app_config);

static void response_classify(struct rte_mbuf *m, unsigned portid, struct app_config *app_config);

// Open new IPv4 TCP connection
void tcp4_open(unsigned portid, struct app_config *app_config) {

    uint16_t src_port = rte_rand();
    uint32_t src_ip_rand_bits;

    do {
        src_ip_rand_bits = rte_rand() & app_config->user_config.ip4_src_rand_bit_mask;
    } while (unlikely(
            src_ip_rand_bits == 0 ||
            src_ip_rand_bits == app_config->user_config.ip4_src_rand_bit_mask)); // No net and broadcast addrs


    struct rte_mbuf *syn_mbuf = rte_pktmbuf_alloc(app_config->dpdk_config.pktmbuf_pool);
    if (syn_mbuf == NULL) {
        RTE_LOG(CRIT, TCPGEN, "tcp4_open: failed to allocate mbuf for new tcp connection\n");
        rte_exit(EXIT_FAILURE, "mbuf allocation failed");
    }

    syn_mbuf->pkt_len = syn_mbuf->data_len = IP4_SYN_MBUF_DATALEN;

    // Initialize L2 header
    struct ether_hdr *eth = mbuf_eth_ptr(syn_mbuf);
    memcpy(eth->d_addr.addr_bytes, app_config->user_config.dst_mac, ETHER_ADDR_LEN);
    memcpy(eth->s_addr.addr_bytes, app_config->user_config.src_mac, ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    // Initialize L3 header
    struct ipv4_hdr *ip = mbuf_ip4_ip_ptr(syn_mbuf);
    ip->version_ihl = 0x45; // Version 4 HL 20 (multiplier 5)
    ip->type_of_service = 0;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = rte_cpu_to_be_16(0x4000); // Don't fragment flag set
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->hdr_checksum = 0;
    ip->src_addr = *(uint32_t *) app_config->user_config.ip4_src_subnet | rte_cpu_to_be_32(src_ip_rand_bits);
    ip->dst_addr = *(uint32_t *) app_config->user_config.ip4_dst_addr;

    // Process IP checksum
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // Initialize L4 header
    struct tcp_hdr *tcp = mbuf_ip4_tcp_ptr(syn_mbuf);
    tcp->src_port = rte_cpu_to_be_16(src_port);
    tcp->dst_port = rte_cpu_to_be_16(app_config->user_config.tcp_dst_port);
    tcp->sent_seq = 0;
    tcp->recv_ack = 0;
    tcp->data_off = 0x50; // 20 byte (5 * 4) header
    tcp->tcp_flags = 0x02; // SYN flag
    tcp->rx_win = rte_cpu_to_be_16(0xfaf0);
    tcp->cksum = 0;
    tcp->tcp_urp = 0;

    // Process TCP checksum
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

    // Send
    struct rte_eth_dev_tx_buffer *buffer;

    buffer = app_config->dpdk_config.tx_buffer[portid];
    app_config->port_stats[portid].tx_bytes += syn_mbuf->data_len + 24; // L1 bytes
    app_config->port_stats[portid].tx_packets++;
    rte_eth_tx_buffer(portid, 0, buffer, syn_mbuf);
}

// Open new IPv6 TCP connection
void tcp6_open(unsigned portid, struct app_config *app_config) {

    uint16_t src_port = rte_rand();

    uint64_t src_ip_rand_bits[2];
    do {
        src_ip_rand_bits[0] = rte_rand() & app_config->user_config.ip6_src_rand_bit_mask[0];
        src_ip_rand_bits[1] = rte_rand() & app_config->user_config.ip6_src_rand_bit_mask[1];
    } while (unlikely(
            memcmp(src_ip_rand_bits, app_config->user_config.ip6_src_rand_bit_mask, IPv6_ADDR_LEN) == 0 ||
            (src_ip_rand_bits[0] == 0 && src_ip_rand_bits[1] == 0))); // No net and broadcast addrs


    struct rte_mbuf *syn_mbuf = rte_pktmbuf_alloc(app_config->dpdk_config.pktmbuf_pool);
    if (syn_mbuf == NULL) {
        RTE_LOG(CRIT, TCPGEN, "tcp6_open: failed to allocate mbuf for new tcp connection\n");
        rte_exit(EXIT_FAILURE, "mbuf allocation failed");
    }

    syn_mbuf->pkt_len = syn_mbuf->data_len = IP6_SYN_MBUF_DATALEN;

    // Initialize L2 header
    struct ether_hdr *eth = mbuf_eth_ptr(syn_mbuf);
    memcpy(eth->d_addr.addr_bytes, app_config->user_config.dst_mac, ETHER_ADDR_LEN);
    memcpy(eth->s_addr.addr_bytes, app_config->user_config.src_mac, ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv6);

    // Initialize L3 header
    struct ipv6_hdr *ip = mbuf_ip6_ip_ptr(syn_mbuf);
    ip->vtc_flow = rte_cpu_to_be_32(0x60000000); // version 6 + no flow id
    ip->payload_len = rte_cpu_to_be_16(sizeof(struct tcp_hdr));
    ip->proto = IPPROTO_TCP;
    ip->hop_limits = 64;
    *(uint64_t *) &ip->src_addr[0] =
            *(uint64_t *) &app_config->user_config.ip6_src_subnet[0] | rte_cpu_to_be_64(src_ip_rand_bits[0]);
    *(uint64_t *) &ip->src_addr[8] =
            *(uint64_t *) &app_config->user_config.ip6_src_subnet[8] | rte_cpu_to_be_64(src_ip_rand_bits[1]);
    memcpy(ip->dst_addr, app_config->user_config.ip6_dst_addr, IPv6_ADDR_LEN);

    // Initialize L4 header
    struct tcp_hdr *tcp = mbuf_ip6_tcp_ptr(syn_mbuf);
    tcp->src_port = rte_cpu_to_be_16(src_port);
    tcp->dst_port = rte_cpu_to_be_16(app_config->user_config.tcp_dst_port);
    tcp->sent_seq = 0;
    tcp->recv_ack = 0;
    tcp->data_off = 0x50; // 20 byte (5 * 4) header
    tcp->tcp_flags = 0x02; // SYN flag
    tcp->rx_win = rte_cpu_to_be_16(0xfaf0);
    tcp->cksum = 0;
    tcp->tcp_urp = 0;

    // Process TCP checksum
    tcp->cksum = rte_ipv6_udptcp_cksum(ip, tcp);

    // Send
    struct rte_eth_dev_tx_buffer *buffer;

    buffer = app_config->dpdk_config.tx_buffer[portid];
    app_config->port_stats[portid].tx_bytes += syn_mbuf->data_len + 24; // L1 bytes
    app_config->port_stats[portid].tx_packets++;
    rte_eth_tx_buffer(portid, 0, buffer, syn_mbuf);
}

static void send_ack(struct rte_mbuf *m, unsigned portid, struct app_config *app_config, bool fin) {
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

    // Update cksums
    if (ether_type == ETHER_TYPE_IPv4) {
        ip4_hdr->hdr_checksum = rte_ipv4_cksum(ip4_hdr);
        tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ip4_hdr, tcp_hdr);
    } else {
        tcp_hdr->cksum = rte_ipv6_udptcp_cksum(ip6_hdr, tcp_hdr);
    }

    // Send
    struct rte_eth_dev_tx_buffer *buffer;

    buffer = app_config->dpdk_config.tx_buffer[portid];
    app_config->port_stats[portid].tx_bytes += m->data_len;
    app_config->port_stats[portid].tx_packets++;
    rte_eth_tx_buffer(portid, 0, buffer, m);
}

// FIXME: split app_config and stats
static void generate_query_pcap(struct rte_mbuf *m, unsigned portid, struct app_config *app_config) {
    struct pcap_list_entry *ref_pcap = pcap_list_get(&app_config->pcap_list);
    // Move forward in PCAP list
    pcap_list_next(&app_config->pcap_list);

    // Copy data from reference mbuf to outgoing mbuf
    memcpy(rte_pktmbuf_mtod_offset(m, void *, m->data_len), ref_pcap->pcap_payload, ref_pcap->payload_len);
    m->pkt_len = m->data_len = m->data_len + ref_pcap->payload_len;

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
        RTE_LOG(CRIT, TCPGEN, "invalid ether_type in generate_query_pcap\n");
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

    // Send
    struct rte_eth_dev_tx_buffer *tx_buffer = app_config->dpdk_config.tx_buffer[portid];
    app_config->port_stats[portid].tx_bytes += m->data_len;
    app_config->port_stats[portid].tx_packets++;
    app_config->port_stats[portid].tx_queries++;
    rte_eth_tx_buffer(portid, 0, tx_buffer, m);
}

//void generate_query(struct rte_mbuf *m, unsigned portid) {
//    // Select random QNAME from table
//    uint32_t qname_index = rte_rand() % qname_table.records;
//    uint8_t qname_bytes = qname_table.data[qname_index].qname_bytes;
//
//    // Pointers to headers
//    struct ipv4_hdr *ip = mbuf_ip4_ptr(m);
//    struct tcp_hdr *tcp = mbuf_tcp_ptr(m);
//    struct dns_hdr *dns_hdr = mbuf_dns_header_ptr(m);
//    uint8_t *qname_ptr = mbuf_dns_qname_ptr(m);
//    struct dns_query_flags *dns_query_flags = (struct dns_query_flags *) (qname_ptr + qname_bytes);
//
//    m->pkt_len = m->data_len = DNS_PACKET_MIN_LEN + qname_bytes + sizeof(struct dns_query_flags);
//
//    ip->total_length = rte_cpu_to_be_16(m->data_len - sizeof(struct ether_hdr));
//    ip->hdr_checksum = 0;
//
//    tcp->tcp_flags = 0x18; // ACK + PSH
//    tcp->cksum = 0;
//
//    dns_hdr->len = rte_cpu_to_be_16(
//            sizeof(struct dns_hdr) + qname_bytes + sizeof(struct dns_query_flags) - 2); // Length bytes not counted
//    dns_hdr->tx_id = rte_rand();
//    dns_hdr->flags = 0;
//    dns_hdr->q_cnt = rte_cpu_to_be_16(1);
//    dns_hdr->an_cnt = 0;
//    dns_hdr->auth_cnt = 0;
//    dns_hdr->additional_cnt = 0;
//
//    memcpy(qname_ptr, qname_table.data[qname_index].qname, qname_bytes);
//
//    dns_query_flags->qtype = rte_cpu_to_be_16(DNS_QTYPE_A);
//    dns_query_flags->qclass = rte_cpu_to_be_16(DNS_QCLASS_IN);
//
//    // Update cksums
//    ip->hdr_checksum = rte_ipv4_cksum(ip);
//    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);
//
//    // Send
//    struct rte_eth_dev_tx_buffer *buffer;
//
//    buffer = tx_buffer[portid];
//    rte_eth_tx_buffer(portid, 0, buffer, m);
//    port_stats[portid].tx_bytes += m->data_len;
//    port_stats[portid].tx_packets++;
//    port_stats[portid].tx_queries++;
//}

static struct rte_mbuf *mbuf_clone(struct rte_mbuf *m, const struct app_config *app_config) {
    struct rte_mbuf *clone = rte_pktmbuf_alloc(app_config->dpdk_config.pktmbuf_pool);
    if (clone == NULL)
        rte_exit(EXIT_FAILURE, "mbuf clone - mbuf alloc failed\n");

    clone->pkt_len = clone->data_len = m->data_len;
    rte_memcpy(rte_pktmbuf_mtod(clone, void *), rte_pktmbuf_mtod(m, const void *), m->data_len);

    return clone;
}

static void response_classify(struct rte_mbuf *m, unsigned portid, struct app_config *app_config) {
    struct ether_hdr *eth_hdr = mbuf_eth_ptr(m);
    struct dns_hdr *dns_hdr = NULL;

    if (rte_be_to_cpu_16(eth_hdr->ether_type) == ETHER_TYPE_IPv4) {
        dns_hdr = mbuf_ip4_dns_header_ptr(m);
    } else if (rte_be_to_cpu_16(eth_hdr->ether_type) == ETHER_TYPE_IPv6) {
        dns_hdr = mbuf_ip6_dns_header_ptr(m);
    } else {
        RTE_LOG(CRIT, TCPGEN, "response_classify: invalid ether type\n");
        return;
    }

    uint8_t rcode = rte_be_to_cpu_16(dns_hdr->flags) & 0xf;
    app_config->port_stats[portid].rx_rcode[rcode]++;
}

// Incoming packet handler
void handle_incoming(struct rte_mbuf *m, unsigned portid, struct app_config *app_config) {

    app_config->port_stats[portid].rx_bytes += m->pkt_len;

    if (m->pkt_len < MIN_PKT_LEN) {
        rte_pktmbuf_free(m);
        return;
    }

    // Pointers to headers
    struct ether_hdr *eth_hdr = mbuf_eth_ptr(m);
    struct tcp_hdr *tcp_hdr;

    if (rte_be_to_cpu_16(eth_hdr->ether_type) == ETHER_TYPE_IPv4 && m->pkt_len >= IP4_MIN_PKT_LEN) {
        struct ipv4_hdr *ip4_hdr = mbuf_ip4_ip_ptr(m);
        tcp_hdr = mbuf_ip4_tcp_ptr(m);

        if (ip4_hdr->next_proto_id != IPPROTO_TCP) {
            rte_pktmbuf_free(m);
            return;
        }
    } else if (rte_be_to_cpu_16(eth_hdr->ether_type) == ETHER_TYPE_IPv6 && m->pkt_len >= IP6_MIN_PKT_LEN) {
        struct ipv6_hdr *ip6_hdr = mbuf_ip6_ip_ptr(m);
        tcp_hdr = mbuf_ip6_tcp_ptr(m);

        if (ip6_hdr->proto != IPPROTO_TCP) {
            rte_pktmbuf_free(m);
            return;
        }
    } else {
        rte_pktmbuf_free(m);
        return;
    }

    // Check if traffic originated from dst port
    if (rte_be_to_cpu_16(tcp_hdr->src_port) != app_config->user_config.tcp_dst_port) {
        rte_pktmbuf_free(m);
        return;
    }

    // If this is a SYN-ACK, generate ACK and DNS query
    if ((tcp_hdr->tcp_flags & 0x12) == 0x12) {
        rte_mbuf_refcnt_update(m, 1); // Keep mbuf for cloning into query
        send_ack(m, portid, app_config, false);
        struct rte_mbuf *m_clone = mbuf_clone(m, app_config);
        rte_mbuf_refcnt_update(m, -1);
        generate_query_pcap(m_clone, portid, app_config);
    }
        // Generate ACK if SYN or FIN is set
    else if (tcp_hdr->tcp_flags & 0x03) {
        send_ack(m, portid, app_config, false);
    }
        // Handle DNS query response
    else if (MBUF_HAS_MIN_DNS_LEN(m)) {
        app_config->port_stats[portid].rx_responses++;
        rte_mbuf_refcnt_update(m, 1); // Keep mbuf for RCODE classification
        send_ack(m, portid, app_config, true);
        response_classify(m, portid, app_config);
        rte_mbuf_refcnt_update(m, -1);
    } else {
        rte_pktmbuf_free(m);
    }
}
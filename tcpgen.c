/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Brno University of Technology
 *
 * tcpgen - a simple DPDK TCP DNS traffic generator
 * Author: Matej Postolka <xposto02@stud.fit.vutbr.cz>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "dns.h"

static volatile bool force_quit;

#define RTE_LOGTYPE_TCPGEN RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* mask of enabled ports */
static uint32_t tcpgen_enabled_port_mask = 0;

static unsigned int tcpgen_rx_queue_per_lcore = 1;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf {
    unsigned n_port;
    unsigned port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
        .rxmode = {
                .split_hdr_size = 0,
        },
        .txmode = {
                .mq_mode = ETH_MQ_TX_NONE,
        },
};

struct rte_mempool *tcpgen_pktmbuf_pool = NULL;

struct tcpgen_port_stats {
    /* Total TX packet count */
    uint64_t tx_packets;
    /* Total TX byte count */
    uint64_t tx_bytes;
    /* DNS query TX count */
    uint64_t tx_queries;
    /* TX dropped count */
    uint64_t tx_dropped;

    /* Total RX packet count */
    uint64_t rx_packets;
    /* Total RX byte count */
    uint64_t rx_bytes;
    /* DNS packet RX count */
    uint64_t rx_responses;
    /* Per-RCode stats */
    uint64_t rx_rcode[DNS_RCODE_MAX_TYPES];
} __rte_cache_aligned;

struct tcpgen_port_stats port_stats[RTE_MAX_ETHPORTS];

static uint64_t tx_tsc_period = 1000000000;

#define SYN_MBUF_DATALEN ( \
    sizeof(struct ether_hdr) + \
    sizeof(struct ipv4_hdr) + \
    sizeof(struct tcp_hdr) )
#define ACK_MBUF_DATALEN SYN_MBUF_DATALEN

static uint8_t src_mac[ETHER_ADDR_LEN];
static uint8_t dst_mac[ETHER_ADDR_LEN];

#define IP_ADDR_LEN 4
static uint8_t src_ip_mask[IP_ADDR_LEN];
static uint8_t dst_ip[IP_ADDR_LEN];

#define DNS_PORT 53
#define TCP_STATE_NONE 0
#define TCP_STATE_SYN 1
#define TCP_STATE_OPEN 2

#define mbuf_eth_ptr(m) (rte_pktmbuf_mtod((m), struct ether_hdr *))
#define mbuf_ip4_ptr(m) (rte_pktmbuf_mtod_offset((m), struct ipv4_hdr *, sizeof(struct ether_hdr)))
#define mbuf_tcp_ptr(m) (rte_pktmbuf_mtod_offset((m), struct tcp_hdr *, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr)))
#define mbuf_dns_header_ptr(m) (rte_pktmbuf_mtod_offset((m), struct dns_hdr *, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr)))
#define mbuf_dns_query_ptr(m) (rte_pktmbuf_mtod_offset((m), struct dns_query_static *, sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) + sizeof(struct dns_hdr)))

/* TCP connection generator */
static void
tcp_open(unsigned portid) {
    uint16_t src_port = rte_rand();
    uint16_t src_ip_rand_octets = rte_rand() & ((1 << 14) - 1); /* 14 random bits in IP */

    struct rte_mbuf *syn_mbuf = rte_pktmbuf_alloc(tcpgen_pktmbuf_pool);
    if (syn_mbuf == NULL) {
        RTE_LOG(CRIT, TCPGEN, "failed to allocate mbuf for new tcp connection\n");
        rte_exit(EXIT_FAILURE, "mbuf allocation failed");
    }

    syn_mbuf->pkt_len = syn_mbuf->data_len = SYN_MBUF_DATALEN;

    /* Initialize L2 header */
    struct ether_hdr *eth = mbuf_eth_ptr(syn_mbuf);
    memcpy(&eth->d_addr.addr_bytes[0], &dst_mac[0], ETHER_ADDR_LEN);
    memcpy(&eth->s_addr.addr_bytes[0], &src_mac[0], ETHER_ADDR_LEN);
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    /* Initialize L3 header */
    struct ipv4_hdr *ip = mbuf_ip4_ptr(syn_mbuf);
    ip->version_ihl = 0x45; /* Version 4 HL 20 (multiplier 5) */
    ip->type_of_service = 0;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = rte_cpu_to_be_16(0x4000); /* Don't fragment flag set */
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->hdr_checksum = 0;
    ip->src_addr = rte_cpu_to_be_32(*((uint32_t *) src_ip_mask) | src_ip_rand_octets);
    ip->dst_addr = rte_cpu_to_be_32(*((uint32_t *) dst_ip));

    /* Process IP checksum */
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    /* Initialize L4 header */
    struct tcp_hdr *tcp = mbuf_tcp_ptr(syn_mbuf);
    tcp->src_port = rte_cpu_to_be_16(src_port);
    tcp->dst_port = rte_cpu_to_be_16(DNS_PORT);
    tcp->sent_seq = 0;
    tcp->recv_ack = 0;
    tcp->data_off = 0x50; /* 20 byte (5 * 4) header */
    tcp->tcp_flags = 0x02; /* SYN flag */
    tcp->rx_win = rte_cpu_to_be_16(0xfaf0);
    tcp->cksum = 0;
    tcp->tcp_urp = 0;

    /* Process TCP checksum */
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

    /* Send */
    struct rte_eth_dev_tx_buffer *buffer;

    buffer = tx_buffer[portid];
    rte_eth_tx_buffer(portid, 0, buffer, syn_mbuf);
    port_stats[portid].tx_bytes += SYN_MBUF_DATALEN + 24;
    port_stats[portid].tx_packets++;
}

static void
send_ack(struct rte_mbuf *m, unsigned portid, bool fin) {
    /* Pointers to headers */
    struct ether_hdr *eth = mbuf_eth_ptr(m);
    struct ipv4_hdr *ip = mbuf_ip4_ptr(m);
    struct tcp_hdr *tcp = mbuf_tcp_ptr(m);

    uint8_t data_offset = tcp->data_off; /* data_off * 4 = byte offset */
    int16_t payload_len = rte_be_to_cpu_16(ip->total_length) - sizeof(struct ipv4_hdr) - (data_offset >> 2);

    m->pkt_len = m->data_len = ACK_MBUF_DATALEN;

    /* Swap MAC addresses */
    *((uint64_t *) &eth->d_addr.addr_bytes[0]) ^= *((uint64_t *) &eth->s_addr.addr_bytes[0]) & 0x0000FFFFFFFFFFFF;
    *((uint64_t *) &eth->s_addr.addr_bytes[0]) ^= *((uint64_t *) &eth->d_addr.addr_bytes[0]) & 0x0000FFFFFFFFFFFF;
    *((uint64_t *) &eth->d_addr.addr_bytes[0]) ^= *((uint64_t *) &eth->s_addr.addr_bytes[0]) & 0x0000FFFFFFFFFFFF;

    /* Swap IP addresses */
    ip->src_addr ^= ip->dst_addr;
    ip->dst_addr ^= ip->src_addr;
    ip->src_addr ^= ip->dst_addr;

    ip->packet_id = 0;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr));
    ip->hdr_checksum = 0;

    /* Update TCP header */
    tcp->src_port ^= tcp->dst_port;
    tcp->dst_port ^= tcp->src_port;
    tcp->src_port ^= tcp->dst_port;

    tcp->sent_seq ^= tcp->recv_ack;
    tcp->recv_ack ^= tcp->sent_seq;
    tcp->sent_seq ^= tcp->recv_ack;

    if (payload_len > 0)
        tcp->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcp->recv_ack) + payload_len);
    else
        tcp->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcp->recv_ack) + 1); /* ACK sender's seq +1 */
    //tcp->tcp_flags |= 0x10; /* ACK bit set */
    //tcp->tcp_flags &= 0xfd; /* clear SYN */
    tcp->tcp_flags = 0x10; /* set ACK */
    if (fin)
        tcp->tcp_flags |= 0x01;

    tcp->data_off = 0x50; /* 20 byte (5 * 4) header */
    tcp->cksum = 0;

    /* Update cksums */
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

    /* Send */
    struct rte_eth_dev_tx_buffer *buffer;

    buffer = tx_buffer[portid];
    rte_eth_tx_buffer(portid, 0, buffer, m);
    port_stats[portid].tx_bytes += ACK_MBUF_DATALEN;
    port_stats[portid].tx_packets++;
}

#define DNS_PACKET_MIN_LEN (sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) + sizeof(struct dns_hdr))
#define DNS_STATIC_QUERY_LEN (DNS_PACKET_MIN_LEN + sizeof(struct dns_query_static))

static void
generate_query(struct rte_mbuf *m, unsigned portid) {
    /* Pointers to headers */
    struct ipv4_hdr *ip = mbuf_ip4_ptr(m);
    struct tcp_hdr *tcp = mbuf_tcp_ptr(m);
    struct dns_hdr *dns_hdr = mbuf_dns_header_ptr(m);
    struct dns_query_static *dns_query = mbuf_dns_query_ptr(m);

    m->pkt_len = m->data_len = DNS_STATIC_QUERY_LEN;

    ip->total_length = rte_cpu_to_be_16(DNS_STATIC_QUERY_LEN - sizeof(struct ether_hdr));
    ip->hdr_checksum = 0;

    tcp->tcp_flags = 0x18; /* ACK + PSH */
    tcp->cksum = 0;

    dns_hdr->len = rte_cpu_to_be_16(
            sizeof(struct dns_hdr) + sizeof(struct dns_query_static) - 2); /* Length bytes not counted */
    dns_hdr->tx_id = rte_rand();
    dns_hdr->flags = 0;
    dns_hdr->q_cnt = rte_cpu_to_be_16(1);
    dns_hdr->an_cnt = 0;
    dns_hdr->auth_cnt = 0;
    dns_hdr->additional_cnt = 0;

    dns_query->qname[0] = 1;
    dns_query->qname[1] = 'a';
    dns_query->qname[2] = 4;
    dns_query->qname[3] = 't';
    dns_query->qname[4] = 'e';
    dns_query->qname[5] = 's';
    dns_query->qname[6] = 't';
    dns_query->qname[7] = 0;

    dns_query->qtype = rte_cpu_to_be_16(DNS_QTYPE_A);
    dns_query->qclass = rte_cpu_to_be_16(DNS_QCLASS_IN);

    /* Update cksums */
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

    /* Send */
    struct rte_eth_dev_tx_buffer *buffer;

    buffer = tx_buffer[portid];
    rte_eth_tx_buffer(portid, 0, buffer, m);
    port_stats[portid].tx_bytes += DNS_STATIC_QUERY_LEN;
    port_stats[portid].tx_packets++;
    port_stats[portid].tx_queries++;
}

struct rte_mbuf *
mbuf_clone(struct rte_mbuf *m) {
    struct rte_mbuf *clone = rte_pktmbuf_alloc(tcpgen_pktmbuf_pool);
    if (clone == NULL)
        rte_exit(EXIT_FAILURE, "mbuf clone - mbuf alloc failed\n");

    clone->pkt_len = clone->data_len = m->data_len;
    rte_memcpy(rte_pktmbuf_mtod(clone, void *), rte_pktmbuf_mtod(m, const void *), m->data_len);

    return clone;
}

static void
response_classify(struct rte_mbuf *m, unsigned portid) {
    struct dns_hdr *dns_hdr = mbuf_dns_header_ptr(m);
    uint8_t rcode = rte_be_to_cpu_16(dns_hdr->flags) & 0x4;
    port_stats[portid].rx_rcode[rcode]++;
}

#define MIN_PKT_LEN SYN_MBUF_DATALEN

/* Incoming packet handler */
static void
handle_incoming(struct rte_mbuf *m, unsigned portid) {

    port_stats[portid].rx_bytes += m->pkt_len;

    /* Ensure that at least Ethernet, IP and TCP headers are present */
    if (m->pkt_len < SYN_MBUF_DATALEN) {
        rte_pktmbuf_free(m);
        return;
    }

    /* Pointers to headers */
    struct ether_hdr *eth = mbuf_eth_ptr(m);
    struct ipv4_hdr *ip = mbuf_ip4_ptr(m);
    struct tcp_hdr *tcp = mbuf_tcp_ptr(m);

    /* Discard non-DNS traffic */
    if (rte_be_to_cpu_16(eth->ether_type) != ETHER_TYPE_IPv4) {
        rte_pktmbuf_free(m);
        return;
    }

    if (ip->next_proto_id != IPPROTO_TCP) {
        rte_pktmbuf_free(m);
        return;
    }

    if (rte_be_to_cpu_16(tcp->src_port) != DNS_PORT) {
        rte_pktmbuf_free(m);
        return;
    }

    /* If this is a SYN-ACK, generate ACK and DNS query */
    if ((tcp->tcp_flags & 0x12) == 0x12) {
        rte_mbuf_refcnt_update(m, 1); /* Keep mbuf for cloning into query */
        send_ack(m, portid, false);
        struct rte_mbuf *m_clone = mbuf_clone(m);
        rte_mbuf_refcnt_update(m, -1);
        generate_query(m_clone, portid);
    }
        /* Generate ACK if SYN or FIN is set */
    else if (tcp->tcp_flags & 0x03) {
        send_ack(m, portid, false);
    }
        /* Handle DNS query response */
    else if (m->pkt_len > DNS_STATIC_QUERY_LEN) {
        port_stats[portid].rx_responses++;
        rte_mbuf_refcnt_update(m, 1); /* Keep mbuf for RCODE classification */
        send_ack(m, portid, true);
        response_classify(m, portid);
        rte_mbuf_refcnt_update(m, -1);
    } else {
        rte_pktmbuf_free(m);
    }
}

/* main processing loop */
static void
tcpgen_main_loop(void) {
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf *m;
    unsigned lcore_id;
    uint64_t prev_tsc, diff_tsc, cur_tsc, tx_tsc, tx_diff;
    unsigned i, j, portid, nb_rx;
    struct lcore_queue_conf *qconf;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
                               BURST_TX_DRAIN_US;
    struct rte_eth_dev_tx_buffer *buffer;
    uint64_t start_tsc, stop_tsc;

    prev_tsc = 0;
    tx_tsc = 0;

    lcore_id = rte_lcore_id();
    qconf = &lcore_queue_conf[lcore_id];

    if (qconf->n_port == 0) {
        RTE_LOG(INFO, TCPGEN, "lcore %u has nothing to do\n", lcore_id);
        return;
    }

    RTE_LOG(INFO, TCPGEN, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < qconf->n_port; i++) {

        portid = qconf->port_list[i];
        RTE_LOG(INFO, TCPGEN, " -- lcoreid=%u portid=%u\n", lcore_id,
                portid);

    }

    start_tsc = rte_rdtsc();

    while (!force_quit) {
        cur_tsc = rte_rdtsc();

        /*
         * TX burst queue drain
         */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            for (i = 0; i < qconf->n_port; i++) {
                portid = qconf->port_list[i];
                buffer = tx_buffer[portid];
                rte_eth_tx_buffer_flush(portid, 0, buffer);
            }
            prev_tsc = cur_tsc;
        }

        /*
         * Read packet from RX queues
         */
        tx_diff = cur_tsc - tx_tsc;
        for (i = 0; i < qconf->n_port; i++) {
            portid = qconf->port_list[i];

            if (tx_diff > tx_tsc_period) {
                tcp_open(portid);
                tx_tsc = cur_tsc;
            }

            nb_rx = rte_eth_rx_burst(portid, 0,
                                     pkts_burst, MAX_PKT_BURST);

            port_stats[portid].rx_packets += nb_rx;

            for (j = 0; j < nb_rx; j++) {
                m = pkts_burst[j];
                rte_prefetch0(rte_pktmbuf_mtod(m, void *));
                handle_incoming(m, portid);
            }
        }
    }

    for (i = 0; i < qconf->n_port; i++) {
        portid = qconf->port_list[i];
        buffer = tx_buffer[portid];
        rte_eth_tx_buffer_flush(portid, 0, buffer);
    }

    stop_tsc = rte_rdtsc();
    uint64_t runtime_tsc = stop_tsc - start_tsc;
    uint64_t runtime_usec = runtime_tsc / (rte_get_tsc_hz() / 1000000);
    uint64_t runtime_sec = runtime_tsc / rte_get_tsc_hz();
    printf("Total runtime: %lu microseconds (%lu seconds)\n", runtime_usec, runtime_sec);
    for (i = 0; i < qconf->n_port; i++) {
        portid = qconf->port_list[i];
        printf("Port %d stats:\n\tTX bytes: %lu\n\tTX packets: %lu\n\tTX queries: %lu\n\n\t",
               portid,
               port_stats[portid].tx_bytes,
               port_stats[portid].tx_packets,
               port_stats[portid].tx_queries);
        printf("RX bytes: %lu\n\tRX packets: %lu\n\tRX responses: %lu\n\t\t",
               port_stats[portid].rx_bytes,
               port_stats[portid].rx_packets,
               port_stats[portid].rx_responses);
        printf("NOERROR: %lu\n\t\tFORMERR: %lu\n\t\tSERVFAIL: %lu\n\t\tNXDOMAIN: %lu\n\t\tNOTIMP: %lu\n\t\tREFUSED: %lu\n\n\t",
               port_stats[portid].rx_rcode[DNS_RCODE_NOERROR],
               port_stats[portid].rx_rcode[DNS_RCODE_FORMERR],
               port_stats[portid].rx_rcode[DNS_RCODE_SERVFAIL],
               port_stats[portid].rx_rcode[DNS_RCODE_NXDOMAIN],
               port_stats[portid].rx_rcode[DNS_RCODE_NOTIMP],
               port_stats[portid].rx_rcode[DNS_RCODE_REFUSED]);
        printf("TX bitrate: %f Gbit/s\n\tTX QPS: %.2f\n\tTX FPS: %.2f\n\tRX bitrate: %f Gbit/s\n\tRX RPS: %.2f\n\tRX FPS: %.2f\n\tResponse rate: %.2f%%\n",
               ((port_stats[portid].tx_bytes << 3) / (double) runtime_usec) / 1000,
               (port_stats[portid].tx_queries / (double) runtime_usec) * 1000000,
               (port_stats[portid].tx_packets / (double) runtime_usec) * 1000000,
               ((port_stats[portid].rx_bytes << 3) / (double) runtime_usec) / 1000,
               (port_stats[portid].rx_responses / (double) runtime_usec) * 1000000,
               (port_stats[portid].rx_packets / (double) runtime_usec) * 1000000,
               ((port_stats[portid].rx_responses / (double) port_stats[portid].tx_queries)) * 100);
    }
}

static int
tcpgen_launch_one_lcore(__attribute__((unused)) void *dummy) {
    tcpgen_main_loop();
    return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint16_t portid;
    uint8_t count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("\nChecking link status...");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        if (force_quit)
            return;
        all_ports_up = 1;
        RTE_ETH_FOREACH_DEV(portid) {
            if (force_quit)
                return;
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf(
                            "Port%d Link Up. Speed %u Mbps - %s\n",
                            portid, link.link_speed,
                            (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                            ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n", portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf(" done\n");
        }
    }
}

/* display usage */
static void
tcpgen_usage(const char *prgname) {
    printf("%s [EAL options] -- -p PORTMASK --src-mac SRC_MAC --dst-mac DST_MAC --src-ip-mask SRC_IP_MASK --dst-ip DST_IP\n"
           "  -p PORTMASK: Hexadecimal bitmask of ports to generate traffic on\n"
           "  -t TCP GAP: TSC delay before opening a new TCP connection\n"
           "  --src-mac: Source MAC address of queries\n"
           "  --dst-mac: Destination MAC address of queries\n"
           "  --src-ip-mask: Mask for source IP of queries\n"
           "  --dst-ip: Destinatio IP of queries\n",
           prgname);
}

static int
tcpgen_parse_portmask(const char *portmask) {
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

static const char short_options[] =
        "p:"  /* portmask */
        "t:"  /* tcp gap */
;

#define CMD_LINE_OPT_SRC_MAC "src-mac"
#define CMD_LINE_OPT_DST_MAC "dst-mac"
#define CMD_LINE_OPT_SRC_IP_MASK "src-ip-mask"
#define CMD_LINE_OPT_DST_IP "dst-ip"

enum {
    CMD_LINE_OPT_MIN_NUM = 256,
    CMD_LINE_OPT_SRC_MAC_NUM,
    CMD_LINE_OPT_DST_MAC_NUM,
    CMD_LINE_OPT_SRC_IP_MASK_NUM,
    CMD_LINE_OPT_DST_IP_NUM,
};

static const struct option long_options[] = {
        {CMD_LINE_OPT_SRC_MAC,     required_argument, 0, CMD_LINE_OPT_SRC_MAC_NUM},
        {CMD_LINE_OPT_DST_MAC,     required_argument, 0, CMD_LINE_OPT_DST_MAC_NUM},
        {CMD_LINE_OPT_SRC_IP_MASK, required_argument, 0, CMD_LINE_OPT_SRC_IP_MASK_NUM},
        {CMD_LINE_OPT_DST_IP,      required_argument, 0, CMD_LINE_OPT_DST_IP_NUM},
        {NULL, 0,                                     0, 0}
};

static int
tcpgen_parse_args(int argc, char **argv) {
    int opt, ret;
    int option_index;
    int scanned;
    char **argvopt;
    char *prgname = argv[0];

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, short_options, long_options, &option_index)) != EOF) {
        switch (opt) {
            case 'p':
                tcpgen_enabled_port_mask = tcpgen_parse_portmask(optarg);
                if (tcpgen_enabled_port_mask == 0) {
                    printf("invalid portmask\n");
                    tcpgen_usage(prgname);
                    return -1;
                }
                break;

            case 't':
                tx_tsc_period = strtoull(optarg, NULL, 10);
                break;

            case CMD_LINE_OPT_SRC_MAC_NUM:
                scanned = sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &src_mac[0], &src_mac[1], &src_mac[2],
                                 &src_mac[3], &src_mac[4], &src_mac[5]);
                if (scanned != ETHER_ADDR_LEN) {
                    fprintf(stderr, "failed to parse src-mac\n");
                    tcpgen_usage(prgname);
                    return -1;
                }
                break;

            case CMD_LINE_OPT_DST_MAC_NUM:
                scanned = sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dst_mac[0], &dst_mac[1], &dst_mac[2],
                                 &dst_mac[3], &dst_mac[4], &dst_mac[5]);
                if (scanned != ETHER_ADDR_LEN) {
                    fprintf(stderr, "failed to parse dst-mac\n");
                    tcpgen_usage(prgname);
                    return -1;
                }
                break;

            case CMD_LINE_OPT_SRC_IP_MASK_NUM:
                // little-endian int casting
                scanned = sscanf(optarg, "%hhd.%hhd.%hhd.%hhd", &src_ip_mask[3], &src_ip_mask[2], &src_ip_mask[1],
                                 &src_ip_mask[0]);
                if(scanned != IP_ADDR_LEN) {
                    fprintf(stderr, "failed to parse src IP mask\n");
                    tcpgen_usage(prgname);
                    return -1;
                }
                break;

            case CMD_LINE_OPT_DST_IP_NUM:
                // little-endian int casting
                scanned = sscanf(optarg, "%hhd.%hhd.%hhd.%hhd", &dst_ip[3], &dst_ip[2], &dst_ip[1], &dst_ip[0]);
                if(scanned != IP_ADDR_LEN) {
                    fprintf(stderr, "failed to parse dest IP\n");
                    tcpgen_usage(prgname);
                    return -1;
                }
                break;

            default:
                tcpgen_usage(prgname);
                return -1;
        }
    }

    if (optind >= 0)
        argv[optind - 1] = prgname;

    ret = optind - 1;
    optind = 1; /* reset getopt lib */
    return ret;
}

static void
signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit...\n",
               signum);
        force_quit = true;
    }
}

int
main(int argc, char **argv) {
    struct lcore_queue_conf *qconf;
    int ret;
    uint16_t nb_ports;
    uint16_t nb_ports_available = 0;
    uint16_t portid;
    unsigned lcore_id, rx_lcore_id;
    unsigned nb_ports_in_mask = 0;
    unsigned int nb_lcores = 0;
    unsigned int nb_mbufs;

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* parse application arguments (after the EAL ones) */
    ret = tcpgen_parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid TCPGEN arguments\n");

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    /* check port mask to possible port mask */
    if (tcpgen_enabled_port_mask & ~((1 << nb_ports) - 1))
        rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
                 (1 << nb_ports) - 1);

    rx_lcore_id = 0;
    qconf = NULL;

    /* Initialize the port/queue configuration of each logical core */
    RTE_ETH_FOREACH_DEV(portid) {
        /* skip ports that are not enabled */
        if ((tcpgen_enabled_port_mask & (1 << portid)) == 0)
            continue;

        nb_ports_in_mask++;

        /* get the lcore_id for this port */
        while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
               lcore_queue_conf[rx_lcore_id].n_port ==
               tcpgen_rx_queue_per_lcore) {
            rx_lcore_id++;
            if (rx_lcore_id >= RTE_MAX_LCORE)
                rte_exit(EXIT_FAILURE, "Not enough cores\n");
        }

        if (qconf != &lcore_queue_conf[rx_lcore_id]) {
            /* Assigned a new logical core in the loop above. */
            qconf = &lcore_queue_conf[rx_lcore_id];
            nb_lcores++;
        }

        qconf->port_list[qconf->n_port] = portid;
        qconf->n_port++;
        printf("Lcore %u: RX port %u\n", rx_lcore_id, portid);
    }

    nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
                                   nb_lcores * MEMPOOL_CACHE_SIZE), 8192U);

    /* create the mbuf pool */
    tcpgen_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
                                                  MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                                  rte_socket_id());
    if (tcpgen_pktmbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

    /* Initialise each port */
    RTE_ETH_FOREACH_DEV(portid) {
        struct rte_eth_rxconf rxq_conf;
        struct rte_eth_txconf txq_conf;
        struct rte_eth_conf local_port_conf = port_conf;
        struct rte_eth_dev_info dev_info;

        /* skip ports that are not enabled */
        if ((tcpgen_enabled_port_mask & (1 << portid)) == 0) {
            printf("Skipping disabled port %u\n", portid);
            continue;
        }
        nb_ports_available++;

        /* init port */
        printf("Initializing port %u... ", portid);
        fflush(stdout);
        rte_eth_dev_info_get(portid, &dev_info);
        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
            local_port_conf.txmode.offloads |=
                    DEV_TX_OFFLOAD_MBUF_FAST_FREE;
        ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
                     ret, portid);

        ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
                                               &nb_txd);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                     "Cannot adjust number of descriptors: err=%d, port=%u\n",
                     ret, portid);

        /* init one RX queue */
        fflush(stdout);
        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = local_port_conf.rxmode.offloads;
        ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
                                     rte_eth_dev_socket_id(portid),
                                     &rxq_conf,
                                     tcpgen_pktmbuf_pool);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                     ret, portid);

        /* init one TX queue on each port */
        fflush(stdout);
        txq_conf = dev_info.default_txconf;
        txq_conf.offloads = local_port_conf.txmode.offloads;
        ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
                                     rte_eth_dev_socket_id(portid),
                                     &txq_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                     ret, portid);

        /* Initialize TX buffers */
        tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
                                               RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
                                               rte_eth_dev_socket_id(portid));
        if (tx_buffer[portid] == NULL)
            rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
                     portid);

        rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

        ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
                                                 rte_eth_tx_buffer_count_callback,
                                                 &port_stats[portid].tx_dropped);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                     "Cannot set error callback for tx buffer on port %u\n",
                     portid);

        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
                     ret, portid);

        printf("done: \n");

        rte_eth_promiscuous_enable(portid);

        /* initialize port stats */
        memset(&port_stats, 0, sizeof(port_stats));
    }

    if (!nb_ports_available) {
        rte_exit(EXIT_FAILURE,
                 "All available ports are disabled. Please set portmask.\n");
    }

    check_all_ports_link_status(tcpgen_enabled_port_mask);

    ret = 0;
    /* launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(tcpgen_launch_one_lcore, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    }

    RTE_ETH_FOREACH_DEV(portid) {
        if ((tcpgen_enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        printf(" Done\n");
    }

    printf("Bye...\n");

    return ret;
}
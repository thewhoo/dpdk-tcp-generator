//
// Created by postolka on 25.6.19.
//

#ifndef DPDK_TCP_GENERATOR_COMMON_H
#define DPDK_TCP_GENERATOR_COMMON_H

#include <arpa/inet.h>

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
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "dns.h"
#include "pcap.h"
#include "stats.h"

#define RTE_LOGTYPE_TCPGEN RTE_LOGTYPE_USER1



#define DNS_PORT 53
#define IPv4_ADDR_LEN 4
#define IPv6_ADDR_LEN 16

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16

// Global quit flag
volatile uint8_t tcpgen_force_quit;

struct lcore_queue_conf {
    unsigned n_port;
    unsigned port_list[MAX_RX_QUEUE_PER_LCORE];
    uint16_t port_queue[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;

struct app_config;

struct dpdk_config {
    // Number of RX/TX ring descriptors
    uint16_t nb_rxd;
    uint16_t nb_txd;

    // RX-queues per lcore
    unsigned int rx_queue_per_lcore;

    // per-lcore queue configurations
    struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

    // per-port TX buffers
    struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

    // Universal port configuration
    struct rte_eth_conf port_conf;

    // mbuf mempool
    struct rte_mempool *pktmbuf_pool;
};

struct user_config {
    // Ports generating traffic
    uint32_t enabled_port_mask;

    // TSC between opening new TCP connections
    uint64_t tx_tsc_period;

    uint64_t tsc_runtime;

    const char *config_file;
    const char *pcap_file;
    const char *result_file;

    uint8_t src_mac[ETHER_ADDR_LEN];
    uint8_t dst_mac[ETHER_ADDR_LEN];

    uint8_t ip4_src_subnet[IPv4_ADDR_LEN];
    uint8_t ip4_src_netmask[IPv4_ADDR_LEN];
    uint32_t ip4_src_rand_bit_mask;
    uint8_t ip4_dst_addr[IPv4_ADDR_LEN];
    uint8_t ip6_src_subnet[IPv6_ADDR_LEN];
    uint8_t ip6_src_netmask[IPv6_ADDR_LEN];
    uint64_t ip6_src_rand_bit_mask[2];
    uint8_t ip6_dst_addr[IPv6_ADDR_LEN];
    uint16_t dst_port;
    double ip_ipv6_probability;
    uint64_t udp_probability;
    uint64_t tcp_keepalive_probability;

    uint32_t supplied_args;
    uint32_t supplied_config_opts;
};

struct app_config {
    struct dpdk_config dpdk_config;

    struct lcore_stats lcore_stats[RTE_MAX_LCORE];
    struct port_stats port_stats[RTE_MAX_ETHPORTS];

    struct user_config user_config;

    struct pcap_list pcap_lists[RTE_MAX_LCORE];
    uint64_t pcap_ipv6_probability;

    uint64_t ipv6_probability;
};

#endif //DPDK_TCP_GENERATOR_COMMON_H

//
// Created by postolka on 18.11.19.
//

#ifndef DPDK_TCP_GENERATOR_STATS_H
#define DPDK_TCP_GENERATOR_STATS_H

#include <stdint.h>

#include <rte_memory.h>

#include "dns.h"

struct app_config;

struct lcore_stats {
    // Total TX packet count
    uint64_t tx_packets;
    // Total TX byte count
    uint64_t tx_bytes;
    // DNS query TX count
    uint64_t tx_queries;

    // Total RX packet count
    uint64_t rx_packets;
    // Total RX byte count
    uint64_t rx_bytes;
    // DNS packet RX count
    uint64_t rx_responses;
    // Per-RCode stats
    uint64_t rx_rcode[DNS_RCODE_MAX_TYPES];
} __rte_cache_aligned;

struct port_stats {
    // TX dropped count
    uint64_t tx_dropped;
} __rte_cache_aligned;

void print_all_stats(const struct app_config *app_config, uint64_t runtime_tsc);

void write_json_stats(const struct app_config *app_config, uint64_t runtime_tsc);

#endif //DPDK_TCP_GENERATOR_STATS_H

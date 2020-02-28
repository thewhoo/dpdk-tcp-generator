//
// Created by postolka on 10.02.20.
//

#ifndef DPDK_TCP_GENERATOR_DPDK_H
#define DPDK_TCP_GENERATOR_DPDK_H

#include <rte_ethdev.h>

#include "common.h"

#define RXTX_MAX_PKT_BURST 32

struct dpdk_config dpdk_default_config;

uint8_t check_all_ports_link_status(uint32_t port_mask);

void lcore_port_queue_map(struct app_config *app_config);

uint16_t init_ports(struct app_config *app_config);

void shutdown_ports(const struct app_config *app_config);

int pktmbuf_mempool_init(struct app_config *app_config);

int run_worker_lcores(struct app_config *app_config);

#endif //DPDK_TCP_GENERATOR_DPDK_H

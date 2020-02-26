//
// Created by postolka on 1.11.19.
//

#ifndef DPDK_TCP_GENERATOR_CONFIG_H
#define DPDK_TCP_GENERATOR_CONFIG_H

#include <stdio.h>

#include "common.h" // struct user_config

#define CONF_OPT_NUM_SRC_MAC (1 << 0)
#define CONF_OPT_NUM_DST_MAC (1 << 1)
#define CONF_OPT_NUM_IP4_SRC_NET (1 << 2)
#define CONF_OPT_NUM_IP4_SRC_MASK (1 << 3)
#define CONF_OPT_NUM_IP4_DST_IP (1 << 4)
#define CONF_OPT_NUM_IP6_SRC_NET (1 << 5)
#define CONF_OPT_NUM_IP6_SRC_MASK (1 << 6)
#define CONF_OPT_NUM_IP6_DST_IP (1 << 7)
#define CONF_OPT_NUM_DST_PORT (1 << 8)
#define CONF_OPT_NUM_IP_IPV6_PROBABILITY (1 << 9)
#define CONF_OPT_NUM_UDP_PROBABILITY (1 << 10)
#define CONF_OPT_NUM_TCP_KEEPALIVE_PROBABILITY (1 << 11)

int config_file_parse(const char *filename, struct user_config *config);

#endif //DPDK_TCP_GENERATOR_CONFIG_H
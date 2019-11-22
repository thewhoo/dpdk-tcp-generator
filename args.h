//
// Created by postolka on 1.7.19.
//

#ifndef DPDK_TCP_GENERATOR_ARGS_H
#define DPDK_TCP_GENERATOR_ARGS_H

#include "common.h" // struct user_config

#define ARG_PORT_MASK (1 << 0)
#define ARG_TSC_PERIOD (1 << 1)
#define ARG_CONFIG_FILE (1 << 2)
#define ARG_PCAP_FILE (1 << 3)
#define ARG_QNAME_FILE (1 << 4)
#define ARG_RESULT_FILE (1 << 5)
#define ARG_RUNTIME (1 << 6)

void tcpgen_usage(void);
int tcpgen_parse_args(int argc, char **argv, struct user_config *args);

#endif //DPDK_TCP_GENERATOR_ARGS_H

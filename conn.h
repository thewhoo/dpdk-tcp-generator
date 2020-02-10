//
// Created by postolka on 1.7.19.
//

#ifndef DPDK_TCP_GENERATOR_CONN_H
#define DPDK_TCP_GENERATOR_CONN_H

#include <stdint.h>

void tcp4_open(unsigned portid, uint16_t queue_id, struct app_config *app_config);
void tcp6_open(unsigned portid, uint16_t queue_id, struct app_config *app_config);
void handle_incoming(struct rte_mbuf *m, unsigned portid, uint16_t queue_id, struct app_config *app_config);

#endif //DPDK_TCP_GENERATOR_CONN_H

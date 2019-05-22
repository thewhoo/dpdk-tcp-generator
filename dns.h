//
// Created by postolka on 22.5.19.
//

#ifndef DPDK_TCP_GENERATOR_DNS_H
#define DPDK_TCP_GENERATOR_DNS_H

/**
 * DNS query types
 */
#define DNS_QTYPE_A     1
#define DNS_QTYPE_NS    2
#define DNS_QTYPE_CNAME 5
#define DNS_QTYPE_SOA   6
#define DNS_QTYPE_MX    15
#define DNS_QTYPE_TXT   16
#define DNS_QTYPE_AXFR  252

#define DNS_QTYPE_MAX_TYPES 1 << 8

/**
 * DNS query classes
 */
#define DNS_QCLASS_IN = 1
#define DNS_QCLASS_CH = 3

#endif //DPDK_TCP_GENERATOR_DNS_H

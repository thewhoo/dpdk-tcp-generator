//
// Created by postolka on 22.5.19.
//

#ifndef DPDK_TCP_GENERATOR_DNS_H
#define DPDK_TCP_GENERATOR_DNS_H

#include <stdint.h>

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
 * DNS RCodes
 */
#define DNS_RCODE_NOERROR   0
#define DNS_RCODE_FORMERR   1
#define DNS_RCODE_SERVFAIL  2
#define DNS_RCODE_NXDOMAIN  3
#define DNS_RCODE_NOTIMP    4
#define DNS_RCODE_REFUSED   5

#define DNS_RCODE_MAX_TYPES 1 << 8

/**
 * DNS query classes
 */
#define DNS_QCLASS_IN 1
#define DNS_QCLASS_CH 3

struct dns_hdr {
    uint16_t len;
    uint16_t tx_id;
    uint16_t flags;
    uint16_t q_cnt;
    uint16_t an_cnt;
    uint16_t auth_cnt;
    uint16_t additional_cnt;
} __attribute__((__packed__));

struct dns_query_flags {
    uint16_t qtype;
    uint16_t qclass;
} __attribute__((__packed__));

#endif //DPDK_TCP_GENERATOR_DNS_H

//
// Created by postolka on 6.6.19.
//

#ifndef DPDK_TCP_GENERATOR_QNAME_H
#define DPDK_TCP_GENERATOR_QNAME_H

#include <stdint.h>

#define QNAME_MAX_BYTES 256

struct qname_table_record {
    uint8_t qname_bytes;
    uint8_t qname[QNAME_MAX_BYTES];
};

struct qname_table {
    uint32_t records;
    struct qname_table_record *data;
};

void qname_table_alloc(const char *filename, struct qname_table *tbl);
void qname_table_free(struct qname_table *tbl);

#endif //DPDK_TCP_GENERATOR_QNAME_H

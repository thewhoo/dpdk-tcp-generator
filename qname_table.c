/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Brno University of Technology
 *
 * tcpgen - a simple DPDK TCP DNS traffic generator
 * Author: Matej Postolka <xposto02@stud.fit.vutbr.cz>
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_malloc.h>

#include "qname_table.h"

static uint32_t line_count(FILE *fp)
{
    uint32_t line_count = 0;
    int ch;
    do {
        ch = fgetc(fp);
        if(ch == '\n')
            line_count++;
    }
    while (ch != EOF);

    fseek(fp, 0, SEEK_SET);

    return line_count;
}

static void qname_file_parse(FILE *fp, struct qname_table *tbl)
{
    uint8_t buf[256];

    uint8_t buf_pos = 0;
    uint8_t record_offset = 0;
    uint32_t tbl_record = 0;
    int ch;
    do {
        ch = fgetc(fp);

        if (ch == '.') {
            int bytes = buf_pos + 1;
            bytes = record_offset + bytes > QNAME_MAX_BYTES ? QNAME_MAX_BYTES - record_offset : bytes;

            if(bytes > 0) {
                // Write domain component size
                tbl->data[tbl_record].qname[record_offset] = buf_pos;
                record_offset++;
                bytes--;
                memcpy(&tbl->data[tbl_record].qname[record_offset], buf, bytes);

                record_offset += bytes;
                buf_pos = 0;
            }
        }
        else if (ch == '\n') {
            // Null byte at end of QNAME
            tbl->data[tbl_record].qname[record_offset] = 0;
            record_offset++;
            tbl->data[tbl_record].qname_bytes = record_offset;

            tbl_record++;
            record_offset = 0;
            buf_pos = 0;
        }
        else if (ch != EOF) {
            buf[buf_pos] = (uint8_t) ch;
            buf_pos++;
        }
    } while (ch != EOF);
}

void qname_table_alloc(const char *filename, struct qname_table *tbl)
{
    FILE *fp = fopen(filename, "r");
    if(fp == NULL) {
        rte_exit(EXIT_FAILURE, "failed to open qname file\n");
    }

    tbl->records = line_count(fp);
    tbl->data = rte_zmalloc("qname_table_data", tbl->records * sizeof(struct qname_table_record), 0);
    if(tbl->data == NULL) {
        rte_exit(EXIT_FAILURE, "failed to allocate qname_table\n");
    }

    qname_file_parse(fp, tbl);

    fclose(fp);
}

void qname_table_free(struct qname_table *tbl) {
    rte_free(tbl->data);
    tbl->data = NULL;
    tbl->records = 0;
}
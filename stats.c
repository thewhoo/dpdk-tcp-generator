/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Brno University of Technology
 *
 * tcpgen - a simple DPDK TCP DNS traffic generator
 * Author: Matej Postolka <xposto02@stud.fit.vutbr.cz>
 */

#include <stdint.h>
#include <stdio.h>

#include <rte_cycles.h>
#include <rte_log.h>

#include "stats.h"
#include "common.h"
#include "args.h"
#include "dns.h"

#define TSC_TO_USEC(tsc) ((tsc) / (rte_get_tsc_hz() / 1000000))
#define TSC_TO_SEC(tsc) ((tsc) / rte_get_tsc_hz())

struct aggregate_stats {
    uint64_t tx_bytes;
    uint64_t tx_packets;
    uint64_t tx_queries;

    uint64_t rx_bytes;
    uint64_t rx_packets;
    uint64_t rx_responses;

    uint64_t rx_rcode[DNS_RCODE_MAX_TYPES];

    double tx_bitrate;
    double tx_qps;
    double tx_fps;

    double rx_bitrate;
    double rx_rps;
    double rx_fps;

    double response_rate;
};

static void get_aggregate_stats(const struct app_config *app_config, uint64_t runtime_usec, struct aggregate_stats *as);

static void get_aggregate_stats(const struct app_config *app_config, uint64_t runtime_usec, struct aggregate_stats *as) {
    memset(as, 0, sizeof(struct aggregate_stats));

    unsigned lcore_id;
    RTE_LCORE_FOREACH(lcore_id) {
        as->tx_bytes += app_config->lcore_stats[lcore_id].tx_bytes;
        as->tx_packets += app_config->lcore_stats[lcore_id].tx_packets;
        as->tx_queries += app_config->lcore_stats[lcore_id].tx_queries;

        as->rx_bytes += app_config->lcore_stats[lcore_id].rx_bytes;
        as->rx_packets += app_config->lcore_stats[lcore_id].rx_packets;
        as->rx_responses += app_config->lcore_stats[lcore_id].rx_responses;

        for (int i = 0; i < DNS_RCODE_MAX_TYPES; i++) {
            as->rx_rcode[i] += app_config->lcore_stats[lcore_id].rx_rcode[i];
        }
    }

    as->tx_bitrate = ((as->tx_bytes << 3) / (double) runtime_usec) / 1000;
    as->tx_qps = (as->tx_queries / (double) runtime_usec) * 1000000;
    as->tx_fps = (as->tx_packets / (double) runtime_usec) * 1000000;

    as->rx_bitrate = ((as->rx_bytes << 3) / (double) runtime_usec) / 1000;
    as->rx_rps = (as->rx_responses / (double) runtime_usec) * 1000000;
    as->rx_fps = (as->rx_packets / (double) runtime_usec) * 1000000;

    as->response_rate = (as->rx_responses / (double) as->tx_queries) * 100;
}

void write_json_stats(const struct app_config *app_config, uint64_t runtime_tsc) {

    if (!(app_config->user_config.supplied_args & ARG_RESULT_FILE))
        return;

    uint64_t runtime_usec = TSC_TO_USEC(runtime_tsc);

    struct aggregate_stats as;
    get_aggregate_stats(app_config, runtime_usec, &as);

    FILE *fp = fopen(app_config->user_config.result_file, "w");
    if (fp == NULL) {
        RTE_LOG(ERR, TCPGEN, "write_json_stats: unable to open result file\n");
        return;
    }

    fprintf(fp, "{\n\t\"tx_bytes\": %lu,\n\t\"tx_frame_count\": %lu,\n\t\"tx_query_count\": %lu,\n\t",
            as.tx_bytes,
            as.tx_packets,
            as.tx_queries);
    fprintf(fp, "\"rx_bytes\": %lu,\n\t\"rx_frame_count\": %lu,\n\t\"rx_response_count\": %lu,\n\t",
            as.rx_bytes,
            as.rx_packets,
            as.rx_responses);
    fprintf(fp, "\"runtime_usec\": %lu,\n\t", runtime_usec);
    fprintf(fp, "\"response_stats\": {\n\t\t");

    int written = 0;
    for (int j = 0; j < DNS_RCODE_MAX_TYPES; j++) {
        if (as.rx_rcode[j] > 0) {
            fprintf(fp, "\"%d\": %lu,\n\t\t", j, as.rx_rcode[j]);
            written++;
        }
    }

    if (written > 0) {
        fseek(fp, -4, SEEK_CUR);
    }

    fprintf(fp, "\n\t}\n}");
}

void print_all_stats(const struct app_config *app_config, uint64_t runtime_tsc) {
    uint64_t runtime_usec = TSC_TO_USEC(runtime_tsc);
    uint64_t runtime_sec = TSC_TO_SEC(runtime_tsc);

    struct aggregate_stats as;
    get_aggregate_stats(app_config, runtime_usec, &as);

    printf("\nTotal runtime: %lu microseconds (%lu seconds)\n", runtime_usec, runtime_sec);
    printf("\tTX bytes: %lu\n\tTX packets: %lu\n\tTX queries: %lu\n\n",
           as.tx_bytes,
           as.tx_packets,
           as.tx_queries);
    printf("\tRX bytes: %lu\n\tRX packets: %lu\n\tRX responses: %lu\n",
           as.rx_bytes,
           as.rx_packets,
           as.rx_responses);
    printf("\t\tNOERROR: %lu\n\t\tFORMERR: %lu\n\t\tSERVFAIL: %lu\n\t\tNXDOMAIN: %lu\n\t\tNOTIMP: %lu\n\t\tREFUSED: %lu\n\n",
           as.rx_rcode[DNS_RCODE_NOERROR],
           as.rx_rcode[DNS_RCODE_FORMERR],
           as.rx_rcode[DNS_RCODE_SERVFAIL],
           as.rx_rcode[DNS_RCODE_NXDOMAIN],
           as.rx_rcode[DNS_RCODE_NOTIMP],
           as.rx_rcode[DNS_RCODE_REFUSED]);
    printf("\tTX bitrate: %f Gbit/s\n\tTX QPS: %.2f\n\tTX FPS: %.2f\n\n\tRX bitrate: %f Gbit/s\n\tRX RPS: %.2f\n\tRX FPS: %.2f\n\n\tResponse rate: %.2f%%\n",
           as.tx_bitrate,
           as.tx_qps,
           as.tx_fps,
           as.rx_bitrate,
           as.rx_rps,
           as.rx_fps,
           as.response_rate
    );
}
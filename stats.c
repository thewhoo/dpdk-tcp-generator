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

void write_json_stats(const struct app_config *app_config, unsigned lcore_id, uint64_t runtime_tsc) {

    const struct lcore_queue_conf *queue_conf = &app_config->dpdk_config.lcore_queue_conf[lcore_id];

    uint64_t runtime_usec = TSC_TO_USEC(runtime_tsc);

    if (!(app_config->user_config.supplied_args & ARG_RESULT_FILE))
        return;

    FILE *fp;
    char fn[1024];

    for (unsigned int i = 0; i < queue_conf->n_port; i++) {

        unsigned portid = queue_conf->port_list[i];

        snprintf(fn, 1024, "%s_lcore_%d_port_%d.json", app_config->user_config.result_file, lcore_id, portid);
        fp = fopen(fn, "w");
        if (fp == NULL) {
            RTE_LOG(ERR, TCPGEN, "write_json_stats: unable to open result file\n");
            return;
        }

        fprintf(fp, "{\n\t\"tx_bytes\": %lu,\n\t\"tx_frame_count\": %lu,\n\t\"tx_query_count\": %lu,\n\t",
                app_config->port_stats[portid].tx_bytes,
                app_config->port_stats[portid].tx_packets,
                app_config->port_stats[portid].tx_queries);
        fprintf(fp, "\"rx_bytes\": %lu,\n\t\"rx_frame_count\": %lu,\n\t\"rx_response_count\": %lu,\n\t",
               app_config->port_stats[portid].rx_bytes,
               app_config->port_stats[portid].rx_packets,
               app_config->port_stats[portid].rx_responses);
        fprintf(fp, "\"runtime_usec\": %lu,\n\t", runtime_usec);
        fprintf(fp, "\"response_stats\": {\n\t\t");

        int written = 0;
        for(int j = 0; j < DNS_RCODE_MAX_TYPES; j++) {
            if (app_config->port_stats[portid].rx_rcode[j] > 0) {
                fprintf(fp, "\"%d\": %lu,\n\t\t", j, app_config->port_stats[portid].rx_rcode[j]);
                written++;
            }
        }

        if(written > 0) {
            fseek(fp, -4, SEEK_CUR);
        }
        fprintf(fp, "\n\t}\n}");
    }

}

void print_all_stats(const struct app_config *app_config, unsigned lcore_id, uint64_t runtime_tsc) {

    const struct lcore_queue_conf *queue_conf = &app_config->dpdk_config.lcore_queue_conf[lcore_id];

    uint64_t runtime_usec = TSC_TO_USEC(runtime_tsc);
    uint64_t runtime_sec = TSC_TO_SEC(runtime_tsc);

    printf("lcore %u total runtime: %lu microseconds (%lu seconds)\n", lcore_id, runtime_usec, runtime_sec);
    for (unsigned int i = 0; i < queue_conf->n_port; i++) {

        unsigned portid = queue_conf->port_list[i];

        printf("Port %d stats:\n\tTX bytes: %lu\n\tTX packets: %lu\n\tTX queries: %lu\n\n\t",
               portid,
               app_config->port_stats[portid].tx_bytes,
               app_config->port_stats[portid].tx_packets,
               app_config->port_stats[portid].tx_queries);
        printf("RX bytes: %lu\n\tRX packets: %lu\n\tRX responses: %lu\n\t\t",
               app_config->port_stats[portid].rx_bytes,
               app_config->port_stats[portid].rx_packets,
               app_config->port_stats[portid].rx_responses);
        printf("NOERROR: %lu\n\t\tFORMERR: %lu\n\t\tSERVFAIL: %lu\n\t\tNXDOMAIN: %lu\n\t\tNOTIMP: %lu\n\t\tREFUSED: %lu\n\n\t",
               app_config->port_stats[portid].rx_rcode[DNS_RCODE_NOERROR],
               app_config->port_stats[portid].rx_rcode[DNS_RCODE_FORMERR],
               app_config->port_stats[portid].rx_rcode[DNS_RCODE_SERVFAIL],
               app_config->port_stats[portid].rx_rcode[DNS_RCODE_NXDOMAIN],
               app_config->port_stats[portid].rx_rcode[DNS_RCODE_NOTIMP],
               app_config->port_stats[portid].rx_rcode[DNS_RCODE_REFUSED]);
        printf("TX bitrate: %f Gbit/s\n\tTX QPS: %.2f\n\tTX FPS: %.2f\n\tRX bitrate: %f Gbit/s\n\tRX RPS: %.2f\n\tRX FPS: %.2f\n\tResponse rate: %.2f%%\n",
               ((app_config->port_stats[portid].tx_bytes << 3) / (double) runtime_usec) / 1000,
               (app_config->port_stats[portid].tx_queries / (double) runtime_usec) * 1000000,
               (app_config->port_stats[portid].tx_packets / (double) runtime_usec) * 1000000,
               ((app_config->port_stats[portid].rx_bytes << 3) / (double) runtime_usec) / 1000,
               (app_config->port_stats[portid].rx_responses / (double) runtime_usec) * 1000000,
               (app_config->port_stats[portid].rx_packets / (double) runtime_usec) * 1000000,
               ((app_config->port_stats[portid].rx_responses / (double) app_config->port_stats[portid].tx_queries)) *
               100);
    }
}
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Brno University of Technology
 *
 * tcpgen - a simple DPDK TCP DNS traffic generator
 * Author: Matej Postolka <xposto02@stud.fit.vutbr.cz>
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_eal.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>

#include "pcap.h"
#include "common.h"
#include "args.h"
#include "config.h"
#include "stats.h"
#include "wyrand.h"
#include "dpdk.h"

static void packet_6to4_ratio_set(struct app_config *app_config);

static void signal_handler(int signum);

static struct user_config default_user_config = {
        .tx_tsc_period = 1000000000, // 1 new connection every 1e9 CPU cycles
        .tsc_runtime = 0,
        .dst_port = 53,
        .ip_ipv6_probability = 0.0,
        .udp_probability = 0,
        .tcp_keepalive_probability = 0,
};

int main(int argc, char **argv) {
    int ret;

    // Initialize EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    tcpgen_force_quit = 0;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize application config
    struct app_config app_config;
    memset(&app_config, 0, sizeof(app_config));
    app_config.dpdk_config = dpdk_default_config;
    app_config.user_config = default_user_config;

    wyrand_seed();

    // Parse command-line arguments (non-EAL ones)
    if (tcpgen_parse_args(argc, argv, &app_config.user_config) < 0) {
        tcpgen_usage();
        rte_exit(EXIT_FAILURE, "Invalid TCPGEN arguments\n");
    }

    if (config_file_parse(app_config.user_config.config_file, &app_config.user_config) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot parse configuration file\n");
    }

    if (pcap_parse(&app_config) == -1) {
        rte_exit(EXIT_FAILURE, "Cannot parse PCAP file\n");
    }

    // Create packet mbuf mempool
    if (pktmbuf_mempool_init(&app_config) == -1) {
        rte_exit(EXIT_FAILURE, "Cannot initialize pktmbuf mempool\n");
    }

    // Explicit IPv6 probability in config overrides PCAP-derived probability
    packet_6to4_ratio_set(&app_config);

    // Map queues on ports to lcores
    lcore_port_queue_map(&app_config);

    if (init_ports(&app_config) == 0) {
        rte_exit(EXIT_FAILURE, "Port initialization failed\n");
    }

    if (check_all_ports_link_status(app_config.user_config.enabled_port_mask) == 0) {
        rte_exit(EXIT_FAILURE, "Cannot bring up all ports\n");
    }

    // Launch workers
    uint64_t start_tsc = rte_rdtsc();
    ret = run_worker_lcores(&app_config);
    uint64_t stop_tsc = rte_rdtsc();
    uint64_t runtime_tsc = stop_tsc - start_tsc;

    // Shutdown
    shutdown_ports(&app_config);

    pcap_list_destroy_all(app_config.pcap_lists);

    rte_mempool_free(app_config.dpdk_config.pktmbuf_pool);

    print_all_stats(&app_config, runtime_tsc);
    write_json_stats(&app_config, runtime_tsc);

    return ret;
}

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        RTE_LOG(INFO, TCPGEN, "Signal %d received, preparing to exit...\n", signum);
        tcpgen_force_quit = 1;
    }
}

static void packet_6to4_ratio_set(struct app_config *app_config) {
    if (app_config->user_config.supplied_config_opts & CONF_OPT_NUM_IP_IPV6_PROBABILITY) {
        if (app_config->user_config.ip_ipv6_probability >= 1.0f) {
            app_config->ipv6_probability = UINT64_MAX;
        } else if (app_config->user_config.ip_ipv6_probability <= 0.0f) {
            app_config->ipv6_probability = 0;
        } else {
            app_config->ipv6_probability = (uint64_t) (app_config->user_config.ip_ipv6_probability *
                                                       (double) UINT64_MAX);
        }
    } else {
        app_config->ipv6_probability = app_config->pcap_ipv6_probability;
    }
}

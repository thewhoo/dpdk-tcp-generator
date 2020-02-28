//
// Created by postolka on 10.02.20.
//

#include <stdio.h>
#include <stdbool.h>

#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_launch.h>

#include "common.h"
#include "dpdk.h"
#include "wyrand.h"
#include "conn.h"

#define RTE_RX_DESC_DEFAULT 1024
#define RTE_TX_DESC_DEFAULT 1024

struct dpdk_config dpdk_default_config = {
        .nb_rxd = RTE_RX_DESC_DEFAULT,
        .nb_txd = RTE_TX_DESC_DEFAULT,
        .rx_queue_per_lcore = 1,
        .port_conf = {
                .rxmode = {
                        .split_hdr_size = 0,
                        .mq_mode = ETH_MQ_RX_RSS,
                },
                .txmode = {
                        .mq_mode = ETH_MQ_TX_NONE,
                },
                .rx_adv_conf = {
                        .rss_conf = {
                                .rss_key = NULL,
                                .rss_hf = ETH_RSS_UDP | ETH_RSS_TCP,
                        },
                },
        },
        .pktmbuf_pool = NULL,
};

#define BURST_TX_DRAIN_US 100
#define MEMPOOL_CACHE_SIZE 256
#define PKTMBUF_MEMPOOL_SIZE 262144

#define PORT_CHECK_INTERVAL 100 // 100ms
#define PORT_MAX_CHECK_TIME 90 // 9s (90 * 100ms)

#define PORT_ENABLED(port_id, port_mask) ((port_mask) & (1 << (port_id)))

static int launch_one_lcore(struct app_config *app_config);

static void lcore_main_loop(struct app_config *app_config);

void lcore_port_queue_map(struct app_config *app_config) {
    unsigned port_id;
    unsigned lcore_id;
    struct lcore_queue_conf *qconf;

    // Initialize the port/queue configuration of each logical core
    RTE_ETH_FOREACH_DEV(port_id) {
        // Skip ports that are not enabled
        if (!PORT_ENABLED(port_id, app_config->user_config.enabled_port_mask))
            continue;

        uint16_t queue = 0;

        // Assign port queues to all enables lcores
        RTE_LCORE_FOREACH(lcore_id) {
            qconf = &app_config->dpdk_config.lcore_queue_conf[lcore_id];
            if (rte_lcore_is_enabled(lcore_id) && qconf->n_port < app_config->dpdk_config.rx_queue_per_lcore) {
                qconf->port_list[qconf->n_port] = port_id;
                qconf->port_queue[qconf->n_port] = queue;

                RTE_LOG(INFO, TCPGEN, "Assigned port %u (queue %u) to lcore %u\n", port_id, queue, lcore_id);

                queue++;
                qconf->n_port++;
            }
        }
    }
}

uint16_t init_ports(struct app_config *app_config) {

    unsigned port_id;
    unsigned lcore_id;
    uint16_t nb_ports = rte_eth_dev_count_total();
    uint16_t nb_ports_available = 0;

    // Use 1 RX and 1 TX queue per lcore on each port
    uint16_t rx_tx_queue_count = rte_lcore_count();

    int ret;

    // Check validity of port mask
    if (app_config->user_config.enabled_port_mask & ~((1 << nb_ports) - 1)) {
        RTE_LOG(CRIT, TCPGEN, "init_ports: invalid portmask - possible (0x%x)\n", (1 << nb_ports) - 1);
        return 0;
    }

    // Initialize each port
    RTE_ETH_FOREACH_DEV(port_id) {
        struct rte_eth_rxconf rxq_conf;
        struct rte_eth_txconf txq_conf;
        struct rte_eth_dev_info dev_info;
        struct rte_eth_conf local_port_conf = app_config->dpdk_config.port_conf;

        if (!PORT_ENABLED(port_id, app_config->user_config.enabled_port_mask)) {
            printf("Skipping disabled port %u\n", port_id);
            continue;
        }

        nb_ports_available++;

        RTE_LOG(INFO, TCPGEN, "Initializing port %u...\n", port_id);

        rte_eth_dev_info_get(port_id, &dev_info);

        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
            local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

        ret = rte_eth_dev_configure(port_id, rx_tx_queue_count, rx_tx_queue_count, &local_port_conf);
        if (ret < 0) {
            RTE_LOG(CRIT, TCPGEN, "init_ports: cannot configure device: err=%d, port=%u\n", ret, port_id);
            return 0;
        }

        ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &app_config->dpdk_config.nb_rxd,
                                               &app_config->dpdk_config.nb_txd);
        if (ret < 0) {
            RTE_LOG(CRIT, TCPGEN, "init_ports: cannot adjust number of descriptors: err=%d, port=%u\n", ret, port_id);
            return 0;
        }

        // Initialize 1 RX queue on port for each lcore
        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = local_port_conf.rxmode.offloads;
        RTE_LCORE_FOREACH(lcore_id) {
            uint16_t queue_id = rte_lcore_index(lcore_id);

            ret = rte_eth_rx_queue_setup(port_id, queue_id, app_config->dpdk_config.nb_rxd,
                                         rte_eth_dev_socket_id(port_id),
                                         &rxq_conf,
                                         app_config->dpdk_config.pktmbuf_pool);
            if (ret < 0) {
                RTE_LOG(CRIT, TCPGEN, "init_ports: RX queue setup failed: err=%d, port=%u, queue=%u\n", ret, port_id,
                        queue_id);
                return 0;
            }
        }

        // Initialize 1 TX queue on port for each lcore
        txq_conf = dev_info.default_txconf;
        txq_conf.offloads = local_port_conf.txmode.offloads;
        RTE_LCORE_FOREACH(lcore_id) {
            uint16_t queue_id = rte_lcore_index(lcore_id);

            ret = rte_eth_tx_queue_setup(port_id, queue_id, app_config->dpdk_config.nb_txd,
                                         rte_eth_dev_socket_id(port_id),
                                         &txq_conf);
            if (ret < 0) {
                RTE_LOG(CRIT, TCPGEN, "init_ports: TX queue setup failed: err=%d, port=%u, queue=%u\n", ret, port_id,
                        queue_id);
                return 0;
            }
        }

        // Initialize TX buffers
        app_config->dpdk_config.tx_buffer[port_id] = rte_zmalloc_socket("tx_buffer",
                                                                        RTE_ETH_TX_BUFFER_SIZE(RXTX_MAX_PKT_BURST), 0,
                                                                        rte_eth_dev_socket_id(port_id));
        if (app_config->dpdk_config.tx_buffer[port_id] == NULL) {
            RTE_LOG(CRIT, TCPGEN, "init_ports: cannot allocate TX buffer on port %u\n", port_id);
            return 0;
        }

        rte_eth_tx_buffer_init(app_config->dpdk_config.tx_buffer[port_id], RXTX_MAX_PKT_BURST);
        ret = rte_eth_tx_buffer_set_err_callback(app_config->dpdk_config.tx_buffer[port_id],
                                                 rte_eth_tx_buffer_count_callback,
                                                 &app_config->port_stats[port_id].tx_dropped);
        if (ret < 0) {
            RTE_LOG(CRIT, TCPGEN, "init_ports: cannot set error callback for TX buffer on port %u\n", port_id);
            return 0;
        }

        // Start device
        ret = rte_eth_dev_start(port_id);
        if (ret < 0) {
            RTE_LOG(CRIT, TCPGEN, "init_ports: cannot start device: err=%d, port=%u\n", ret, port_id);
            return 0;
        }
        rte_eth_promiscuous_enable(port_id);
    }

    return nb_ports_available;
}

void shutdown_ports(const struct app_config *app_config) {
    unsigned port_id;

    RTE_ETH_FOREACH_DEV(port_id) {
        if (!PORT_ENABLED(port_id, app_config->user_config.enabled_port_mask))
            continue;

        RTE_LOG(INFO, TCPGEN, "Shutting down port %u\n", port_id);

        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
    }

    RTE_LOG(INFO, TCPGEN, "All ports shut down\n");
}

int pktmbuf_mempool_init(struct app_config *app_config) {
    uint16_t nb_ports = rte_eth_dev_count_avail();

    if (nb_ports == 0) {
        RTE_LOG(CRIT, TCPGEN, "pktmbuf_mempool_init: no available ethernet ports\n");
        return -1;
    }

    app_config->dpdk_config.pktmbuf_pool = rte_pktmbuf_pool_create("pktmbuf_pool", PKTMBUF_MEMPOOL_SIZE,
                                                                   MEMPOOL_CACHE_SIZE, 0,
                                                                   RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (app_config->dpdk_config.pktmbuf_pool == NULL) {
        RTE_LOG(CRIT, TCPGEN, "pktmbuf_mempool_init: failed to allocate pktmbuf mempool\n");
        return -1;
    }

    return 0;
}

uint8_t check_all_ports_link_status(uint32_t port_mask) {
    uint16_t portid;
    uint8_t count;
    uint8_t all_ports_up = 0;
    uint8_t print_flag = 0;
    struct rte_eth_link link;

    RTE_LOG(INFO, TCPGEN, "Checking link status...");

    for (count = 0; count <= PORT_MAX_CHECK_TIME; count++) {
        if (tcpgen_force_quit)
            return all_ports_up;
        all_ports_up = 1;

        RTE_ETH_FOREACH_DEV(portid) {

            if (tcpgen_force_quit)
                return all_ports_up;
            if (!PORT_ENABLED(portid, port_mask))
                continue;

            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);

            // Print link status if flag set
            if (print_flag == 1) {
                if (link.link_status)
                    RTE_LOG(INFO, TCPGEN,
                            "Port %d link up. Speed %u Mbps - %s\n",
                            portid, link.link_speed,
                            (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                            ("full-duplex") : ("half-duplex\n"));
                else
                    RTE_LOG(INFO, TCPGEN, "Port %d Link Down\n", portid);
                continue;
            }

            // Clear all_ports_up flag if any link down
            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }

        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(PORT_CHECK_INTERVAL);
        }

        // Set the print_flag if all ports up or timeout
        if (all_ports_up == 1 || count == (PORT_MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf(" done\n");
        }
    }

    return all_ports_up;
}

int run_worker_lcores(struct app_config *app_config) {
    rte_eal_mp_remote_launch((lcore_function_t *) launch_one_lcore, app_config, CALL_MASTER);

    unsigned lcore_id;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            return -1;
        }
    }

    return 0;
}

static int launch_one_lcore(struct app_config *app_config) {
    lcore_main_loop(app_config);
    return 0;
}

static void lcore_main_loop(struct app_config *app_config) {
    struct rte_mbuf *pkts_burst[RXTX_MAX_PKT_BURST];
    struct rte_mbuf *m;
    struct rte_eth_dev_tx_buffer *tx_buffer;

    unsigned lcore_id = rte_lcore_id();
    struct lcore_queue_conf *qconf = &app_config->dpdk_config.lcore_queue_conf[lcore_id];

    unsigned i, j, port_id, nb_rx;
    uint16_t queue_id;

    if (qconf->n_port == 0) {
        RTE_LOG(INFO, TCPGEN, "lcore %u has nothing to do\n", lcore_id);
        return;
    }

    for (i = 0; i < qconf->n_port; i++) {
        port_id = qconf->port_list[i];
        queue_id = qconf->port_queue[i];
        RTE_LOG(INFO, TCPGEN, "Launched lcore %u <-> port %u (queue %d)\n", lcore_id, port_id, queue_id);
    }

    const uint64_t start_tsc = rte_rdtsc();
    const uint64_t drain_tsc_period = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    uint64_t cur_tsc;

    // TX buffer drain timestamps
    uint64_t prev_drain_tsc = 0;
    uint64_t drain_diff;

    // New connection timestamps
    uint64_t prev_open_tsc = 0;
    uint64_t open_diff;

    uint64_t keepalive_counter = 0;

    while (!tcpgen_force_quit) {
        cur_tsc = rte_rdtsc();

        if (unlikely(app_config->user_config.tsc_runtime > 0 &&
                     (cur_tsc - start_tsc) > app_config->user_config.tsc_runtime)) {
            tcpgen_force_quit = 1;
        }

        // Flush TX buffers every drain_tsc_period
        drain_diff = cur_tsc - prev_drain_tsc;
        if (unlikely(drain_diff > drain_tsc_period)) {
            for (i = 0; i < qconf->n_port; i++) {
                port_id = qconf->port_list[i];
                queue_id = qconf->port_queue[i];
                tx_buffer = app_config->dpdk_config.tx_buffer[port_id];
                rte_eth_tx_buffer_flush(port_id, queue_id, tx_buffer);
            }
            prev_drain_tsc = cur_tsc;
        }

        open_diff = cur_tsc - prev_open_tsc;
        for (i = 0; i < qconf->n_port; i++) {
            port_id = qconf->port_list[i];
            queue_id = qconf->port_queue[i];

            // Open new connection every tx_tsc_period
            if (open_diff > app_config->user_config.tx_tsc_period) {
                // Reset counter
                prev_open_tsc = cur_tsc;

                // Do not open new connection if previous connection was kept alive
                if (keepalive_counter > 0) {
                    keepalive_counter--;
                } else if (wyrand() < app_config->ipv6_probability) {
                    if (wyrand() < app_config->user_config.udp_probability)
                        generate_udp6_query(port_id, queue_id, app_config);
                    else
                        tcp6_open(port_id, queue_id, app_config);
                } else {
                    if (wyrand() < app_config->user_config.udp_probability)
                        generate_udp4_query(port_id, queue_id, app_config);
                    else
                        tcp4_open(port_id, queue_id, app_config);
                }

            }

            // Handle incoming traffic
            nb_rx = rte_eth_rx_burst(port_id, queue_id, pkts_burst, RXTX_MAX_PKT_BURST);

            app_config->lcore_stats[lcore_id].rx_packets += nb_rx;

            for (j = 0; j < nb_rx; j++) {
                m = pkts_burst[j];
                rte_prefetch0(rte_pktmbuf_mtod(m, void *));
                handle_incoming(m, port_id, queue_id, app_config, &keepalive_counter);
            }
        }
    }

    // Flush TX buffers on all ports
    for (i = 0; i < qconf->n_port; i++) {
        port_id = qconf->port_list[i];
        queue_id = qconf->port_queue[i];
        tx_buffer = app_config->dpdk_config.tx_buffer[port_id];
        rte_eth_tx_buffer_flush(port_id, queue_id, tx_buffer);
    }
}
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Brno University of Technology
 *
 * tcpgen - a simple DPDK TCP DNS traffic generator
 * Author: Matej Postolka <xposto02@stud.fit.vutbr.cz>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <rte_log.h>
#include <rte_cycles.h>

#include "common.h"
#include "args.h"

#define ARGS_REQUIRED (ARG_PORT_MASK | ARG_CONFIG_FILE | ARG_PCAP_FILE)
#define ARGS_VALID(args) (((args) & ARGS_REQUIRED) == ARGS_REQUIRED)

#define USEC_TO_TSC(usec) ((usec) * (rte_get_tsc_hz() / 1000000))

static int tcpgen_parse_portmask(const char *portmask);

static const char short_options[] =
        "p:"  // portmask
        "g:"  // tcp gap
        "c:"  // config file
        "r:"  // runtime
;

#define CMD_LINE_OPT_PCAP_FILE "pcap"
#define CMD_LINE_OPT_RESULT_FILE "results"

enum {
    CMD_LINE_OPT_MIN_NUM = 256,
    CMD_LINE_OPT_PCAP_FILE_NUM,
    CMD_LINE_OPT_RESULT_FILE_NUM,
};

static const struct option long_options[] = {
        {CMD_LINE_OPT_PCAP_FILE,   required_argument, 0, CMD_LINE_OPT_PCAP_FILE_NUM},
        {CMD_LINE_OPT_RESULT_FILE, required_argument, 0, CMD_LINE_OPT_RESULT_FILE_NUM},
        {NULL, 0,                                     0, 0}
};


int tcpgen_parse_args(int argc, char **argv, struct user_config *config) {
    int opt, ret;
    int option_index;
    char *endptr; // strtoul
    char **argvopt;
    char *prgname = argv[0];

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, short_options, long_options, &option_index)) != EOF) {
        switch (opt) {
            case 'p':
                config->enabled_port_mask = tcpgen_parse_portmask(optarg);
                if (config->enabled_port_mask == 0) {
                    RTE_LOG(ERR, TCPGEN, "args: invalid portmask\n");
                    return -1;
                }
                config->supplied_args |= ARG_PORT_MASK;
                break;

            case 'g':
                config->tx_tsc_period = USEC_TO_TSC(strtoul(optarg, &endptr, 10));
                if(*endptr != '\0') {
                    RTE_LOG(ERR, TCPGEN, "args: invalid tcp gap\n");
                    return -1;
                }
                config->supplied_args |= ARG_TSC_PERIOD;
                break;

            case 'c':
                config->config_file = optarg;
                config->supplied_args |= ARG_CONFIG_FILE;
                break;

            case 'r':
                config->tsc_runtime = USEC_TO_TSC((strtoul(optarg, &endptr, 10)));
                if(*endptr != '\0') {
                    RTE_LOG(ERR, TCPGEN, "args: invalid runtime\n");
                    return -1;
                }
                config->supplied_args |= ARG_RUNTIME;
                break;

            case CMD_LINE_OPT_PCAP_FILE_NUM:
                config->pcap_file = optarg;
                config->supplied_args |= ARG_PCAP_FILE;
                break;

            case CMD_LINE_OPT_RESULT_FILE_NUM:
                config->result_file = optarg;
                config->supplied_args |= ARG_RESULT_FILE;
                break;

            default:
                return -1;
        }
    }

    if (!ARGS_VALID(config->supplied_args)) {
        // Missing required arguments
        RTE_LOG(CRIT, TCPGEN, "args: invalid combination of supplied arguments\n");
        return -1;
    }

    if (optind >= 0)
        argv[optind - 1] = prgname;

    ret = optind - 1;
    optind = 1; // reset getopt lib
    return ret;
}

static int tcpgen_parse_portmask(const char *portmask) {
    char *end = NULL;
    unsigned long pm;

    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

void tcpgen_usage(void) {
    printf("tcpgen [EAL options] -- -p PORTMASK -c CONFIG --pcap PCAP [-g USEC_TCP_GAP] [-r USEC_RUNTIME] [--results PREFIX]\n"
           "  -p PORTMASK: Hexadecimal bitmask of ports to generate traffic on\n"
           "  -g USEC_TCP_GAP: Open new TCP connection no earlier than every USEC_TCP_GAP microseconds\n"
           "  -r USEC_RUNTIME: Stop after USEC_RUNTIME microseconds\n"
           "  -c CONFIG: Generator configuration file (see documentation)\n"
           "  --pcap PCAP: File containing reference packets for generating queries\n"
           "  --results PREFIX: Prefix of file containing per-lcore results in JSON format\n");
}
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

#include "common.h"
#include "args.h"

#define ARGS_REQUIRED_PCAP (ARG_PORT_MASK | ARG_CONFIG_FILE | ARG_PCAP_FILE)
#define ARGS_REQUIRED_QNAME (ARG_PORT_MASK | ARG_CONFIG_FILE | ARG_QNAME_FILE)
#define ARGS_VALID(args) (((((args) & ARGS_REQUIRED_PCAP) == ARGS_REQUIRED_PCAP) && !((args) & ARG_QNAME_FILE)) || ((((args) & ARGS_REQUIRED_QNAME) == ARGS_REQUIRED_QNAME) && !((args) & ARG_PCAP_FILE)))

static int tcpgen_parse_portmask(const char *portmask);

static const char short_options[] =
        "p:"  // portmask
        "t:"  // tcp gap
        "c:"  // config file
;

#define CMD_LINE_OPT_PCAP_FILE "pcap"
#define CMD_LINE_OPT_QNAME_FILE "qnames"

enum {
    CMD_LINE_OPT_MIN_NUM = 256,
    CMD_LINE_OPT_PCAP_FILE_NUM,
    CMD_LINE_OPT_QNAME_FILE_NUM,
};

static const struct option long_options[] = {
        {CMD_LINE_OPT_PCAP_FILE,      required_argument, 0, CMD_LINE_OPT_PCAP_FILE_NUM},
        {CMD_LINE_OPT_QNAME_FILE,     required_argument, 0, CMD_LINE_OPT_QNAME_FILE_NUM},
        {NULL, 0,                                        0, 0}
};


int tcpgen_parse_args(int argc, char **argv, struct user_config *config) {
    int opt, ret;
    int option_index;
    char **argvopt;
    char *prgname = argv[0];

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, short_options, long_options, &option_index)) != EOF) {
        switch (opt) {
            case 'p':
                config->enabled_port_mask = tcpgen_parse_portmask(optarg);
                if (config->enabled_port_mask == 0) {
                    RTE_LOG(CRIT, TCPGEN, "args: invalid portmask\n");
                    return -1;
                }
                config->supplied_args |= ARG_PORT_MASK;
                break;

            case 't':
                config->tx_tsc_period = strtoull(optarg, NULL, 10);
                config->supplied_args |= ARG_TSC_PERIOD;
                break;

            case 'c':
                config->config_file = optarg;
                config->supplied_args |= ARG_CONFIG_FILE;
                break;

            case CMD_LINE_OPT_PCAP_FILE_NUM:
                config->pcap_file = optarg;
                config->supplied_args |= ARG_PCAP_FILE;
                break;

            case CMD_LINE_OPT_QNAME_FILE_NUM:
                config->qname_file = optarg;
                config->supplied_args |= ARG_QNAME_FILE;
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
    printf("tcpgen [EAL options] -- -p PORTMASK [-t TCP_GAP] -c CONFIG {--pcap PCAP | --qnames QNAMES}\n"
           "  -p PORTMASK: Hexadecimal bitmask of ports to generate traffic on\n"
           "  -t TCP_GAP: TSC delay before opening a new TCP connection\n"
           "  -c CONFIG: Generator configuration file (see documentation)\n"
           "  --pcap PCAP: File containing reference packets for generating queries\n"
           "  --qnames QNAMES: File containing QNAMEs and record types used to derive queries (see documentation)\n");
}
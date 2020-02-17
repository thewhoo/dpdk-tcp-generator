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

static int parse_portmask(const char *portmask);

static int parse_timestr(const char *timestr, uint64_t *nsec_val);

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
    char **argvopt;
    char *prgname = argv[0];

    uint64_t nsec_result;

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, short_options, long_options, &option_index)) != EOF) {
        switch (opt) {
            case 'p':
                config->enabled_port_mask = parse_portmask(optarg);
                if (config->enabled_port_mask == 0) {
                    RTE_LOG(ERR, TCPGEN, "args: invalid portmask\n");
                    return -1;
                }
                config->supplied_args |= ARG_PORT_MASK;
                break;

            case 'g':
                if (parse_timestr(optarg, &nsec_result) == -1) {
                    RTE_LOG(ERR, TCPGEN, "args: invalid tcp gap\n");
                    return -1;
                }
                config->tx_tsc_period = NSEC_TO_TSC(nsec_result, rte_get_tsc_hz());
                config->supplied_args |= ARG_TSC_PERIOD;
                break;

            case 'c':
                config->config_file = optarg;
                config->supplied_args |= ARG_CONFIG_FILE;
                break;

            case 'r':
                if (parse_timestr(optarg, &nsec_result) == -1) {
                    RTE_LOG(ERR, TCPGEN, "args: invalid runtime\n");
                    return -1;
                }
                config->tsc_runtime = NSEC_TO_TSC(nsec_result, rte_get_tsc_hz());
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

static int parse_portmask(const char *portmask) {
    char *end = NULL;
    unsigned long pm;

    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

static int parse_timestr(const char *timestr, uint64_t *nsec_val) {
    char nr_buf[128];
    char unit_buf[128];

    uint32_t index = 0;
    for (; *timestr > 47 && *timestr < 58 && index < 127; timestr++) {
        nr_buf[index] = *timestr;
        index++;
    }
    nr_buf[index] = '\0';

    index = 0;
    for (; *timestr != '\0' && index < 127; timestr++) {
        unit_buf[index] = *timestr;
        index++;
    }
    unit_buf[index] = '\0';

    char *endptr;
    *nsec_val = strtoul(nr_buf, &endptr, 10);
    if (*endptr != '\0')
        return -1;

    if (strcmp(unit_buf, "h") == 0)
        *nsec_val *= 1000000000ULL * 3600;
    else if (strcmp(unit_buf, "m") == 0)
        *nsec_val *= 1000000000ULL * 60;
    else if (strcmp(unit_buf, "s") == 0)
        *nsec_val *= 1000000000;
    else if (strcmp(unit_buf, "ms") == 0)
        *nsec_val *= 1000000;
    else if (strcmp(unit_buf, "us") == 0 || strcmp(unit_buf, "") == 0)
        *nsec_val *= 1000;
    else if (strcmp(unit_buf, "ns") == 0)
        ;
    else
        return -1;

    return 0;
}

void tcpgen_usage(void) {
    printf("tcpgen [EAL options] -- -p PORTMASK -c CONFIG --pcap PCAP [-g USEC_TCP_GAP] [-r USEC_RUNTIME] [--results RESULTS]\n"
           "-p PORTMASK: Hexadecimal bitmask of ports to generate traffic on\n"
           "-c CONFIG: Generator configuration file (see example.conf)\n"
           "--pcap PCAP: File containing reference packets for generating queries\n"
           "-g USEC_TCP_GAP: Open a new TCP connection no earlier than every TCP_GAP{h|m|s|ms|us|ns} (default: microseconds)\n"
           "-r USEC_RUNTIME: Stop after RUNTIME{h|m|s|ms|us|ns} (default: microseconds)\n"
           "--results RESULTS: Name of file containing per-lcore results in JSON format\n");
}
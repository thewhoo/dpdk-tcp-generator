/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Brno University of Technology
 *
 * tcpgen - a simple DPDK TCP DNS traffic generator
 * Author: Matej Postolka <xposto02@stud.fit.vutbr.cz>
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_log.h>

#include "config.h"
#include "common.h"

#define CONF_MAC_MASK (CONF_OPT_NUM_SRC_MAC | CONF_OPT_NUM_DST_MAC)
#define CONF_IP4_MASK (CONF_OPT_NUM_IP4_SRC_NET | CONF_OPT_NUM_IP4_SRC_MASK | CONF_OPT_NUM_IP4_DST_IP | CONF_OPT_NUM_TCP_DST_PORT)
#define CONF_IP6_MASK (CONF_OPT_NUM_IP6_SRC_NET | CONF_OPT_NUM_IP6_SRC_MASK | CONF_OPT_NUM_IP6_DST_IP | CONF_OPT_NUM_TCP_DST_PORT)
#define CONF_VALID(supplied_opts) (((supplied_opts) == (CONF_MAC_MASK | CONF_IP4_MASK)) || ((supplied_opts) == (CONF_MAC_MASK | CONF_IP6_MASK)) || ((supplied_opts) == (CONF_MAC_MASK | CONF_IP4_MASK | CONF_IP6_MASK)))

#define CONF_OPT_SRC_MAC "source-mac"
#define CONF_OPT_DST_MAC "destination-mac"
#define CONF_OPT_IP4_SRC_NET "ipv4-source-network"
#define CONF_OPT_IP4_SRC_MASK "ipv4-source-netmask"
#define CONF_OPT_IP4_DST_IP "ipv4-destination-ip"
#define CONF_OPT_IP6_SRC_NET "ipv6-source-network"
#define CONF_OPT_IP6_SRC_MASK "ipv6-source-netmask"
#define CONF_OPT_IP6_DST_IP "ipv6-destination-ip"
#define CONF_OPT_TCP_DST_PORT "tcp-destination-port"

#define STR_EQUAL(str1, str2, len) (strncmp((str1), (str2), (len)) == 0)
#define CHAR_IS_WHITESPACE(ch) (((ch) == ' ') || ((ch) == '\t') || ((ch) == '\r') || ((ch) == '\n') || ((ch) == EOF))

enum {
    CONF_AUTOMATON_STATE_KEYWORD,
    CONF_AUTOMATON_STATE_SRC_MAC,
    CONF_AUTOMATON_STATE_DST_MAC,
    CONF_AUTOMATON_STATE_IP4_SRC_NET,
    CONF_AUTOMATON_STATE_IP4_SRC_MASK,
    CONF_AUTOMATON_STATE_IP4_DST_IP,
    CONF_AUTOMATON_STATE_IP6_SRC_NET,
    CONF_AUTOMATON_STATE_IP6_SRC_MASK,
    CONF_AUTOMATON_STATE_IP6_DST_IP,
    CONF_AUTOMATON_STATE_TCP_DST_PORT,
};

#define AUTOMATON_EXIT_FAIL(param) do {RTE_LOG(ERR, TCPGEN, "config_file_parse: failed to parse value of %s\n", (param)); return -1;} while (0)

static int parse_mac_addr_str(const char *mac_addr_str, uint8_t *dest);

static int parse_mac_addr_str(const char *mac_addr_str, uint8_t *dest) {
    char buf[128];
    int buf_index = 0;
    int str_index = 0;
    int mac_addr_byte_index = 0;
    char c;

    do {
        c = mac_addr_str[str_index];

        if (buf_index > 127 || mac_addr_byte_index > 5) {
            return -1;
        }

        if (c == ':' || c == '\0') {
            buf[buf_index] = '\0';
            char *endptr;
            dest[mac_addr_byte_index] = strtoul(buf, &endptr, 16);
            if (*endptr != '\0') {
                return -1;
            }
            mac_addr_byte_index++;
            buf_index = 0;
        }
        else {
            buf[buf_index] = c;
            buf_index++;
        }

        str_index++;
    }
    while (c != '\0');

    if (mac_addr_byte_index == 6)
        return 0;
    else
        return -1;
}

int config_file_parse(const char *filename, struct user_config *config) {
    FILE *fp = fopen(filename, "r");
    if(fp == NULL) {
        RTE_LOG(ERR, TCPGEN, "config_file_parse: failed to open configuration file\n");
        return -1;
    }

    char buf[1024];
    uint32_t buf_pos = 0;

    uint8_t conf_automaton_state = CONF_AUTOMATON_STATE_KEYWORD;
    uint8_t skip_line = 0;

    int ch;
    do {
        if (buf_pos > 1023) {
            RTE_LOG(ERR, TCPGEN, "config_file_parse: invalid data in configuration file\n");
            return -1;
        }

        ch = fgetc(fp);

        if (ch == '\n')
            skip_line = 0;
        if (skip_line)
            continue;

        if (ch == '#') {
            skip_line = 1;
        } else if (CHAR_IS_WHITESPACE(ch) && buf_pos > 0 && conf_automaton_state == CONF_AUTOMATON_STATE_KEYWORD) {
            buf[buf_pos] = '\0';

            if (STR_EQUAL(buf, CONF_OPT_SRC_MAC, buf_pos)) {
                conf_automaton_state = CONF_AUTOMATON_STATE_SRC_MAC;
            } else if (STR_EQUAL(buf, CONF_OPT_DST_MAC, buf_pos)) {
                conf_automaton_state = CONF_AUTOMATON_STATE_DST_MAC;
            } else if (STR_EQUAL(buf, CONF_OPT_IP4_SRC_NET, buf_pos)) {
                conf_automaton_state = CONF_AUTOMATON_STATE_IP4_SRC_NET;
            } else if (STR_EQUAL(buf, CONF_OPT_IP4_SRC_MASK, buf_pos)) {
                conf_automaton_state = CONF_AUTOMATON_STATE_IP4_SRC_MASK;
            } else if (STR_EQUAL(buf, CONF_OPT_IP4_DST_IP, buf_pos)) {
                conf_automaton_state = CONF_AUTOMATON_STATE_IP4_DST_IP;
            } else if (STR_EQUAL(buf, CONF_OPT_IP6_SRC_NET, buf_pos)) {
                conf_automaton_state = CONF_AUTOMATON_STATE_IP6_SRC_NET;
            } else if (STR_EQUAL(buf, CONF_OPT_IP6_SRC_MASK, buf_pos)) {
                conf_automaton_state = CONF_AUTOMATON_STATE_IP6_SRC_MASK;
            } else if (STR_EQUAL(buf, CONF_OPT_IP6_DST_IP, buf_pos)) {
                conf_automaton_state = CONF_AUTOMATON_STATE_IP6_DST_IP;
            } else if (STR_EQUAL(buf, CONF_OPT_TCP_DST_PORT, buf_pos)) {
                conf_automaton_state = CONF_AUTOMATON_STATE_TCP_DST_PORT;
            } else {
                RTE_LOG(ERR, TCPGEN, "config_file_parse: unkown configuration key: %s\n", buf);
                return -1;
            }

            buf_pos = 0;
        } else if (CHAR_IS_WHITESPACE(ch) && buf_pos > 0 && conf_automaton_state != CONF_AUTOMATON_STATE_KEYWORD) {
            buf[buf_pos] = '\0';
            char *endptr; // strtoul

            switch (conf_automaton_state) {
                case CONF_AUTOMATON_STATE_SRC_MAC:
                    if (parse_mac_addr_str(buf, config->src_mac) != 0) {
                        AUTOMATON_EXIT_FAIL(CONF_OPT_SRC_MAC);
                    }
                    config->supplied_config_opts |= CONF_OPT_NUM_SRC_MAC;
                    break;
                case CONF_AUTOMATON_STATE_DST_MAC:
                    if (parse_mac_addr_str(buf, config->dst_mac) != 0) {
                        AUTOMATON_EXIT_FAIL(CONF_OPT_DST_MAC);
                    }
                    config->supplied_config_opts |= CONF_OPT_NUM_DST_MAC;
                    break;
                case CONF_AUTOMATON_STATE_IP4_SRC_NET:
                    if (inet_pton(AF_INET, buf, config->ip4_src_subnet) != 1) {
                        AUTOMATON_EXIT_FAIL(CONF_OPT_IP4_SRC_NET);
                    }
                    config->supplied_config_opts |= CONF_OPT_NUM_IP4_SRC_NET;
                    break;
                case CONF_AUTOMATON_STATE_IP4_SRC_MASK:
                    if (inet_pton(AF_INET, buf, config->ip4_src_netmask) != 1) {
                        AUTOMATON_EXIT_FAIL(CONF_OPT_IP4_SRC_MASK);
                    }
                    config->ip4_src_rand_bit_mask = rte_be_to_cpu_32(~*(uint32_t *)config->ip4_src_netmask);
                    config->supplied_config_opts |= CONF_OPT_NUM_IP4_SRC_MASK;
                    break;
                case CONF_AUTOMATON_STATE_IP4_DST_IP:
                    if (inet_pton(AF_INET, buf, config->ip4_dst_addr) != 1) {
                        AUTOMATON_EXIT_FAIL(CONF_OPT_IP4_DST_IP);
                    }
                    config->supplied_config_opts |= CONF_OPT_NUM_IP4_DST_IP;
                    break;
                case CONF_AUTOMATON_STATE_IP6_SRC_NET:
                    if (inet_pton(AF_INET6, buf, config->ip6_src_subnet) != 1) {
                        AUTOMATON_EXIT_FAIL(CONF_OPT_IP6_SRC_NET);
                    }
                    config->supplied_config_opts |= CONF_OPT_NUM_IP6_SRC_NET;
                    break;
                case CONF_AUTOMATON_STATE_IP6_SRC_MASK:
                    if (inet_pton(AF_INET6, buf, config->ip6_src_netmask) != 1) {
                        AUTOMATON_EXIT_FAIL(CONF_OPT_IP6_SRC_MASK);
                    }
                    config->ip6_src_rand_bit_mask[0] = rte_be_to_cpu_64(~*(uint64_t *)&config->ip6_src_netmask[0]);
                    config->ip6_src_rand_bit_mask[1] = rte_be_to_cpu_64(~*(uint64_t *)&config->ip6_src_netmask[8]);
                    config->supplied_config_opts |= CONF_OPT_NUM_IP6_SRC_MASK;
                    break;
                case CONF_AUTOMATON_STATE_IP6_DST_IP:
                    if (inet_pton(AF_INET6, buf, config->ip6_dst_addr) != 1) {
                        AUTOMATON_EXIT_FAIL(CONF_OPT_IP6_DST_IP);
                    }
                    config->supplied_config_opts |= CONF_OPT_NUM_IP6_DST_IP;
                    break;
                case CONF_AUTOMATON_STATE_TCP_DST_PORT:
                    config->tcp_dst_port = strtoul(buf, &endptr, 10);
                    if (*endptr != '\0') {
                        AUTOMATON_EXIT_FAIL(CONF_OPT_TCP_DST_PORT);
                    }
                    config->supplied_config_opts |= CONF_OPT_NUM_TCP_DST_PORT;
                    break;
                default:
                    RTE_LOG(ERR, TCPGEN, "config_file_parse: invalid conf automaton state\n");
                    return -1;
            }

            conf_automaton_state = CONF_AUTOMATON_STATE_KEYWORD;
            buf_pos = 0;
        } else if (!CHAR_IS_WHITESPACE(ch)) {
            buf[buf_pos] = ch;
            buf_pos++;
        }
    } while (ch != EOF);

    fclose(fp);

    if (conf_automaton_state != CONF_AUTOMATON_STATE_KEYWORD || buf_pos != 0) {
        RTE_LOG(ERR, TCPGEN, "config_file_parse: malformed configuration file\n");
        return -1;
    }

    if (!CONF_VALID(config->supplied_config_opts)) {
        RTE_LOG(ERR, TCPGEN, "config_file_parse: invalid combination of configuration options (see documentation)\n");
        return -1;
    }

    return 0;
}
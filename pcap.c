/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Brno University of Technology
 *
 * tcpgen - a simple DPDK TCP DNS traffic generator
 * Author: Matej Postolka <xposto02@stud.fit.vutbr.cz>
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_log.h>
#include <rte_lcore.h>

#include "pcap.h"
#include "common.h"

#define MAGIC_USEC_TS 0xa1b2c3d4
#define MAGIC_NSEC_TS 0xa1b23c4d

static struct pcap_list_entry *pcap_list_insert(struct pcap_list *list, uint8_t *payload, uint32_t payload_len);
static void pcap_list_init_all(struct pcap_list *pcap_lists);
static void pcap_list_destroy(struct pcap_list *list);

static struct pcap_list_entry *pcap_list_insert(struct pcap_list *list, uint8_t *payload, uint32_t payload_len)
{
    struct pcap_list_entry *new_entry = rte_malloc("pcap_list_entry", sizeof(struct pcap_list_entry), 0);
    if(new_entry == NULL) {
        RTE_LOG(CRIT, TCPGEN, "pcap_list_insert: rte_malloc (pcap_list_entry) failed\n");
        return NULL;
    }

    new_entry->pcap_payload = payload;
    new_entry->payload_len = payload_len;
    new_entry->next = NULL;

    if(list->first == NULL) {
        list->first = list->last = list->current = new_entry;
    }
    else {
        list->last->next = new_entry;
        list->last = new_entry;
    }

    return new_entry;
}

struct pcap_list_entry *pcap_list_get(const struct pcap_list *list)
{
    struct pcap_list_entry *current = list->current;

    if(current == NULL) {
        return NULL;
    }

    return current;
}

static void pcap_list_init_all(struct pcap_list *pcap_lists) {
    for(int i = 0; i < RTE_MAX_LCORE; i++) {
        pcap_lists[i].first = pcap_lists[i].current = pcap_lists[i].last = NULL;
    }
}

void pcap_list_destroy_all(struct pcap_list *pcap_lists) {
    for(int i = 0; i < RTE_MAX_LCORE; i++) {
        pcap_list_destroy(&pcap_lists[i]);
    }
}

void pcap_list_next(struct pcap_list *list)
{
    if(list->current == NULL)
        return;

    if(list->current->next == NULL)
        list->current = list->first;
    else
        list->current = list->current->next;
}

static void pcap_list_destroy(struct pcap_list *list)
{
    struct pcap_list_entry *next;
    struct pcap_list_entry *current;

    for(current = list->first; current != NULL;) {
        rte_free(current->pcap_payload);
        next = current->next;
        rte_free(current);
        current = next;
    }

    list->first = list->current = list->last = NULL;
}

int pcap_parse(struct app_config *config)
{
    pcap_list_init_all(config->pcap_lists);

    FILE *fp = fopen(config->user_config.pcap_file, "r");
    if(fp == NULL) {
        RTE_LOG(ERR, TCPGEN, "pcap_parse: failed to open pcap file\n");
        return -1;
    }

    struct pcap_global_hdr hdr;
    if(fread(&hdr, sizeof(hdr), 1, fp) != 1) {
        RTE_LOG(ERR, TCPGEN, "pcap_parse: failed to read pcap global header\n");
        return -1;
    }

    if(hdr.magic_number != MAGIC_USEC_TS && hdr.magic_number != MAGIC_NSEC_TS) {
        RTE_LOG(ERR, TCPGEN, "pcap_parse: invalid or unsupported magic in pcap global header\n");
        return -1;
    }

    // Insert packets round-robin in per-lcore pcap lists (start with master)
    unsigned lcore_id = rte_get_master_lcore();

    size_t pcap_bytes = 0;
    uint32_t pcap_records = 0;

    uint32_t ipv4_query_count = 0;
    uint32_t ipv6_query_count = 0;

    struct pcap_packet_hdr pkt_hdr;
    struct ether_hdr eth_hdr;
    struct ipv4_hdr ip4_hdr;
    struct ipv6_hdr ip6_hdr;
    struct udp_hdr udp_hdr;
    size_t read_bytes;

    while(fread(&pkt_hdr, sizeof(pkt_hdr), 1, fp) == 1) {

        uint32_t *query_counter = NULL;
        read_bytes = 0;

        // Read L2 header
        if(fread(&eth_hdr, sizeof(eth_hdr), 1, fp) != 1) {
            RTE_LOG(WARNING, TCPGEN, "pcap: failed to read ether header\n");
            goto packet_seek_end;
        }

        read_bytes += sizeof(eth_hdr);

        // Read L3 header
        uint16_t ether_type = rte_be_to_cpu_16(eth_hdr.ether_type);

        if(ether_type == ETHER_TYPE_IPv4) {

            if(fread(&ip4_hdr, sizeof(ip4_hdr), 1, fp) != 1) {
                RTE_LOG(WARNING, TCPGEN, "pcap_parse: failed to read ipv4 header\n");
                goto packet_seek_end;
            }

            read_bytes += sizeof(ip4_hdr);

            // Check next header
            if(ip4_hdr.next_proto_id != IPPROTO_UDP) {
                RTE_LOG(WARNING, TCPGEN, "pcap_parse: unsupported non-UDP next protocol id in ivp4 header\n");
                goto packet_seek_end;
            }

            query_counter = &ipv4_query_count;

        }

        else if(ether_type == ETHER_TYPE_IPv6) {

            if(fread(&ip6_hdr, sizeof(ip6_hdr), 1, fp) != 1) {
                RTE_LOG(WARNING, TCPGEN, "pcap_parse: failed to read ipv6 header\n");
                goto packet_seek_end;
            }

            read_bytes += sizeof(ip6_hdr);

            // Check next header
            if(ip6_hdr.proto != IPPROTO_UDP) {
                RTE_LOG(WARNING, TCPGEN, "pcap_parse: unsupported non-UDP next protocol id in ivp6 header\n");
                goto packet_seek_end;
            }

            query_counter = &ipv6_query_count;
        }

        else {
            RTE_LOG(WARNING, TCPGEN, "pcap_parse: unsupported ether type (expected ipv4 or ipv6)\n");
            goto packet_seek_end;
        }

        // Read L4 header
        if(fread(&udp_hdr, sizeof(udp_hdr), 1, fp) != 1) {
            RTE_LOG(WARNING, TCPGEN, "pcap_parse: failed to read udp header\n");
            goto packet_seek_end;
        }

        read_bytes += sizeof(udp_hdr);

        size_t remaining_bytes = pkt_hdr.incl_len - read_bytes;
        if(remaining_bytes <= 0) {
            RTE_LOG(WARNING, TCPGEN, "pcap_parse: invalid dns payload size\n");
            goto packet_seek_end;
        }

        uint8_t *payload = rte_malloc("pcap payload", remaining_bytes, 0);
        if(payload == NULL) {
            RTE_LOG(CRIT, TCPGEN, "pcap_parse: rte_malloc payload allocation failed\n");
            return -1;
        }

        // Length field of TCP DNS at start of DNS payload
        uint16_t *mbuf_tcp_dns_payload_len = (uint16_t *)payload;

        uint32_t payload_len = remaining_bytes + sizeof(*mbuf_tcp_dns_payload_len);
        *mbuf_tcp_dns_payload_len = rte_cpu_to_be_16(remaining_bytes);

        // DNS payload
        void *mbuf_dns_payload = (void *)(payload + sizeof(*mbuf_tcp_dns_payload_len));


        // Read in rest of mbuf
        if(fread(mbuf_dns_payload, 1, remaining_bytes, fp) != remaining_bytes) {
            RTE_LOG(WARNING, TCPGEN, "pcap_parse: failed to read dns payload\n");
            goto packet_seek_end;
        }

        read_bytes += remaining_bytes;

        if(pcap_list_insert(&config->pcap_lists[lcore_id], payload, payload_len) == NULL) {
            RTE_LOG(CRIT, TCPGEN, "pcap_parse: failed to insert new pcap list entry\n");
            return -1;
        }
        // Insert next packet in next lcore's list
        lcore_id = rte_get_next_lcore(lcore_id, 0, 1);

        pcap_bytes += read_bytes;
        pcap_records++;
        *query_counter += 1;

        // Seek to end of current packet if less bytes were read than included in packet
        packet_seek_end:
        fseek(fp, pkt_hdr.incl_len - read_bytes, SEEK_CUR);
    }

    fclose(fp);

    RTE_LOG(INFO, TCPGEN, "pcap_parse: successfully read in %d packets (%lu bytes)\n", pcap_records, pcap_bytes);
    if(pcap_records == 0) {
        RTE_LOG(ERR, TCPGEN, "pcap_parse: failed to read in any valid packets\n");
        return -1;
    }

    if(ipv4_query_count == 0) {
        config->pcap_ipv6_probability = UINT64_MAX;
    }
    else if(ipv6_query_count == 0) {
        config->pcap_ipv6_probability = 0;
    }
    else {
        config->pcap_ipv6_probability = (double)ipv6_query_count / ((double)(ipv4_query_count + ipv6_query_count)) * INT64_MAX;
    }

    return pcap_records;
}
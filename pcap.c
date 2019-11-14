/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Brno University of Technology
 *
 * tcpgen - a simple DPDK TCP DNS traffic generator
 * Author: Matej Postolka <xposto02@stud.fit.vutbr.cz>
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_log.h>

#include "pcap.h"
#include "common.h"

#define MAGIC_USEC_TS 0xa1b2c3d4
#define MAGIC_NSEC_TS 0xa1b23c4d

static void pcap_list_insert(struct pcap_list *list, struct rte_mbuf *mbuf);

void pcap_list_init(struct pcap_list *list)
{
    list->first = list->current = list->last = NULL;
}

static void pcap_list_insert(struct pcap_list *list, struct rte_mbuf *mbuf)
{
    struct pcap_list_entry *new_entry = rte_zmalloc("pcap_list_entry", sizeof(struct pcap_list_entry), 0);
    if(new_entry == NULL) {
        rte_exit(EXIT_FAILURE, "rte_zmalloc failed (pcap_list_entry)\n");
    }

    new_entry->mbuf = mbuf;
    new_entry->next = NULL;

    if(list->first == NULL) {
        list->first = list->last = list->current = new_entry;
    }
    else {
        list->last->next = new_entry;
        list->last = new_entry;
    }
}

struct rte_mbuf *pcap_list_get(const struct pcap_list *list)
{
    struct pcap_list_entry *current = list->current;

    if(current == NULL) {
        return NULL;
    }

    return current->mbuf;
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

void pcap_list_destroy(struct pcap_list *list)
{
    struct pcap_list_entry *next;
    struct pcap_list_entry *current;

    for(current = list->first; current != NULL;) {
        next = current->next;
        rte_free(current);
        current = next;
    }

    list->first = list->current = list->last = NULL;
}

void pcap_parse(struct app_config *config)
{
    FILE *fp = fopen(config->user_config.pcap_file, "r");
    if(fp == NULL) {
        rte_exit(EXIT_FAILURE, "failed to open pcap file\n");
    }

    struct pcap_global_hdr hdr;
    if(fread(&hdr, sizeof(hdr), 1, fp) != 1) {
        rte_exit(EXIT_FAILURE, "failed to read PCAP header\n");
    }

    if(hdr.magic_number != MAGIC_USEC_TS && hdr.magic_number != MAGIC_NSEC_TS) {
        rte_exit(EXIT_FAILURE, "invalid or unsupported PCAP magic\n");
    }

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
                RTE_LOG(WARNING, TCPGEN, "pcap: failed to read ipv4 header\n");
                goto packet_seek_end;
            }

            read_bytes += sizeof(ip4_hdr);

            // Check next header
            if(ip4_hdr.next_proto_id != IPPROTO_UDP) {
                RTE_LOG(WARNING, TCPGEN, "pcap: unsupported non-UDP next protocol id in ivp4 header\n");
                goto packet_seek_end;
            }

            query_counter = &ipv4_query_count;

        }

        else if(ether_type == ETHER_TYPE_IPv6) {

            if(fread(&ip6_hdr, sizeof(ip6_hdr), 1, fp) != 1) {
                RTE_LOG(WARNING, TCPGEN, "pcap: failed to read ipv6 header\n");
                goto packet_seek_end;
            }

            read_bytes += sizeof(ip6_hdr);

            // Check next header
            if(ip6_hdr.proto != IPPROTO_UDP) {
                RTE_LOG(WARNING, TCPGEN, "pcap: unsupported non-UDP next protocol id in ivp6 header\n");
                goto packet_seek_end;
            }

            query_counter = &ipv6_query_count;
        }

        else {
            RTE_LOG(WARNING, TCPGEN, "pcap: unsupported ether type (expected ipv4 or ipv6)\n");
            goto packet_seek_end;
        }

        // Read L4 header
        if(fread(&udp_hdr, sizeof(udp_hdr), 1, fp) != 1) {
            RTE_LOG(WARNING, TCPGEN, "pcap: failed to read udp header\n");
            goto packet_seek_end;
        }

        read_bytes += sizeof(udp_hdr);

        struct rte_mbuf *pcap_mbuf = rte_pktmbuf_alloc(config->dpdk_config.pktmbuf_pool);
        if(pcap_mbuf == NULL) {
            rte_exit(EXIT_FAILURE, "pcap: mbuf allocation failed\n");
        }

        // Length field of TCP DNS at start of DNS payload
        uint16_t *mbuf_tcp_dns_payload_len = rte_pktmbuf_mtod(pcap_mbuf, uint16_t *);

        // DNS payload
        void *mbuf_dns_payload = rte_pktmbuf_mtod_offset(pcap_mbuf, void *, sizeof(*mbuf_tcp_dns_payload_len));

        // Read in rest of mbuf
        size_t remaining_bytes = pkt_hdr.incl_len - read_bytes;
        if(remaining_bytes <= 0) {
            RTE_LOG(WARNING, TCPGEN, "pcap: invalid dns payload size\n");
            goto packet_seek_end;
        }

        pcap_mbuf->pkt_len = pcap_mbuf->data_len = remaining_bytes + sizeof(*mbuf_tcp_dns_payload_len);

        *mbuf_tcp_dns_payload_len = rte_cpu_to_be_16(remaining_bytes);

        if(fread(mbuf_dns_payload, 1, remaining_bytes, fp) != remaining_bytes) {
            RTE_LOG(WARNING, TCPGEN, "pcap: failed to read dns payload\n");
            goto packet_seek_end;
        }

        read_bytes += remaining_bytes;

        pcap_list_insert(&config->pcap_list, pcap_mbuf);

        pcap_bytes += read_bytes;
        pcap_records++;
        *query_counter += 1;

        // Seek to end of current packet if less bytes were read than included in packet
        packet_seek_end:
        fseek(fp, pkt_hdr.incl_len - read_bytes, SEEK_CUR);
    }

    fclose(fp);

    RTE_LOG(INFO, TCPGEN, "pcap: successfully read in %d packets (%lu bytes)\n", pcap_records, pcap_bytes);
    if(pcap_records == 0) {
        rte_exit(EXIT_FAILURE, "pcap: read in 0 packets, exiting...\n");
    }

    if(ipv4_query_count == 0) {
        config->pcap_ipv6_probability = UINT64_MAX;
    }
    else if(ipv6_query_count == 0) {
        config->pcap_ipv6_probability = 0;
    }
    else {
        config->pcap_ipv6_probability = ipv6_query_count / ((double)(ipv4_query_count + ipv6_query_count)) * UINT64_MAX;
    }
}
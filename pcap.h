//
// Created by postolka on 13.6.19.
//

#ifndef DPDK_TCP_GENERATOR_PCAP_H
#define DPDK_TCP_GENERATOR_PCAP_H

#include <stdint.h>

#include <rte_mbuf.h>

struct app_config;

struct pcap_global_hdr {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct pcap_packet_hdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

struct pcap_list_entry {
    uint8_t *pcap_payload;
    uint32_t payload_len;
    struct pcap_list_entry *next;
};

struct pcap_list {
    struct pcap_list_entry *first;
    struct pcap_list_entry *last;
    struct pcap_list_entry *current;
};

void pcap_list_init(struct pcap_list *list);
struct pcap_list_entry *pcap_list_get(const struct pcap_list *list);
void pcap_list_next(struct pcap_list *list);
void pcap_list_destroy(struct pcap_list *list);
int pcap_parse(struct app_config *config);

#endif //DPDK_TCP_GENERATOR_PCAP_H

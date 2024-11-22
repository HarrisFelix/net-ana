// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_CAPTURE_PACKET_UTILS_H_
#define SRC_CAPTURE_PACKET_UTILS_H_

#include <pcap.h>

void print_timestamp(const struct pcap_pkthdr *header);
void print_packet_bytes(const u_char *packet, uint len);
uint16_t validate_checksum(const void *pseudo_header, const void *packet,
                           uint num_32bit_words);

#endif  // SRC_CAPTURE_PACKET_UTILS_H_

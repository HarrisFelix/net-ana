// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_CAPTURE_PACKET_UTILS_H_
#define SRC_CAPTURE_PACKET_UTILS_H_

#include <pcap.h>
#include <stdbool.h>

#define LITTLE_ENDIAN_INT_TO_32_BIT_WORDS(x) ((x) / 4)

typedef struct {
  const char *oui;
  const char *name;
} oui_t;

/* https://en.wikipedia.org/wiki/Organizationally_unique_identifier */
extern oui_t oui_list[];

void print_timestamp(const struct pcap_pkthdr *header);
void print_packet_bytes(const u_char *packet, uint len);
const char *get_oui(const unsigned char *mac);
void print_clear_text(const char *clear_text);
uint16_t validate_checksum(const void *pseudo_header, bool is_ipv6,
                           const void *packet, uint num_32bit_words);

#endif  // SRC_CAPTURE_PACKET_UTILS_H_

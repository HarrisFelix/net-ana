// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_DATA_LINK_LINUX_COOKED_CAPTURE_LINUX_COOKED_CAPTURE_H_
#define SRC_PROTOCOLS_DATA_LINK_LINUX_COOKED_CAPTURE_LINUX_COOKED_CAPTURE_H_

#include <pcap/sll.h>
#include <stdint.h>

#define ARPHRD_IEEE80211_RADIOTAP 803
#define ARPHRD_IPGRE 778
#define ARPHRD_FRAD 770
#define ARPHRD_NETLINK 824

typedef enum {
  PACKET_TYPE_DIRECTED = 0,        // Specifically sent to us
  PACKET_TYPE_BROADCAST = 1,       // Broadcast by somebody else
  PACKET_TYPE_MULTICAST = 2,       // Multicast but not broadcast
  PACKET_TYPE_OTHER_TO_OTHER = 3,  // Sent to somebody else by somebody else
  PACKET_TYPE_OWN = 4              // Sent by us
} packet_type_t;

uint16_t print_linux_cooked_header(const struct sll_header *sll);
uint16_t print_linux_cooked_2_header(const struct sll2_header *sll2);
void print_ssl_packet_type(uint8_t packet_type);

#endif  // SRC_PROTOCOLS_DATA_LINK_LINUX_COOKED_CAPTURE_LINUX_COOKED_CAPTURE_H_

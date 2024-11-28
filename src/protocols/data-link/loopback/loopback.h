// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_DATA_LINK_LOOPBACK_LOOPBACK_H_
#define SRC_PROTOCOLS_DATA_LINK_LOOPBACK_LOOPBACK_H_

#include "../../../utils/utils.h"
#include <stdint.h>

/* Loopback protocols can have multiple values that are equivalent to a single
 * EtherType */
#define LOOPBACK_IP 2
#define LOOPBACK_IP6_1 24
#define LOOPBACK_IP6_2 28
#define LOOPBACK_IP6_3 30
#define LOOPBACK_OSI 7
#define LOOPBACK_IPX 23

/* https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html */
struct bsd_loopback_hdr {
  uint32_t protocol_type;
};

typedef struct name_value_pair_t bsd_lo_protocol_t;
extern bsd_lo_protocol_t bsd_lo_protocols[];

uint16_t print_loopback_header(const struct bsd_loopback_hdr *lo);

#endif  // SRC_PROTOCOLS_DATA_LINK_LOOPBACK_LOOPBACK_H_

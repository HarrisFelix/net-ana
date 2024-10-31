// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_DATA_LINK_H_
#define SRC_PROTOCOLS_DATA_LINK_H_

#include "../utils.h"
#include <net/ethernet.h>
#include <net/if_arp.h>

#define ETHERTYPE_LINKLOCAL 0xFE80

struct name_value_pair_t {
  u_short value;
  const char *name;
};

/* Associates an EtherType with its corresponding name, keeping semantical
 * meaning */
typedef struct name_value_pair_t ether_type_t;
extern ether_type_t ether_types[];

/* Allows us to keep semantical meaning even if the structs are identical */
typedef struct name_value_pair_t arp_hardware_t;
extern arp_hardware_t arp_hardwares[];

/* https://en.wikipedia.org/wiki/Address_Resolution_Protocol
 *
 * The protocol type of ARP shares a numbering space with the ones for the
 * EtherType, so we are gonna transparently point to the ether_types table while
 * remaining semantical by redefining the stucts */
typedef ether_type_t arp_protocol_t;
extern arp_protocol_t *arp_protocols;

ether_type_t get_ether_type_name(u_short ether_value);
u_short print_ethernet_header(const struct ether_header *ethernet,
                              enum verbosity_level verbosity);
void print_arp_header(const struct arphdr *arp);
void print_arp_frame(const struct arphdr *arp, enum verbosity_level verbosity);

#endif  // SRC_PROTOCOLS_DATA_LINK_H_

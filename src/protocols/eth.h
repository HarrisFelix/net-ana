// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_ETH_H_
#define SRC_PROTOCOLS_ETH_H_

#include "../utils.h"
#include <net/ethernet.h>

#define ETHERTYPE_LINKLOCAL 0xFE80

typedef struct {
  u_short ether_value;
  const char *name;
} ether_types_t;

extern ether_types_t ether_types[];

ether_types_t get_ether_type_name(u_short ether_value);
u_short print_ethernet_header(const struct ether_header *ethernet,
                              enum verbosity_level verbosity);

#endif  // SRC_PROTOCOLS_ETH_H_

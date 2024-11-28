// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_NETWORK_ICMP6_ICMP6_H_
#define SRC_PROTOCOLS_NETWORK_ICMP6_ICMP6_H_

#include <netinet/icmp6.h>
#include <stdint.h>

#ifdef __linux__
#define ND_RA_FLAG_HA ND_RA_FLAG_HOME_AGENT
#endif

union icmp6_un {
  const struct nd_router_solicit *rs;
  const struct nd_router_advert *ra;
  const struct nd_neighbor_solicit *ns;
  const struct nd_neighbor_advert *na;
};

void print_icmp6_frame(const struct icmp6_hdr *icmp6, uint16_t len);

#endif  // SRC_PROTOCOLS_NETWORK_ICMP6_ICMP6_H_

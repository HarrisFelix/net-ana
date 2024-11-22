// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_NETWORK_H_
#define SRC_PROTOCOLS_NETWORK_H_

#include "../capture/capture_utils.h"
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>

struct pseudo_ip6_hdr {
  struct in6_addr ip6_src; /* source address */
  struct in6_addr ip6_dst; /* destination address */
  uint32_t plen;           /* payload length */
  uint8_t zero[3];         /* three zero bytes */
  uint8_t nxt;             /* next header */
} __attribute__((packed));

union icmp6_un {
  const struct nd_router_solicit *rs;
  const struct nd_router_advert *ra;
  const struct nd_neighbor_solicit *ns;
  const struct nd_neighbor_advert *na;
};

void print_ip_or_ip6_encapsulated_protocol(const void *header, u_char protocol,
                                           uint16_t len,
                                           enum verbosity_level verbosity);
void print_ip_frame(const struct ip *ip, enum verbosity_level verbosity);
void print_ip6_frame(const struct ip6_hdr *ip6, enum verbosity_level verbosity);
void print_icmp_frame(const struct icmp *icmp, uint16_t len,
                      enum verbosity_level verbosity);
void print_icmp6_frame(const struct icmp6_hdr *icmp6, uint16_t len,
                       enum verbosity_level verbosity);
void set_pseudo_ip6_hdr(struct pseudo_ip6_hdr *pseudo_ip6,
                        const struct in6_addr src, const struct in6_addr dst,
                        uint16_t plen, uint8_t nxt);

#endif  // SRC_PROTOCOLS_NETWORK_H_

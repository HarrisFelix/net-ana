// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_NETWORK_IP6_IP6_H_
#define SRC_PROTOCOLS_NETWORK_IP6_IP6_H_

#include <netinet/ip6.h>

#ifdef __linux__
#define IPV6_FLOWLABEL_MASK 0xffff0f00
#endif

struct pseudo_ip6_hdr {
  struct in6_addr ip6_src; /* source address */
  struct in6_addr ip6_dst; /* destination address */
  uint32_t plen;           /* payload length */
  uint8_t zero[3];         /* three zero bytes */
  uint8_t nxt;             /* next header */
} __attribute__((packed));

void print_ip6_encapsulated_protocol(const void *header, u_char protocol,
                                     uint16_t len);
void print_ip6_frame(const struct ip6_hdr *ip6);
void set_pseudo_ip6_hdr(struct pseudo_ip6_hdr *pseudo_ip6,
                        const struct in6_addr src, const struct in6_addr dst,
                        uint16_t plen, uint8_t nxt);

#endif  // SRC_PROTOCOLS_NETWORK_IP6_IP6_H_

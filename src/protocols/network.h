// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_NETWORK_H_
#define SRC_PROTOCOLS_NETWORK_H_

#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>

#ifdef __linux__
#define IPV6_FLOWLABEL_MASK 0xffff0f00
#define ND_RA_FLAG_HA ND_RA_FLAG_HOME_AGENT
#endif

struct pseudo_ip_hdr {
  struct in_addr ip_src; /* source address */
  struct in_addr ip_dst; /* destination address */
  uint8_t zero;          /* zero byte */
  uint8_t ip_p;          /* protocol */
  uint16_t tcp_len;      /* TCP header and payload length */
} __attribute__((packed));

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
                                           uint16_t len);
void print_ip_frame(const struct ip *ip);
void print_ip6_frame(const struct ip6_hdr *ip6);
void print_icmp_frame(const struct icmp *icmp, uint16_t len);
void print_icmp6_frame(const struct icmp6_hdr *icmp6, uint16_t len);
void set_pseudo_ip_hdr(struct pseudo_ip_hdr *pseudo_ip,
                       const struct in_addr src, const struct in_addr dst,
                       uint8_t protocol, uint16_t tcp_len);
void set_pseudo_ip6_hdr(struct pseudo_ip6_hdr *pseudo_ip6,
                        const struct in6_addr src, const struct in6_addr dst,
                        uint16_t plen, uint8_t nxt);

#endif  // SRC_PROTOCOLS_NETWORK_H_

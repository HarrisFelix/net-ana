// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_NETWORK_IP_IP_H_
#define SRC_PROTOCOLS_NETWORK_IP_IP_H_

#include <netinet/ip.h>
#include <stdint.h>

struct pseudo_ip_hdr {
  struct in_addr ip_src; /* source address */
  struct in_addr ip_dst; /* destination address */
  uint8_t zero;          /* zero byte */
  uint8_t ip_p;          /* protocol */
  uint16_t tcp_len;      /* TCP header and payload length */
} __attribute__((packed));

void print_ip_encapsulated_protocol(const void *header, u_char protocol,
                                    uint16_t len);
void print_ip_frame(const struct ip *ip);
void set_pseudo_ip_hdr(struct pseudo_ip_hdr *pseudo_ip,
                       const struct in_addr src, const struct in_addr dst,
                       uint8_t protocol, uint16_t tcp_len);

#endif  // SRC_PROTOCOLS_NETWORK_IP_IP_H_

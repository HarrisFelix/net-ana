// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_TRANSPORT_UDP_UDP_H_
#define SRC_PROTOCOLS_TRANSPORT_UDP_UDP_H_

#include <netinet/udp.h>
#include <stdbool.h>

#define DNS_PORT 53
#define BOOTP_DHCP_SERVER_PORT 67
#define BOOTP_DHCP_CLIENT_PORT 68

void print_udp_encapsulated_protocol(const struct udphdr *tcp);
void print_udp_frame(const struct udphdr *udp, bool is_ipv6);
void print_udp_cksum(const struct udphdr *udp, bool is_ipv6);

#endif  // SRC_PROTOCOLS_TRANSPORT_UDP_UDP_H_

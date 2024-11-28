// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_TRANSPORT_UDP_UDP_H_
#define SRC_PROTOCOLS_TRANSPORT_UDP_UDP_H_

#include <netinet/udp.h>
#include <stdbool.h>

void print_udp_frame(const struct udphdr *udp, bool is_ipv6);

#endif  // SRC_PROTOCOLS_TRANSPORT_UDP_UDP_H_

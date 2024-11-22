// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_TRANSPORT_H_
#define SRC_PROTOCOLS_TRANSPORT_H_

#include <netinet/tcp.h>
#include <netinet/udp.h>

struct ports {
  u_short source;
  u_short destination;
};

struct ports get_ports(const void *header, u_char protocol);
void print_tcp_frame(const struct tcphdr *tcp);
void print_udp_frame(const struct udphdr *udp);

#endif  // SRC_PROTOCOLS_TRANSPORT_H_

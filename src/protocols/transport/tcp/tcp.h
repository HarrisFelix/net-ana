// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_TRANSPORT_TCP_TCP_H_
#define SRC_PROTOCOLS_TRANSPORT_TCP_TCP_H_

#include <netinet/tcp.h>
#include <stdbool.h>

#ifdef __linux__
#define TH_ECE 0x40
#define TH_CWR 0x80
#endif

void print_tcp_flags(uint8_t flags);
void print_tcp_frame(const struct tcphdr *tcp, bool is_ipv6);

#endif  // SRC_PROTOCOLS_TRANSPORT_TCP_TCP_H_

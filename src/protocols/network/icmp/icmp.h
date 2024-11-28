// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_NETWORK_ICMP_ICMP_H_
#define SRC_PROTOCOLS_NETWORK_ICMP_ICMP_H_

#include <netinet/ip_icmp.h>
#include <stdio.h>

void print_icmp_frame(const struct icmp *icmp, uint16_t len);

#endif  // SRC_PROTOCOLS_NETWORK_ICMP_ICMP_H_

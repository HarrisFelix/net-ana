// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_NETWORK_H_
#define SRC_PROTOCOLS_NETWORK_H_

#include "../capture/capture_utils.h"
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>

void print_ip_or_ip6_encapsulated_protocol(const void *header, u_char protocol,
                                           enum verbosity_level verbosity);
void print_ip_frame(const struct ip *ip, enum verbosity_level verbosity);
void print_ip6_frame(const struct ip6_hdr *ip6, enum verbosity_level verbosity);
void print_icmp_frame(const struct icmp *icmp, enum verbosity_level verbosity);
void print_icmp6_frame(const struct icmp6_hdr *icmp6,
                       enum verbosity_level verbosity);

#endif  // SRC_PROTOCOLS_NETWORK_H_

// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_NETWORK_H_
#define SRC_PROTOCOLS_NETWORK_H_

#include "../capture/capture_utils.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>

void print_ip_frame(const struct ip *ip, enum verbosity_level verbosity);
void print_ip6_frame(const struct ip6_hdr *ip6, enum verbosity_level verbosity);

#endif  // SRC_PROTOCOLS_NETWORK_H_

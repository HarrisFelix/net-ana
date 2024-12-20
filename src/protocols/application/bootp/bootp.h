// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_APPLICATION_BOOTP_BOOTP_H_
#define SRC_PROTOCOLS_APPLICATION_BOOTP_BOOTP_H_

#include "bootp-lib.h"
#include <stdbool.h>

#define DHCP_MAGIC_COOKIE {0x63, 0x82, 0x53, 0x63}

void print_bootp_frame(const struct bootp *bootp);
bool is_dhcp(const struct bootp *bootp);

#endif  // SRC_PROTOCOLS_APPLICATION_BOOTP_BOOTP_H_

// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_DATA_LINK_LINUX_COOKED_CAPTURE_LINUX_COOKED_CAPTURE_H_
#define SRC_PROTOCOLS_DATA_LINK_LINUX_COOKED_CAPTURE_LINUX_COOKED_CAPTURE_H_

#include <pcap/sll.h>
#include <stdint.h>

uint16_t print_linux_cooked_header(const struct sll2_header *sll2);

#endif  // SRC_PROTOCOLS_DATA_LINK_LINUX_COOKED_CAPTURE_LINUX_COOKED_CAPTURE_H_

// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_UTILS_H_
#define SRC_UTILS_H_

#include <pcap.h>

void print_devices();
void print_frame();

void ether_type_to_name();
void print_live_capture_summary();
void print_timestamp(const struct pcap_pkthdr *header);

#endif  // SRC_UTILS_H_

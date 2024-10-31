// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_UTILS_H_
#define SRC_UTILS_H_

#include <pcap.h>

enum verbosity_level { LOW = 1, MEDIUM, HIGH };

char *get_first_non_loopback_device(char *program_name);
void print_devices(char *program_name);

void print_payload();
void print_frame();
void print_live_capture_summary();
void print_timestamp(const struct pcap_pkthdr *header);
void print_packet_bytes(const u_char *packet, int len);

#endif  // SRC_UTILS_H_

// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_CAPTURE_CAPTURE_H_
#define SRC_CAPTURE_CAPTURE_H_

#include "capture_utils.h"
#include <pcap.h>
#include <stdbool.h>

extern enum verbosity_level verbosity;
extern pcap_t *handle;
extern u_int captured_packets_count;

void capture_loop(char *interface, char *file, char *filter,
                  u_int verbose_output);
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

#endif  // SRC_CAPTURE_CAPTURE_H_

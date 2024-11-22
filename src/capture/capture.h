// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_CAPTURE_CAPTURE_H_
#define SRC_CAPTURE_CAPTURE_H_

#include "capture_utils.h"
#include <pcap.h>
#include <stdbool.h>

extern pcap_t *handle;
extern u_int captured_packets_count;

struct pcap_handler_args {
  u_int verbosity;
};

void capture_loop(char *interface, char *file, char *filter, u_int verbosity);
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

#endif  // SRC_CAPTURE_CAPTURE_H_

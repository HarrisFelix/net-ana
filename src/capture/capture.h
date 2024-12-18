// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_CAPTURE_CAPTURE_H_
#define SRC_CAPTURE_CAPTURE_H_

#include "capture_utils.h"
#include <pcap.h>
#include <stdbool.h>

/* We set an arbitrary value as a do not
 * print value, in order to delegate the task of printing to the encapsulated
 * protocol for whatever reason */
#define LET_ENCAPSULATED_PROTOCOL_PRINT_PAYLOAD_LENGTH -1

extern enum verbosity_level verbosity;
extern pcap_t *handle;
extern u_int captured_packets_count;
extern int payload_length;

void capture_loop(char *interface, char *file, char *filter,
                  u_int verbose_output);
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

#endif  // SRC_CAPTURE_CAPTURE_H_

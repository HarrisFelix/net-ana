// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_CAPTURE_H_
#define SRC_CAPTURE_H_

#include <pcap.h>
#include <stdbool.h>

#define SNAPLEN 65535

struct pcap_handler_args {
  u_int verbosity;
};

void capture_loop(char *program_name, char *interface, char *file, char *filter,
                  u_int verbosity, bool supplied_verbosity);
void init_message(char *program_name, char *interface, char *file,
                  bool defaulting, bool supplied_verbosity);
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

#endif  // SRC_CAPTURE_H_

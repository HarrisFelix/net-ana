// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_CAPTURE_H_
#define SRC_CAPTURE_H_

#include <pcap.h>
#include <stdbool.h>

#define SNAPLEN 65535

extern pcap_t *handle;
extern u_int captured_packets_count;

struct pcap_handler_args {
  u_int verbosity;
};

void capture_loop(char *program_name, char *interface, char *file, char *filter,
                  u_int verbosity, bool supplied_verbosity);
void init_message(char *program_name, char *interface, char *file,
                  bool defaulting, bool supplied_verbosity);
void apply_bpf_filter(char *program_name, char *interface,
                      struct bpf_program *fp, bpf_u_int32 *mask,
                      bpf_u_int32 *net, char *filter);
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

#endif  // SRC_CAPTURE_H_

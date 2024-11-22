// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_CAPTURE_CAPTURE_UTILS_H_
#define SRC_CAPTURE_CAPTURE_UTILS_H_

#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>

#define SNAPLEN 65535

enum verbosity_level { NONE, LOW, MEDIUM, HIGH };
extern enum verbosity_level verbosity;

void init_message(char *interface, char *file, bool defaulting);
void apply_bpf_filter(char *interface, struct bpf_program *fp,
                      bpf_u_int32 *mask, bpf_u_int32 *net, char *filter);
char *custom_lookupdev();
void print_devices();
void print_live_capture_summary();

#endif  // SRC_CAPTURE_CAPTURE_UTILS_H_

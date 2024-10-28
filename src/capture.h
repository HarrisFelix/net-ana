#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

struct pcap_handler_args {
   int verbosity;
};

void capture_loop(char *programe_name, char *interface, char* file, char *filter, int verbosity);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif
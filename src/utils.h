#ifndef UTILS_H
#define UTILS_H

void print_devices();
void print_frame();

void ether_type_to_name();
void print_live_capture_summary();
void print_timestamp(const struct pcap_pkthdr *header);

#endif
#include "capture_utils.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum verbosity_level verbosity;
extern char const *program_name;
extern pcap_t *handle;
extern u_int captured_packets_count;

void init_message(char *interface, char *file, bool defaulting) {
  int data_link = pcap_datalink(handle);

  if (defaulting)
    printf("%s: defaulting to data link type %s\n", program_name,
           pcap_datalink_val_to_name(data_link));

  if (!verbosity)
    printf("%s: verbose output suppressed, use -v[v]... for full protocol "
           "decode\n",
           program_name);

  if (interface) {
    printf("Listening on %s, link-type %s (%s), snapshot length %d bytes\n",
           interface, pcap_datalink_val_to_name(data_link),
           pcap_datalink_val_to_description(data_link), SNAPLEN);
  } else {
    printf("Reading from file %s, link-type %s (%s)\n", file,
           pcap_datalink_val_to_name(data_link),
           pcap_datalink_val_to_description(data_link));
  }
}

void apply_bpf_filter(char *interface, struct bpf_program *fp,
                      bpf_u_int32 *mask, bpf_u_int32 *net, char *filter) {
  char errbuf[PCAP_ERRBUF_SIZE];

  if (pcap_lookupnet(interface, net, mask, errbuf) == PCAP_ERROR) {
    fprintf(stderr, "%s: couldn't get netmask for device %s: %s\n",
            program_name, interface, errbuf);
    *net = 0;
    *mask = 0;
  }

  if (pcap_compile(handle, fp, filter, 0, *net) == PCAP_ERROR) {
    fprintf(stderr, "%s: %s\n", program_name, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(handle, fp) == PCAP_ERROR) {
    fprintf(stderr, "%s: %s\n", program_name, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
}

char *custom_lookupdev() {
  char errbuf[PCAP_ERRBUF_SIZE];
  char *interface = NULL;
  pcap_if_t *device, *alldevs;

  if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
    fprintf(stderr, "%s: couldn't retrieve devices (%s)\n", program_name,
            errbuf);
    return NULL;
  }

  for (device = alldevs; device != NULL; device = device->next) {
    if (device->flags & PCAP_IF_LOOPBACK ||
        !(device->flags & PCAP_IF_CONNECTION_STATUS_CONNECTED)) {
      continue;
    }

    break;
  }

  if (device)
    interface = strdup(device->name);

  pcap_freealldevs(alldevs);
  return interface;
}

void print_live_capture_summary() {
  int stats_err = 0;
  struct pcap_stat packet_stats;

  pcap_breakloop(handle);

  stats_err = pcap_stats(handle, &packet_stats);
  if (stats_err == PCAP_ERROR || stats_err == PCAP_ERROR_NOT_ACTIVATED) {
    fprintf(stderr, "%s\n", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  printf("\n\n%d packet%c captured\n", captured_packets_count,
         captured_packets_count != 1 ? 's' : 0);
  printf("%d packet%c received by filter\n", packet_stats.ps_recv,
         packet_stats.ps_recv != 1 ? 's' : 0);
  printf("%d packet%c dropped by kernel\n", packet_stats.ps_drop,
         packet_stats.ps_drop != 1 ? 's' : 0);
}

void print_devices() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *device, *alldevs;

  if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
    fprintf(stderr, "%s: couldn't list devices (%s)\n", program_name, errbuf);
    return;
  }

  printf("%-10s %-40s %-10s\n", "Name", "Description", "Connection Status");
  printf("--------------------------------------------------------------\n");

  for (device = alldevs; device != NULL; device = device->next) {
    const char *status = (device->flags & PCAP_IF_CONNECTION_STATUS_CONNECTED)
                             ? "Connected"
                             : "Disconnected";

    printf("%-10s %-40s %-10s\n", device->name,
           device->description ? device->description : "No description",
           status);
  }

  pcap_freealldevs(alldevs);
}

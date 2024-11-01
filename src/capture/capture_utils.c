#include "capture_utils.h"
#include <ctype.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/_endian.h>
#include <time.h>

extern pcap_t *handle;
extern u_int captured_packets_count;

char *custom_lookupdev(char *program_name) {
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

void print_devices(char *program_name) {
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

/* https://stackoverflow.com/questions/2408976/struct-timeval-to-printable-format
 */
void print_timestamp(const struct pcap_pkthdr *header) {
  time_t nowtime;
  struct tm *nowtm;
  char tmbuf[64], buf[64];

  nowtime = header->ts.tv_sec;
  nowtm = localtime(&nowtime);
  strftime(tmbuf, sizeof tmbuf, "%H:%M:%S", nowtm);
  snprintf(buf, sizeof buf, "%s.%06d", tmbuf, header->ts.tv_usec);
  printf("%s", buf);
}

void print_packet_bytes(const u_char *packet, int len) {
  for (int i = 0; i < len; i++) {
    /* HEX */
    if (i % 16 == 0)
      printf("\n\t0x%04x: ", i);
    if (i % 2 == 0)
      printf(" %02x", packet[i]);
    else
      printf("%02x", packet[i]);

    /* ASCII */
    if ((i + 1) % 16 == 0 || i == len - 1) {
      /* Some explanation, a typical HEX block would be " 0000" and would be
       * comprised of 2 bytes, so each byte occupy half the length of that,
       * which is 2.5 We multiply the length occupied by a byte by the number of
       * bytes left we need to fill row */
      int padding = ((16 - ((i + 1) % 16)) % 16) * 2.5;
      printf(" %*s ", padding, "");

      /* Replace the cursor at the start of the line */
      for (int j = i - (i % 16); j <= i; j++) {
        if (isprint(packet[j]))
          printf("%c", packet[j]);
        else
          printf(".");
      }
    }
  }
}

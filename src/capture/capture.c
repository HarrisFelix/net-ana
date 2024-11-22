#include "../protocols/data-link.h"
#include "../protocols/network.h"
#include "capture.h"
#include "capture_utils.h"
#include "packet_utils.h"
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char const *program_name;
pcap_t *handle;
u_int captured_packets_count = 0;

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  /* Define packet handling related structures. */
  struct pcap_handler_args *packet_args = (struct pcap_handler_args *)args;
  const struct ip *ip;
  const struct ip6_hdr *ip6;
  const struct arphdr *arp;
  u_short protocol;
  u_int size_header;

  print_timestamp(header);

  /* We have to handle different link types that have different headers */
  switch (pcap_datalink(handle)) {
  case DLT_EN10MB:
    /* EtherType or LSAP value */
    size_header = sizeof(struct ether_header);
    protocol = print_ethernet_header((const struct ether_header *)packet,
                                     header->len, packet_args->verbosity);
    break;
  case DLT_NULL:
    /* BSD Loopback protocol */
    size_header = sizeof(struct bsd_loopback_hdr);
    protocol = print_loopback_header((const struct bsd_loopback_hdr *)packet,
                                     packet_args->verbosity);
  case DLT_RAW:
    size_header = 0;
    protocol = (packet[0] >> 4) == 4 ? ETHERTYPE_IP : ETHERTYPE_IPV6;
    printf(" RAW IPv%c", protocol == ETHERTYPE_IP ? '4' : '6');
    break;
  case DLT_LINUX_SLL2:
    printf(" Linux Cooked Capture Unsupported");
    break;
  }

  /* Print the frame according to the protocol */
  switch (protocol) {
  case ETHERTYPE_IP:
  case LOOPBACK_IP:
    ip = (struct ip *)(packet + size_header);
    print_ip_frame(ip, packet_args->verbosity);
    break;
  case ETHERTYPE_IPV6:
  case LOOPBACK_IP6_1:
  case LOOPBACK_IP6_2:
  case LOOPBACK_IP6_3:
    ip6 = (struct ip6_hdr *)(packet + size_header);
    print_ip6_frame(ip6, packet_args->verbosity);
    break;
  case ETHERTYPE_ARP:
    arp = (struct arphdr *)(packet + size_header);
    print_arp_frame(arp, packet_args->verbosity);
    break;
  }

  /* Size of the frame without counting the ethernet header */
  printf(", length %d", header->len - size_header);

  /* Print the bytes and ASCII of the packet. */
  if (packet_args->verbosity == HIGH)
    print_packet_bytes(packet, header->caplen);

  printf("\n");
  captured_packets_count++;
}

void capture_loop(char *interface, char *file, char *filter, u_int verbosity) {
  char errbuf[PCAP_ERRBUF_SIZE];
  bool defaulting = (bool)(!interface && !file);

  /* Filter related */
  struct bpf_program fp; /* The compiled filter expression */
  bpf_u_int32 mask;      /* The netmask of our sniffing device */
  bpf_u_int32 net;       /* The IP of our sniffing device */

  /* Set the handle according to a supplied file or interface, or a default one
   */
  if (file) {
    handle = pcap_open_offline(file, errbuf);

    if (!handle) {
      fprintf(stderr, "%s: %s\n", program_name, errbuf);
      exit(EXIT_FAILURE);
    }
  } else {
    if (defaulting)
      /* Similar to pcap_lookupdev but does not just select the first non
       * loopback device but also the first one that is up and running
       * (connected) */
      interface = custom_lookupdev();

    handle = pcap_open_live(interface, SNAPLEN, 1, 1, errbuf);
    if (!handle) {
      fprintf(stderr, "%s: %s\n", program_name, errbuf);

      /* Check if the error message corresponds to the
       * PCAP_ERROR_NO_SUCH_DEVICE message. */
      if (strstr(errbuf, pcap_statustostr(PCAP_ERROR_NO_SUCH_DEVICE)) != NULL)
        print_devices();

      exit(EXIT_FAILURE);
    }

    apply_bpf_filter(interface, &fp, &mask, &net, filter);
    signal(SIGINT, print_live_capture_summary);
  }

  /* Pretty print to show which interface or file we are sniffing */
  init_message(interface, file, defaulting, verbosity);

  /* Bulk of the program */
  struct pcap_handler_args args = {verbosity};
  pcap_loop(handle, 0, got_packet, (u_char *)&args);

  /* Clean up */
  pcap_freecode(&fp);
  pcap_close(handle);
}

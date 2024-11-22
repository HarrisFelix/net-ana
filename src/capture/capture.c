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
#include <pcap/sll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char const *program_name;
extern enum verbosity_level verbosity;
pcap_t *handle;
u_int captured_packets_count = 0;

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  /* Define packet handling related structures. */
  u_short protocol;
  u_int size_header;

  print_timestamp(header);

  /* We have to handle different link types that have different headers */
  switch (pcap_datalink(handle)) {
  case DLT_EN10MB:
    /* EtherType or LSAP value */
    size_header = sizeof(struct ether_header);
    protocol =
        print_ethernet_header((const struct ether_header *)packet, header->len);
    break;
  case DLT_NULL:
    /* BSD Loopback protocol */
    size_header = sizeof(struct bsd_loopback_hdr);
    protocol = print_loopback_header((const struct bsd_loopback_hdr *)packet);
    break;
  case DLT_RAW:
    /* RAW IP Frame */
    size_header = 0;
    protocol = (packet[0] >> 4) == 4 ? ETHERTYPE_IP : ETHERTYPE_IPV6;
    printf(" RAW IPv%c", protocol == ETHERTYPE_IP ? '4' : '6');
    break;
  case DLT_LINUX_SLL2:
    /* Linux Cooked Capture 2 */
    /* TODO: Complete support for Linux Cooked Capture */
    size_header = sizeof(struct sll2_header);
    protocol = print_linux_cooked_header((const struct sll2_header *)packet);
    break;
  }

  /* Print the frame according to the protocol */
  switch (protocol) {
  case ETHERTYPE_IP:
  case LOOPBACK_IP:
    print_ip_frame((struct ip *)(packet + size_header));
    break;
  case ETHERTYPE_IPV6:
  case LOOPBACK_IP6_1:
  case LOOPBACK_IP6_2:
  case LOOPBACK_IP6_3:
    print_ip6_frame((struct ip6_hdr *)(packet + size_header));
    break;
  case ETHERTYPE_ARP:
    print_arp_frame((struct arphdr *)(packet + size_header));
    break;
  }

  /* Size of the frame without counting the ethernet header */
  printf(", length %d", header->len - size_header);

  /* Print the bytes and ASCII of the packet. */
  if (verbosity == HIGH)
    print_packet_bytes(packet, header->caplen);

  printf("\n");
  captured_packets_count++;
}

void capture_loop(char *interface, char *file, char *filter,
                  u_int verbose_output) {
  char errbuf[PCAP_ERRBUF_SIZE];
  bool defaulting = (bool)(!interface && !file);
  verbosity = verbose_output;

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
  init_message(interface, file, defaulting);

  /* Bulk of the program */
  pcap_loop(handle, 0, got_packet, NULL);

  /* Clean up */
  pcap_freecode(&fp);
  pcap_close(handle);
}

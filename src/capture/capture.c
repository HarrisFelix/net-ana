#include "../protocols/data-link.h"
#include "../protocols/network.h"
#include "capture.h"
#include "capture_utils.h"
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
  const struct ether_header *ethernet;
  const struct ip *ip;
  const struct ip6_hdr *ip6;
  const struct arphdr *arp;

  /* Cast ethernet and ip frame. */
  int size_ethernet = sizeof(struct ether_header);
  ethernet = (struct ether_header *)(packet);

  print_timestamp(header);

  /* EtherType or LSAP value */
  // FIXME: We should treat LINKTYPE NULL differently...
  u_short ether_value =
      print_ethernet_header(ethernet, header->len, packet_args->verbosity);

  /* Print the frame according to the protocol */
  switch (ether_value) {
  case ETHERTYPE_IP:
    ip = (struct ip *)(packet + size_ethernet);
    print_ip_frame(ip, packet_args->verbosity);
    break;
  case ETHERTYPE_IPV6:
    ip6 = (struct ip6_hdr *)(packet + size_ethernet);
    print_ip6_frame(ip6, packet_args->verbosity);
    break;
  case ETHERTYPE_ARP:
    arp = (struct arphdr *)(packet + size_ethernet);
    print_arp_frame(arp, packet_args->verbosity);
    break;
  }

  /* Size of the frame without counting the ethernet header */
  printf(", length %d", header->len - size_ethernet);

  /* Print the bytes and ASCII of the packet. */
  if (packet_args->verbosity == HIGH)
    print_packet_bytes(packet, header->caplen);

  printf("\n");
  captured_packets_count++;
}

void init_message(char *interface, char *file, bool defaulting,
                  enum verbosity_level verbosity) {
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

void capture_loop(char *interface, char *file, char *filter, u_int verbosity) {
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_handler_args args = {verbosity};
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
  pcap_loop(handle, 0, got_packet, (u_char *)&args);

  /* Clean up */
  pcap_freecode(&fp);
  pcap_close(handle);
}

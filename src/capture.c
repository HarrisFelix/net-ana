#include "capture.h"
#include "protocols/eth.h"
#include "utils.h"
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

pcap_t *handle;

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  /* Define packet handling related structures. */
  struct pcap_handler_args *packet_args = (struct pcap_handler_args *)args;
  const struct ether_header *ethernet;
  const struct ip *ip;
  const struct arp_hdr *arp;

  /* Cast ethernet and ip frame. */
  int size_ethernet = sizeof(struct ether_header);
  ethernet = (struct ether_header *)(packet);

  print_timestamp(header);

  /* https://en.wikipedia.org/wiki/EtherType */
  u_short ether_value = print_ethernet_header(ethernet, packet_args->verbosity);

  /* Print the frame according to the protocol */
  switch (ether_value) {
  case ETHERTYPE_IP:
    ip = (struct ip *)(packet + size_ethernet);
    break;
  case ETHERTYPE_IPV6:
    break;
  case ETHERTYPE_ARP:
    arp = (struct arp_hdr *)(packet + size_ethernet);
    break;
  }

  printf("\n");
}

void init_message(char *program_name, char *interface, char *file,
                  bool defaulting, bool supplied_verbosity) {
  int data_link = pcap_datalink(handle);

  if (defaulting)
    printf("%s: defaulting to data link type %s\n", program_name,
           pcap_datalink_val_to_name(data_link));

  if (!supplied_verbosity)
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

void capture_loop(char *program_name, char *interface, char *file, char *filter,
                  u_int verbosity, bool supplied_verbosity) {
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_handler_args args = {verbosity};
  bool defaulting = (bool)(!interface && !file);

  if (file) {
    handle = pcap_open_offline(file, errbuf);

    if (!handle) {
      fprintf(stderr, "%s: %s\n", program_name, errbuf);
      exit(EXIT_FAILURE);
    }
  } else {
    if (defaulting)
      interface = get_first_non_loopback_device(program_name);

    handle = pcap_open_live(interface, SNAPLEN, 1, 1, errbuf);
    if (!handle) {
      fprintf(stderr, "%s: %s\n", program_name, errbuf);

      /* Check if the error message corresponds to the
       * PCAP_ERROR_NO_SUCH_DEVICE message. */
      if (strstr(errbuf, pcap_statustostr(PCAP_ERROR_NO_SUCH_DEVICE)) != NULL)
        print_devices(program_name);

      exit(EXIT_FAILURE);
    }

    signal(SIGINT, print_live_capture_summary);
  }

  init_message(program_name, interface, file, defaulting, supplied_verbosity);

  pcap_loop(handle, 0, got_packet, (u_char *)&args);

  pcap_close(handle);
}

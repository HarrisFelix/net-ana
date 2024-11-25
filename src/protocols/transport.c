#include "../capture/capture_utils.h"
#include "network.h"
#include "transport.h"
#include <stdio.h>

extern enum verbosity_level verbosity;

struct ports get_ports(const void *header, u_char protocol) {
  if (protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (struct tcphdr *)header;

    return (struct ports){htons(tcp->th_sport), htons(tcp->th_dport)};
  } else if (protocol == IPPROTO_UDP) {
    struct udphdr *udp = (struct udphdr *)header;

    return (struct ports){htons(udp->uh_sport), htons(udp->uh_dport)};
  } else {
    return (struct ports){0, 0};
  }
}

void print_tcp_flags(uint8_t flags) {
  printf("[");
  const char *delimiter = "";

  if (!flags) {
    printf("none");
  } else {
    if (flags & TH_FIN) {
      printf("%sFIN", delimiter);
      delimiter = " ";
    }
    if (flags & TH_SYN) {
      printf("%sSYN", delimiter);
      delimiter = " ";
    }
    if (flags & TH_RST) {
      printf("%sRST", delimiter);
      delimiter = " ";
    }
    if (flags & TH_PUSH) {
      printf("%sPSH", delimiter);
      delimiter = " ";
    }
    if (flags & TH_ACK) {
      printf("%sACK", delimiter);
      delimiter = " ";
    }
    if (flags & TH_URG) {
      printf("%sURG", delimiter);
      delimiter = " ";
    }
    if (flags & TH_ECE) {
      printf("%sECE", delimiter);
      delimiter = " ";
    }
    if (flags & TH_CWR) {
      printf("%sCWR", delimiter);
    }
  }

  printf("]");
}

/* https://datatracker.ietf.org/doc/html/rfc9293 */
void print_tcp_frame(const struct tcphdr *tcp) {
  printf(": TCP");

  if (verbosity <= LOW)
    return;

  struct ports ports = get_ports(tcp, IPPROTO_UDP);
  printf(", %d > %d", ports.source, ports.destination);

  printf(", seq %d", htons(tcp->th_seq));
  printf(", ack %d", htons(tcp->th_ack));
  printf(", offset %d", tcp->th_off);
  printf(", reserved 0x%x", tcp->th_x2);

  printf(", flags ");
  print_tcp_flags(tcp->th_flags);

  printf(", win %d", htons(tcp->th_win));

  /* Are we working with IPv4 or with IPv6? */
  struct pseudo_ip_hdr pseudo_ip;
  struct ip *ip = (struct ip *)((char *)tcp - sizeof(struct ip));
}

void print_udp_frame(const struct udphdr *udp) {
  printf(": UDP");

  if (verbosity <= LOW)
    return;

  struct ports ports = get_ports(udp, IPPROTO_UDP);
  printf(", %d > %d", ports.source, ports.destination);
}

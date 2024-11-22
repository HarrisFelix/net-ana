#include "../capture/capture_utils.h"
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

void print_tcp_frame(const struct tcphdr *tcp) {
  printf(": TCP");

  struct ports ports = get_ports(tcp, IPPROTO_UDP);

  if (verbosity == NONE)
    return;
}
void print_udp_frame(const struct udphdr *udp) {
  printf(": UDP");

  struct ports ports = get_ports(udp, IPPROTO_UDP);

  if (verbosity == NONE)
    return;
}

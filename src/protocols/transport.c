#include "transport.h"

struct ports get_ports(const void *header, u_char protocol) {
  if (protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (struct tcphdr *)header;

    return (struct ports){tcp->th_sport, tcp->th_dport};
  } else if (protocol == IPPROTO_UDP) {
    struct udphdr *udp = (struct udphdr *)header;

    return (struct ports){udp->uh_sport, udp->uh_dport};
  } else {
    return (struct ports){0, 0};
  }
}

void print_tcp_frame(const struct tcphdr *tcp, enum verbosity_level verbosity) {
  printf(": TCP");
  if (verbosity == NONE)
    return;
}
void print_udp_frame(const struct udphdr *udp, enum verbosity_level verbosity) {
  printf(": UDP");
  if (verbosity == NONE)
    return;
}

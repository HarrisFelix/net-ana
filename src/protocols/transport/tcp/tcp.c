#include "../../../capture/capture_utils.h"
#include "../../network/ip/ip.h"
#include "../../network/ip6/ip6.h"
#include "tcp.h"

extern enum verbosity_level verbosity;

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
void print_tcp_frame(const struct tcphdr *tcp, bool is_ipv6) {
  printf(": TCP");

  if (verbosity <= LOW)
    return;

  // struct ports ports = get_ports(tcp, IPPROTO_UDP);
  // printf(", %d > %d", ports.source, ports.destination);

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

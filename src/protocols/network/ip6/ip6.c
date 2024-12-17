#include "../../../capture/capture_utils.h"
#include "../../../utils/utils.h"
#include "../../transport/tcp/tcp.h"
#include "../../transport/udp/udp.h"
#include "../icmp6/icmp6.h"
#include "ip6.h"
#include <stdbool.h>
#include <stdio.h>

extern enum verbosity_level verbosity;
extern u_int payload_length;

/* Print the encapsulated protocol of an IP or IPv6 frame
 * TODO: Not happy with the way the len is managed, sometimes transformed into
 * 32 bits words, sometimes not, have to make it predictable instead of having
 * to think of the format of whats passed down to the lower functions, maybe
 * through explicit names ? */
void print_ip6_encapsulated_protocol(const void *header, u_char protocol,
                                     uint16_t len) {
  switch (protocol) {
  case IPPROTO_TCP:
    print_tcp_frame((const struct tcphdr *)header, true);
    break;
  case IPPROTO_UDP:
    print_udp_frame((const struct udphdr *)header, true);
    break;
  case IPPROTO_ICMPV6:
    print_icmp6_frame((const struct icmp6_hdr *)header, len);
    break;
  default:
    printf(": Unsupported protocol (%d)", protocol);
  }
}

void print_ip6_frame(const struct ip6_hdr *ip6) {
  if (verbosity >= MEDIUM) {
    printf(" (flowlabel 0x%x", htonl(ip6->ip6_flow & IPV6_FLOWLABEL_MASK));
    printf(", hlim %d", htons(ip6->ip6_hlim));
    printf(", next-header %s (%d)",
           string_to_upper(getprotobynumber(ip6->ip6_nxt)->p_name),
           ip6->ip6_nxt);
    printf(", payload length: %d)", htons(ip6->ip6_plen));
  }

  /* Same logic as the IPv4 frame */
  char hbuf[NI_MAXHOST];

  /* Source */
  inet_ntop(AF_INET6, &ip6->ip6_src, hbuf, INET6_ADDRSTRLEN);
  printf(", %s >", hbuf);

  /* Destination */
  inet_ntop(AF_INET6, &ip6->ip6_dst, hbuf, INET6_ADDRSTRLEN);
  printf(" %s", hbuf);

  /* Update the payload length */
  payload_length = htons(ip6->ip6_plen);

  /* Now we can take care of printing the encapsulated protocol, the IPv6
   * payload
   * TODO: Take care of the length appropriately */
  print_ip6_encapsulated_protocol(ip6 + 1, ip6->ip6_nxt, ip6->ip6_plen);
}

void set_pseudo_ip6_hdr(struct pseudo_ip6_hdr *pseudo_ip6,
                        const struct in6_addr src, const struct in6_addr dst,
                        uint16_t plen, uint8_t nxt) {
  pseudo_ip6->ip6_src = src;
  pseudo_ip6->ip6_dst = dst;
  pseudo_ip6->plen = plen;
  pseudo_ip6->nxt = nxt;

  pseudo_ip6->zero[0] = 0;
  pseudo_ip6->zero[1] = 0;
  pseudo_ip6->zero[2] = 0;
}

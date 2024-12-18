#include "../../../capture/capture_utils.h"
#include "../../../capture/packet_utils.h"
#include "../../../utils/utils.h"
#include "../../transport/tcp/tcp.h"
#include "../../transport/udp/udp.h"
#include "../icmp/icmp.h"
#include "ip.h"
#include <stdbool.h>
#include <stdio.h>

extern enum verbosity_level verbosity;
extern int payload_length;

/* Print the encapsulated protocol of an IP frame
 * TODO: Not happy with the way the len is managed, sometimes transformed into
 * 32 bits words, sometimes not, have to make it predictable instead of having
 * to think of the format of whats passed down to the lower functions, maybe
 * through explicit names ? */
void print_ip_encapsulated_protocol(const void *header, u_char protocol,
                                    uint16_t len) {
  switch (protocol) {
  case IPPROTO_TCP:
    print_tcp_frame((const struct tcphdr *)header, false);
    break;
  case IPPROTO_UDP:
    print_udp_frame((const struct udphdr *)header, false);
    break;
  case IPPROTO_ICMP:
    print_icmp_frame((const struct icmp *)header, len);
    break;
  case IPPROTO_IGMP:
  default:
    printf(": Unsupported protocol (%d)", protocol);
  }
}

void print_ip_frame(const struct ip *ip) {
  if (verbosity >= MEDIUM) {
    printf(" (");
    if (verbosity == HIGH) {
      printf("version %d", ip->ip_v);
      printf(", ihl %d, ", ip->ip_hl);
    }
    printf("tos 0x%d", ip->ip_tos);
    printf(", ttl %d", ip->ip_ttl);
    printf(", id %d", htons(ip->ip_id));
    printf(", offset %d", htons(ip->ip_off) & IP_OFFMASK);
    /* Seemingly DF and MF can be set at the same time
     * https://ask.wireshark.org/question/22131/strange-ip-flags-mf-and-df/ */
    printf(", flags [%s%s%s%s]", (htons(ip->ip_off) & IP_RF) ? "RF" : "",
           (htons(ip->ip_off) & IP_DF) ? "DF" : "",
           (htons(ip->ip_off) & IP_MF) ? "MF" : "",
           (htons(ip->ip_off) & ~IP_OFFMASK) ? "" : "none");
    printf(", proto %s (%d)",
           string_to_upper(getprotobynumber(ip->ip_p)->p_name), ip->ip_p);
    printf(", chksum 0x%04x (%s)", htons(ip->ip_sum),
           (validate_checksum(NULL, false, (const void *)ip, ip->ip_hl))
               ? "incorrect"
               : "correct");
    printf(", length %d)", htons(ip->ip_len));
  }

  /* Print the source and destination addresses */
  char hbuf[NI_MAXHOST];

  /* Source */
  inet_ntop(AF_INET, &ip->ip_src, hbuf, INET_ADDRSTRLEN);
  printf(", %s >", hbuf);

  /* Destination */
  inet_ntop(AF_INET, &ip->ip_dst, hbuf, INET_ADDRSTRLEN);
  printf(" %s", hbuf);

  /* Update payload length */
  payload_length -= ip->ip_hl * 4;

  /* Now we can take care of printing the encapsulated protocol, the IP payload,
   * length converted to number of 32-bit words for checksum purposes but kept
   * in host byte order
   */
  print_ip_encapsulated_protocol(ip + 1, ip->ip_p,
                                 ntohs(htons(ip->ip_len) / 2 - ip->ip_hl));
}

void set_pseudo_ip_hdr(struct pseudo_ip_hdr *pseudo_ip,
                       const struct in_addr src, const struct in_addr dst,
                       uint8_t protocol, uint16_t tcp_len) {
  pseudo_ip->ip_src = src;
  pseudo_ip->ip_dst = dst;
  pseudo_ip->zero = 0;
  pseudo_ip->ip_p = protocol;
  pseudo_ip->tcp_len = tcp_len;
}

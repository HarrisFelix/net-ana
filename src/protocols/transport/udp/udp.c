#include "../../../capture/capture_utils.h"
#include "../../../capture/packet_utils.h"
#include "../../application/bootp/bootp.h"
#include "../../application/dns/dns.h"
#include "../../network/ip/ip.h"
#include "../../network/ip6/ip6.h"
#include "udp.h"

extern enum verbosity_level verbosity;
extern int payload_length;

void print_udp_encapsulated_protocol(const struct udphdr *udp) {
  uint16_t src = htons(udp->uh_sport);
  uint16_t dst = htons(udp->uh_dport);

  if (src == DNS_PORT || dst == DNS_PORT) {
    print_dns_frame();
  } else if (src == BOOTP_DHCP_SERVER_PORT || dst == BOOTP_DHCP_SERVER_PORT ||
             src == BOOTP_DHCP_CLIENT_PORT || dst == BOOTP_DHCP_CLIENT_PORT) {
    print_bootp_frame((const struct bootp *)udp + sizeof(struct udphdr));
  } else {
    printf(": Unsupported protocol");
  }
}

void print_udp_frame(const struct udphdr *udp, bool is_ipv6) {
  printf(": UDP");
  printf(", ports [src:%d, dst:%d]", htons(udp->uh_sport),
         htons(udp->uh_dport));

  if (verbosity <= LOW) {
    return;
  }

  printf(", udp length %d", htons(udp->uh_ulen));
  print_udp_cksum(udp, is_ipv6);
  payload_length -= (htons(udp->uh_ulen) - payload_length);
  print_udp_encapsulated_protocol(udp);
}

void print_udp_cksum(const struct udphdr *udp, bool is_ipv6) {
  /* We calculate uhe checksum so we have to use a different header depending on
   * if we're working wiuh IPv4 or IPv6 */
  if (is_ipv6) {
    struct pseudo_ip6_hdr pseudo_ip6;
    struct ip6_hdr *ip6 =
        (struct ip6_hdr *)((char *)udp - sizeof(struct ip6_hdr));
    set_pseudo_ip6_hdr(&pseudo_ip6, ip6->ip6_src, ip6->ip6_dst, udp->uh_ulen,
                       ip6->ip6_nxt);

    printf(", udp cksum 0x%04x (%s)", htons(udp->uh_sum),
           validate_checksum(
               (const void *)&pseudo_ip6, is_ipv6, udp,
               LITTLE_ENDIAN_INT_TO_32_BIT_WORDS(htons(udp->uh_ulen)))
               ? "incorrect"
               : "correct");

  } else {
    struct pseudo_ip_hdr pseudo_ip;
    struct ip *ip = (struct ip *)((char *)udp - sizeof(struct ip));
    set_pseudo_ip_hdr(&pseudo_ip, ip->ip_src, ip->ip_dst, ip->ip_p,
                      udp->uh_ulen);

    printf(", udp cksum 0x%04x (%s)", htons(udp->uh_sum),
           validate_checksum(
               (const void *)&pseudo_ip, is_ipv6, udp,
               LITTLE_ENDIAN_INT_TO_32_BIT_WORDS(htons(udp->uh_ulen)))
               ? "incorrect"
               : "correct");
  }
}

#include "../../../capture/capture_utils.h"
#include "../../../capture/packet_utils.h"
#include "../ip6/ip6.h"
#include "icmp6.h"
#include <stdbool.h>
#include <stdio.h>

void print_icmp6_frame(const struct icmp6_hdr *icmp6, uint16_t len) {
  char buf[INET6_ADDRSTRLEN];
  union icmp6_un icmp6_un;

  printf(": ICMP6");

  if (verbosity >= MEDIUM) {
    /* Pseudo header for checksum calculation as per RFC 4443, some pointer
     * arithmetic to retrieve source and destination addresses */
    struct pseudo_ip6_hdr pseudo_ip6;
    const struct ip6_hdr *ip6 =
        (const struct ip6_hdr *)((char *)icmp6 - sizeof(struct ip6_hdr));
    set_pseudo_ip6_hdr(&pseudo_ip6, ip6->ip6_src, ip6->ip6_dst, len,
                       IPPROTO_ICMPV6);

    printf(", cksum 0x%04x (%s)", htons(icmp6->icmp6_cksum),
           validate_checksum((const void *)&pseudo_ip6, true, icmp6,
                             htons(len) / 4)
               ? "incorrect"
               : "correct");
  }

  switch (icmp6->icmp6_type) {
  case ND_ROUTER_SOLICIT:
    printf(", router solicitation");
    break;
  case ND_ROUTER_ADVERT:
    icmp6_un.ra = (const struct nd_router_advert *)icmp6;

    printf(", router advertisement");

    if (verbosity == LOW)
      break;

    printf(", flags [");

    if (icmp6_un.ra->nd_ra_flags_reserved & ND_RA_FLAG_HA)
      printf("H");
    if (icmp6_un.ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER)
      printf("O");
    if (icmp6_un.ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED)
      printf("M");
    if (!icmp6_un.ra->nd_ra_flags_reserved)
      printf("none");

    printf("]");

    break;
  case ND_NEIGHBOR_SOLICIT:
    icmp6_un.ns = (const struct nd_neighbor_solicit *)icmp6;

    printf(
        ", neighbor solicitation, who has %s",
        inet_ntop(AF_INET6, &icmp6_un.ns->nd_ns_target, buf, INET6_ADDRSTRLEN));
    break;
  case ND_NEIGHBOR_ADVERT:
    icmp6_un.na = (const struct nd_neighbor_advert *)icmp6;

    printf(", neighbor advertisement");

    if (verbosity == LOW)
      break;

    printf(", target is %s", inet_ntop(AF_INET6, &icmp6_un.na->nd_na_target,
                                       buf, INET6_ADDRSTRLEN));

    printf(", flags [");

    if (icmp6_un.na->nd_na_flags_reserved & ND_NA_FLAG_OVERRIDE)
      printf("O");
    if (icmp6_un.na->nd_na_flags_reserved & ND_NA_FLAG_SOLICITED)
      printf("S");
    if (icmp6_un.na->nd_na_flags_reserved & ND_NA_FLAG_ROUTER)
      printf("R");
    if (!icmp6_un.na->nd_na_flags_reserved)
      printf("none");

    printf("]");

    break;
  default:
    /* TODO: Add more ICMPv6 types */
    printf(", unsupported type %d", icmp6->icmp6_type);
  }

  if (verbosity >= MEDIUM)
    return;
}

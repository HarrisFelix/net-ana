#include "../capture/capture_utils.h"
#include "../capture/packet_utils.h"
#include "../utils/utils.h"
#include "network.h"
#include "transport.h"
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

extern enum verbosity_level verbosity;

/* Print the encapsulated protocol of an IP or IPv6 frame
 * TODO: Not happy with the way the len is managed, sometimes transformed into
 * 32 bits words, sometimes not, have to make it predictable instead of having
 * to think of the format of whats passed down to the lower functions, maybe
 * through explicit names ? */
void print_ip_or_ip6_encapsulated_protocol(const void *header, u_char protocol,
                                           uint16_t len) {
  switch (protocol) {
  case IPPROTO_TCP:
    print_tcp_frame((const struct tcphdr *)header);
    break;
  case IPPROTO_UDP:
    print_udp_frame((const struct udphdr *)header);
    break;
  case IPPROTO_ICMP:
    print_icmp_frame((const struct icmp *)header, len);
    break;
  case IPPROTO_ICMPV6:
    print_icmp6_frame((const struct icmp6_hdr *)header, len);
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
           (validate_checksum(NULL, (const void *)ip, ip->ip_hl)) ? "incorrect"
                                                                  : "correct");
    printf(", length %d)", htons(ip->ip_len));
  }

  /* Printing the name of the address and service if we manage to find one */
  struct ports ports = get_ports(ip + 1, ip->ip_p);
  char hbuf[NI_MAXHOST];

  /* Source */
  inet_ntop(AF_INET, &ip->ip_src, hbuf, INET_ADDRSTRLEN);
  if (ports.source && verbosity == LOW)
    printf(", %s.%d >", hbuf, ports.source);
  else
    printf(", %s >", hbuf);

  /* Destination */
  inet_ntop(AF_INET, &ip->ip_dst, hbuf, INET_ADDRSTRLEN);
  printf(" %s", hbuf);
  if (ports.destination && verbosity == LOW)
    printf(".%d", ports.destination);

  /* Now we can take care of printing the encapsulated protocol, the IP payload,
   * length converted to number of 32-bit words for checksum purposes but kept
   * in host byte order
   */
  print_ip_or_ip6_encapsulated_protocol(
      ip + 1, ip->ip_p, ntohs(htons(ip->ip_len) / 2 - ip->ip_hl));
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
  struct ports ports = get_ports(ip6 + 1, ip6->ip6_nxt);
  char hbuf[NI_MAXHOST];

  /* Source */
  inet_ntop(AF_INET6, &ip6->ip6_src, hbuf, INET6_ADDRSTRLEN);
  if (ports.source && verbosity == LOW)
    printf(", %s.%d >", hbuf, ports.source);
  else
    printf(", %s >", hbuf);

  /* Destination */
  inet_ntop(AF_INET6, &ip6->ip6_dst, hbuf, INET6_ADDRSTRLEN);
  printf(" %s", hbuf);
  if (ports.destination && verbosity == LOW)
    printf(".%d", ports.destination);

  /* Now we can take care of printing the encapsulated protocol, the IPv6
   * payload
   * TODO: Take care of the length appropriately */
  print_ip_or_ip6_encapsulated_protocol(ip6 + 1, ip6->ip6_nxt, ip6->ip6_plen);
}

void print_icmp_frame(const struct icmp *icmp, uint16_t len) {
  printf(": ICMP");

  switch (icmp->icmp_type) {
  case ICMP_ECHOREPLY:
    printf(", echo reply");
    break;
  case ICMP_ECHO:
    printf(", echo request");
    break;
  case ICMP_UNREACH:
  default:
    printf(", type %d", icmp->icmp_type);
  }

  printf(", id %d, seq %d", htons(icmp->icmp_id), htons(icmp->icmp_seq));

  if (verbosity >= MEDIUM)
    printf(", cksum 0x%04x (%s)", htons(icmp->icmp_cksum),
           validate_checksum(NULL, icmp, htons(len)) ? "incorrect" : "correct");
}

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
           validate_checksum((const void *)&pseudo_ip6, icmp6, htons(len) / 4)
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

void set_pseudo_ip_hdr(struct pseudo_ip_hdr *pseudo_ip,
                       const struct in_addr src, const struct in_addr dst,
                       uint8_t protocol, uint16_t tcp_len) {
  pseudo_ip->ip_src = src;
  pseudo_ip->ip_dst = dst;
  pseudo_ip->zero = 0;
  pseudo_ip->ip_p = protocol;
  pseudo_ip->tcp_len = tcp_len;
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

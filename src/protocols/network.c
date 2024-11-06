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

/* Print the encapsulated protocol of an IP or IPv6 frame, uint32_t was
 * chosen instead of uint16_t to support Jumbo Payload of IPv6 */
void print_ip_or_ip6_encapsulated_protocol(const void *header, u_char protocol,
                                           uint32_t len,
                                           enum verbosity_level verbosity) {
  switch (protocol) {
  case IPPROTO_TCP:
    print_tcp_frame((const struct tcphdr *)header, verbosity);
    break;
  case IPPROTO_UDP:
    print_udp_frame((const struct udphdr *)header, verbosity);
    break;
  case IPPROTO_ICMP:
    print_icmp_frame((const struct icmp *)header, len, verbosity);
    break;
  case IPPROTO_ICMPV6:
    print_icmp6_frame((const struct icmp6_hdr *)header, len, verbosity);
    break;
  case IPPROTO_IGMP:
  default:
    printf(": Unsupported protocol (%d)", protocol);
  }
}

void print_ip_frame(const struct ip *ip, enum verbosity_level verbosity) {
  int error;
  int flags = 0;

  if (verbosity >= MEDIUM) {
    flags = NI_NUMERICHOST | NI_NUMERICSERV;

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
           (validate_checksum((const void *)ip, ip->ip_hl)) ? "incorrect"
                                                            : "correct");
    printf(", length %d)", htons(ip->ip_len));
  }

  /* Printing the name of the address and service if we manage to find one */
  struct ports ports = get_ports(ip + 1, ip->ip_p);

  struct sockaddr_in src_addr_in;
  src_addr_in.sin_family = AF_INET;
  src_addr_in.sin_port = ports.source;
  src_addr_in.sin_addr = ip->ip_src;

  struct sockaddr_in dst_addr_in;
  dst_addr_in.sin_family = AF_INET;
  src_addr_in.sin_port = ports.destination;
  dst_addr_in.sin_addr = ip->ip_dst;

  const struct sockaddr *src_addr = (const struct sockaddr *)&src_addr_in;
  const struct sockaddr *dst_addr = (const struct sockaddr *)&dst_addr_in;
  socklen_t addrlen = sizeof(struct sockaddr_in);
  char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

  /* Source */
  if ((error = getnameinfo(src_addr, addrlen, hbuf, sizeof(hbuf), sbuf,
                           sizeof(sbuf), flags)) == 0) {
    if (ports.source && verbosity == LOW)
      printf(", %s.%s >", hbuf, sbuf);
    else
      printf(", %s >", hbuf);
  } else
    printf(", %s >\n", gai_strerror(error));

  /* Destination */
  if ((error = getnameinfo(dst_addr, addrlen, hbuf, sizeof(hbuf), sbuf,
                           sizeof(sbuf), flags)) == 0) {
    printf(" %s", hbuf);
    if (ports.destination && verbosity == LOW)
      printf(".%s", sbuf);
  } else
    printf(" %s\n", gai_strerror(error));

  /* Now we can take care of printing the encapsulated protocol, the IP payload,
   * length converted to number of 32-bit words for checksum purposes
   */
  print_ip_or_ip6_encapsulated_protocol(
      ip + 1, ip->ip_p, htons(ip->ip_len) / 2 - ip->ip_hl, verbosity);
}

void print_ip6_frame(const struct ip6_hdr *ip6,
                     enum verbosity_level verbosity) {
  int error;
  int flags = 0;

  if (verbosity >= MEDIUM) {
    flags = NI_NUMERICHOST | NI_NUMERICSERV;

    printf(" (flowlabel 0x%x",
           htonl(ip6->ip6_ctlun.ip6_un1.ip6_un1_flow & IPV6_FLOWLABEL_MASK));
    printf(", hlim %d", htons(ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim));
    printf(", next-header %s (%d)",
           string_to_upper(
               getprotobynumber(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt)->p_name),
           ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
    printf(", payload length: %d)", htons(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
  }

  /* Same logic as the IPv4 frame */
  struct ports ports = get_ports(ip6 + 1, ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);

  struct sockaddr_in6 src_addr_in6;
  src_addr_in6.sin6_family = AF_INET6;
  src_addr_in6.sin6_port = ports.source;
  src_addr_in6.sin6_addr = ip6->ip6_src;

  struct sockaddr_in6 dst_addr_in6;
  dst_addr_in6.sin6_family = AF_INET6;
  src_addr_in6.sin6_port = ports.destination;
  dst_addr_in6.sin6_addr = ip6->ip6_dst;

  const struct sockaddr *src_addr = (const struct sockaddr *)&src_addr_in6;
  const struct sockaddr *dst_addr = (const struct sockaddr *)&dst_addr_in6;
  socklen_t addrlen = sizeof(struct sockaddr_in);
  char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

  /* Source */
  // TODO: Lookup table to increase speed, maybe with a fixed table size of 100?
  // FIXME: When the port is a local port, it outputs "number%lo" instead of
  // "local", also doesn't seem to recognize the local machine name...
  if ((error = getnameinfo(src_addr, addrlen, hbuf, sizeof(hbuf), sbuf,
                           sizeof(sbuf), flags)) == 0) {
    if (ports.source && verbosity == LOW)
      printf(", %s.%s >", hbuf, sbuf);
    else
      printf(", %s >", hbuf);
  } else
    printf(", %s >\n", gai_strerror(error));

  /* Destination */
  if ((error = getnameinfo(dst_addr, addrlen, hbuf, sizeof(hbuf), sbuf,
                           sizeof(sbuf), flags)) == 0) {
    printf(" %s", hbuf);
    if (ports.destination && verbosity == LOW)
      printf(".%s", sbuf);
  } else
    printf(" %s\n", gai_strerror(error));

  /* Now we can take care of printing the encapsulated protocol, the IPv6
   * payload
   * TODO: Take care of the length appropriately */
  print_ip_or_ip6_encapsulated_protocol(
      ip6 + 1, ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt,
      ip6->ip6_ctlun.ip6_un1.ip6_un1_plen, verbosity);
}

void print_icmp_frame(const struct icmp *icmp, uint32_t len,
                      enum verbosity_level verbosity) {
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

  printf(", id %d, seq %d", htons(icmp->icmp_hun.ih_idseq.icd_id),
         htons(icmp->icmp_hun.ih_idseq.icd_seq));

  if (verbosity >= MEDIUM)
    printf(", cksum 0x%04x (%s)", htons(icmp->icmp_cksum),
           validate_checksum(icmp, len) ? "incorrect" : "correct");
}

void print_icmp6_frame(const struct icmp6_hdr *icmp6, uint32_t len,
                       enum verbosity_level verbosity) {
  char buf[INET6_ADDRSTRLEN];

  printf(": ICMP6");

  /* FIXME: inet_ntoa deprecated */
  switch (icmp6->icmp6_type) {
  case ND_ROUTER_SOLICIT:
    printf(", router solicitation");
    break;
  case ND_ROUTER_ADVERT:
    printf(", router advertisement");
    break;
  case ND_NEIGHBOR_SOLICIT:
    printf(", neighbor solicitation, who has %s",
           inet_ntop(AF_INET6,
                     &((const struct nd_neighbor_solicit *)icmp6)->nd_ns_target,
                     buf, INET6_ADDRSTRLEN));
    // printf("Flags [%s]");
    break;
  case ND_NEIGHBOR_ADVERT:
    printf(", neighbor advertisement");
    if (verbosity >= MEDIUM)
      printf(
          ", target is %s",
          inet_ntop(AF_INET6,
                    &((const struct nd_neighbor_advert *)icmp6)->nd_na_target,
                    buf, INET6_ADDRSTRLEN));
    break;
  default:
    printf(", type %d", icmp6->icmp6_type);
  }

  if (verbosity >= MEDIUM)
    return;
}

#include "../utils/utils.h"
#include "network.h"
#include <netdb.h>
#include <netinet/in.h>

void print_ip_frame(const struct ip *ip, enum verbosity_level verbosity) {
  if (verbosity >= MEDIUM) {
    printf(" (tos 0x%d", ip->ip_tos);
    printf(", ttl %d", ip->ip_ttl);
    printf(", id %d", htons(ip->ip_id));
    printf(", offset %d", htons(ip->ip_off) & IP_OFFMASK);
    /* Seeminggly DF and MF can be set at the same time
     * https://ask.wireshark.org/question/22131/strange-ip-flags-mf-and-df/ */
    printf(", flags [%s%s%s%s]", (htons(ip->ip_off) & IP_RF) ? "RF" : "",
           (htons(ip->ip_off) & IP_DF) ? "DF" : "",
           (htons(ip->ip_off) & IP_MF) ? "MF" : "",
           (htons(ip->ip_off) & ~IP_OFFMASK) ? "" : "none");
    printf(", proto %s (%d)",
           string_to_upper(getprotobynumber(ip->ip_p)->p_name), ip->ip_p);
    printf(", length %d)", htons(ip->ip_len));
  }

  printf(", %s", inet_ntoa(ip->ip_src));
  printf(" %s", inet_ntoa(ip->ip_dst));
}

void print_ip6_frame(const struct ip6_hdr *ip6,
                     enum verbosity_level verbosity) {}

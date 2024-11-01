#include "data-link.h"
#include <net/if_arp.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

ether_type_t ether_types[] = {
    {ETHERTYPE_IP, "IP"},
    {ETHERTYPE_IPV6, "IP6"},
    {ETHERTYPE_ARP, "ARP"},
    {ETHERTYPE_REVARP, "RARP"},
    {ETHERTYPE_LOOPBACK, "Loopback"},
};

lsap_t lsaps[] = {
    {LSAP_NULL, "NULL"},
    {LSAP_ISIS, "IS-IS"},
    {LSAP_SNAP, "SNAP"},
};

struct name_value_pair_t
get_name_value_pair(u_short type, struct name_value_pair_t *name_value_pairs,
                    size_t len) {
  u_short big_endian_value = htons(type);

  for (int i = 0; i < len; i++) {
    if (name_value_pairs[i].value == big_endian_value) {
      return name_value_pairs[i];
    }
  }

  return (struct name_value_pair_t){big_endian_value, "UNKNOWN"};
}

u_short print_ethernet_header(const struct ether_header *ethernet,
                              bpf_u_int32 len, enum verbosity_level verbosity) {
  struct name_value_pair_t name_value_pair = {0, NULL};
  bool is_802_3 = htons(ethernet->ether_type) <= ETH_FRAME_TYPE_THRESHOLD;

  if (!is_802_3) {
    /* https://en.wikipedia.org/wiki/EtherType */
    size_t ether_types_len = sizeof(ether_types) / sizeof(ether_types[0]);
    name_value_pair = get_name_value_pair(
        ethernet->ether_type, (struct name_value_pair_t *)ether_types,
        ether_types_len);
  } else {
    size_t lsaps_len = sizeof(lsaps) / sizeof(lsaps[0]);
    /* Explaining the pointer logic, we're looking at the memory right after the
     * traditional EtherType field which here actually contains a length since
     * it's IEEE 802.3, we could have defined a struct to make it more obvious
     * but since it's the only time we're doing something like that...
     */
    name_value_pair =
        get_name_value_pair(*(u_short *)(ethernet + 1),
                            (struct name_value_pair_t *)lsaps, lsaps_len);
  }

  if (verbosity == HIGH) {
    printf(" %s >",
           ether_ntoa((const struct ether_addr *)&ethernet->ether_shost));
    printf(" %s,",
           ether_ntoa((const struct ether_addr *)&ethernet->ether_dhost));
    printf(" %s", !is_802_3 ? "ethertype" : "IEEE 802.3,");
    printf("%s", name_value_pair.value == LSAP_ISIS ? " OSI" : "");
  }

  printf(" %s", name_value_pair.name);
  if (verbosity == HIGH)
    printf("%s (0x%04x), length %d",
           name_value_pair.value == ETHERTYPE_IP ? "v4" : "",
           name_value_pair.value, len);

  return name_value_pair.value;
}

/* Even though we only obverse Ethernet ARP frames,
 * https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml */
arp_hardware_t arp_hardwares[] = {
    {ARPHRD_ETHER, "Ethernet"},
    {ARPHRD_IEEE802, "Token-Ring"},
    {ARPHRD_FRELAY, "Frame Relay"},
    {ARPHRD_IEEE1394, "IEEE1394"},
    {ARPHRD_IEEE1394_EUI64, "IEEE1394 EUI-64"},
};

arp_protocol_t *arp_protocols = (arp_protocol_t *)ether_types;

void print_arp_header(const struct arphdr *arp) {
  /* Print hardware related data */
  size_t arp_hardwares_len = sizeof(arp_hardwares) / sizeof(arp_hardwares[0]);
  arp_hardware_t arp_hardware = get_name_value_pair(
      arp->ar_hrd, (struct name_value_pair_t *)arp_hardwares,
      arp_hardwares_len);

  printf(", %s (len %u)", arp_hardware.name, arp->ar_hln);

  /* Print protocol related data
   * Since we defined the protocols to be the same as the EtherTypes, we can
   * define the len of the protocols table to be the same as the ether_types
   * table, allows us to circumvent the fact that it is a pointer */
  size_t arp_protocols_len = sizeof(ether_types) / sizeof(ether_types[0]);
  arp_protocol_t arp_protocol = get_name_value_pair(
      arp->ar_pro, (struct name_value_pair_t *)arp_protocols,
      arp_protocols_len);

  printf(", %s%s (len %u)", arp_protocol.name,
         arp_protocol.value == ETHERTYPE_IP ? "v4" : "", arp->ar_pln);
}

/* https://people.computing.clemson.edu/~westall/853/notes/arprecv.pdf */
void print_arp_frame(const struct arphdr *arp, enum verbosity_level verbosity) {
  u_short arp_operation = ntohs(arp->ar_op);

  if (verbosity >= MEDIUM)
    print_arp_header(arp);

  /* Retrieve the ARP payload thanks to the information in the header */
  u_char *ar_sha = (u_char *)(arp + 1);  /* sender hardware address */
  u_char *ar_spa = ar_sha + arp->ar_hln; /* sender protocol address */
  u_char *ar_tha = ar_spa + arp->ar_pln; /* target hardware address */
  u_char *ar_tpa = ar_tha + arp->ar_hln; /* target protocol address */

  /* Handle gratuitous ARP differently */
  bool is_gratuitous =
      memcmp(ar_spa, ar_tpa, arp->ar_pln) == 0 &&
      (arp_operation == ARPOP_REPLY || arp_operation == ARPOP_REQUEST);
  if (is_gratuitous && verbosity == LOW) {
    printf(", Announcement %s", arp_operation == ARPOP_REQUEST
                                    ? inet_ntoa(*(struct in_addr *)ar_spa)
                                    : inet_ntoa(*(struct in_addr *)ar_tpa));
    return;
  }

  /* Handle ARP requests and replies including RARP */
  // TODO:
  // https://stackoverflow.com/questions/4736718/mac-addresspad-missing-left-zeros
  // What's oui Unknown? Maybe set a struct to support the most common oui
  // https://www.secureideas.com/blog/of-mac-addresses-and-oui-a-subtle-but-useful-recon-resource
  switch (arp_operation) {
  case ARPOP_REQUEST:
    printf(", %s", is_gratuitous ? "Announcement" : "Request");
    printf(" who-has %s", inet_ntoa(*(struct in_addr *)ar_tpa));
    printf(" tell %s", inet_ntoa(*(struct in_addr *)ar_spa));
    break;
  case ARPOP_REPLY:
    printf(", %s", is_gratuitous ? "Announcement" : "Reply");
    printf(" %s", inet_ntoa(*(struct in_addr *)ar_spa));
    printf(" is-at %s (oui Unknown)",
           ether_ntoa((const struct ether_addr *)ar_sha));
    break;
  case ARPOP_REVREQUEST:
    printf(", Reverse Request who-is %s (oui Unknown)",
           ether_ntoa((const struct ether_addr *)ar_sha));
    printf(" tell %s (oui Unknown)",
           ether_ntoa((const struct ether_addr *)ar_tha));
    break;
  case ARPOP_REVREPLY:
    printf(", Reverse Reply %s", ether_ntoa((const struct ether_addr *)ar_tha));
    printf(" is-at %s (oui Unknown)",
           ether_ntoa((const struct ether_addr *)ar_sha));
    break;
  default:
    /* https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml */
    printf(", Unsupported ARP operation (0x%04X)", arp_operation);
  }
}

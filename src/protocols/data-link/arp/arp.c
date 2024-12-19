#include "../../../capture/capture_utils.h"
#include "../../../utils/utils.h"
#include "../ethernet/ethernet.h"
#include "arp.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __linux__
#include <netinet/ether.h>
#endif

extern enum verbosity_level verbosity;
extern ether_type_t ether_types[];
extern const size_t ETHERTYPES_LEN;

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
      htons(arp->ar_hrd), (struct name_value_pair_t *)arp_hardwares,
      arp_hardwares_len);

  printf(", %s (len %u)", arp_hardware.name, arp->ar_hln);

  /* Print protocol related data
   * Since we defined the protocols to be the same as the EtherTypes, we can
   * define the len of the protocols table to be the same as the ether_types
   * table, allows us to circumvent the fact that it is a pointer */
  size_t arp_protocols_len = ETHERTYPES_LEN;
  arp_protocol_t arp_protocol = get_name_value_pair(
      arp->ar_pro, (struct name_value_pair_t *)arp_protocols,
      arp_protocols_len);

  printf(", %s%s (len %u)", arp_protocol.name,
         arp_protocol.value == ETHERTYPE_IP ? "v4" : "", arp->ar_pln);
}

/* https://people.computing.clemson.edu/~westall/853/notes/arprecv.pdf */
void print_arp_frame(const struct arphdr *arp) {
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
  /* FIXME: inet_ntoa deprecated, replace occurrences with ntop */
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

#include "../../../capture/capture_utils.h"
#include "../../../utils/utils.h"
#include "../ethernet/ethernet.h"
#include "linux-cooked-capture.h"
#include <stdint.h>
#include <stdio.h>

extern enum verbosity_level verbosity;
extern ether_type_t ether_types[];
extern const size_t ETHERTYPES_LEN;

uint16_t print_linux_cooked_header(const struct sll_header *sll) {
  uint16_t halen = htons(sll->sll_halen);

  switch (halen) {
  case ARPHRD_IEEE80211_RADIOTAP:
  case ARPHRD_IPGRE:
  case ARPHRD_FRAD:
  case ARPHRD_NETLINK:
    printf(" Unsupported ARPHRD_ type (%d)", halen);
    return 0;
  }

  struct name_value_pair_t name_value_pair = get_name_value_pair(
      htons(sll->sll_protocol), (struct name_value_pair_t *)ether_types,
      ETHERTYPES_LEN);

  printf(" %s", name_value_pair.name);
  if (verbosity == HIGH)
    printf(" (%d)", sll->sll_protocol);

  return name_value_pair.value;
}

uint16_t print_linux_cooked_2_header(const struct sll2_header *sll2) {
  uint16_t halen = htons(sll2->sll2_halen);

  switch (halen) {
  case ARPHRD_IEEE80211_RADIOTAP:
  case ARPHRD_IPGRE:
  case ARPHRD_FRAD:
  case ARPHRD_NETLINK:
    printf(" Unsupported ARPHRD_ type (%d)", halen);
    return 0;
  }

  if (verbosity >= MEDIUM) {
    printf(" (if_index %d", htonl(sll2->sll2_if_index));
    printf(", halen %d", halen);
    printf(", packet_type %d", sll2->sll2_pkttype);

    if (verbosity == HIGH)
      print_ssl_packet_type(sll2->sll2_pkttype);
    printf(")");

    /* TODO: Link-layer address len and the address itself */
  }

  struct name_value_pair_t name_value_pair = get_name_value_pair(
      htons(sll2->sll2_protocol), (struct name_value_pair_t *)ether_types,
      ETHERTYPES_LEN);

  printf(" %s", name_value_pair.name);
  if (verbosity == HIGH)
    printf(" (%d)", sll2->sll2_protocol);

  return name_value_pair.value;
}

void print_ssl_packet_type(uint8_t packet_type) {
  printf(" [");
  switch (packet_type) {
  case PACKET_TYPE_DIRECTED:
    printf("to us");
    break;
  case PACKET_TYPE_BROADCAST:
    printf("broadcast");
    break;
  case PACKET_TYPE_MULTICAST:
    printf("multicast");
    break;
  case PACKET_TYPE_OTHER_TO_OTHER:
    printf("other to other");
    break;
  case PACKET_TYPE_OWN:
    printf("by us");
    break;
  }
  printf("]");
}

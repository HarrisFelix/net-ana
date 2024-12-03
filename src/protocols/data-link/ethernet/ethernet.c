#include "../../../capture/capture_utils.h"
#include "../../../utils/utils.h"
#include "ethernet.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

extern enum verbosity_level verbosity;

ether_type_t ether_types[] = {
    {ETHERTYPE_IP, "IPv4"},           {ETHERTYPE_IPV6, "IPv6"},
    {ETHERTYPE_ARP, "ARP"},           {ETHERTYPE_REVARP, "RARP"},
    {ETHERTYPE_LOOPBACK, "Loopback"}, {ETHERTYPE_DECMOP, "DEC MOP RC"},
};

const size_t ETHERTYPES_LEN = (sizeof(ether_types) / sizeof(ether_types[0]));

lsap_t lsaps[] = {
    {LSAP_NULL, "NULL"},
    {LSAP_ISIS, "IS-IS"},
    {LSAP_SNAP, "SNAP"},
};

const size_t LSAPS_LEN = (sizeof(lsaps) / sizeof(lsaps[0]));

uint16_t print_ethernet_header(const struct ether_header *ethernet,
                               bpf_u_int32 len) {
  struct name_value_pair_t name_value_pair = {0, NULL};
  bool is_802_3 = htons(ethernet->ether_type) <= ETH_FRAME_TYPE_THRESHOLD;

  if (!is_802_3) {
    /* https://en.wikipedia.org/wiki/EtherType */
    name_value_pair = get_name_value_pair(
        htons(ethernet->ether_type), (struct name_value_pair_t *)ether_types,
        ETHERTYPES_LEN);
  } else {
    /* Explaining the pointer logic, we're looking at the memory right after the
     * traditional EtherType field which here actually contains a length since
     * it's IEEE 802.3, we could have defined a struct to make it more obvious
     * but since it's the only time we're doing something like that...
     */
    name_value_pair =
        get_name_value_pair(*(uint16_t *)(ethernet + 1),
                            (struct name_value_pair_t *)lsaps, LSAPS_LEN);
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
    printf(" (0x%04x), length %d", name_value_pair.value, len);

  return name_value_pair.value;
}

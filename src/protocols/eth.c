#include "eth.h"
#include <stdio.h>

ether_types_t ether_types[] = {
    {ETHERTYPE_IP, "IP"},
    {ETHERTYPE_IPV6, "IP6"},
    {ETHERTYPE_ARP, "ARP"},
    {ETHERTYPE_REVARP, "RARP"},
    {ETHERTYPE_LOOPBACK, "Loopback"},
    {ETHERTYPE_LINKLOCAL, "Link-local"},
};

ether_types_t get_ether_type(u_short ether_value) {
  size_t ether_types_len = sizeof(ether_types) / sizeof(ether_types[0]);
  u_short big_endian_ether_value = htons(ether_value);

  for (int i = 0; i < ether_types_len; i++) {
    if (ether_types[i].ether_value == big_endian_ether_value) {
      return ether_types[i];
    }
  }

  // HACK: Print unsupported ether values.
  printf("0x%04X:", big_endian_ether_value);

  return (ether_types_t){big_endian_ether_value, "UNKNOWN"};
}

u_short print_ethernet_header(const struct ether_header *ethernet,
                              enum verbosity_level verbosity) {
  ether_types_t ether_type = get_ether_type(ethernet->ether_type);
  printf("%s ", ether_type.name);

  if (verbosity == HIGH) {
    printf("(%s -> ",
           ether_ntoa((const struct ether_addr *)&ethernet->ether_shost));
    printf("%s) ",
           ether_ntoa((const struct ether_addr *)&ethernet->ether_dhost));
  }

  return ether_type.ether_value;
}

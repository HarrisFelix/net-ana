#include "../../../capture/capture_utils.h"
#include "loopback.h"
#include <stdint.h>
#include <stdio.h>

extern enum verbosity_level verbosity;

bsd_lo_protocol_t bsd_lo_protocols[] = {
    {LOOPBACK_IP, "IPv4"},    {LOOPBACK_IP6_1, "IPv6"},
    {LOOPBACK_IP6_2, "IPv6"}, {LOOPBACK_IP6_3, "IPv6"},
    {LOOPBACK_OSI, "OSI"},    {LOOPBACK_IPX, "IPX"},
};

uint16_t print_loopback_header(const struct bsd_loopback_hdr *lo) {
  size_t lo_p_len = sizeof(bsd_lo_protocols) / sizeof(bsd_lo_protocols[0]);
  struct name_value_pair_t name_value_pair = get_name_value_pair(
      lo->protocol_type, (struct name_value_pair_t *)bsd_lo_protocols,
      lo_p_len);

  printf(" %s", name_value_pair.name);
  if (verbosity == HIGH)
    printf(" (%d)", lo->protocol_type);

  return name_value_pair.value;
}

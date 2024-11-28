#include "../../../capture/capture_utils.h"
#include "udp.h"

void print_udp_frame(const struct udphdr *udp, bool is_ipv6) {
  printf(": UDP");

  if (verbosity <= LOW)
    return;

  // struct ports ports = get_ports(udp, IPPROTO_UDP);
  // printf(", %d > %d", ports.source, ports.destination);
}

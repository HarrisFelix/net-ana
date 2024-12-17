#include "../../../capture/capture_utils.h"
#include "../../../capture/packet_utils.h"
#include "icmp.h"
#include <stdbool.h>
#include <stdio.h>

extern enum verbosity_level verbosity;

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
           validate_checksum(NULL, false, icmp, htons(len)) ? "incorrect"
                                                            : "correct");
}

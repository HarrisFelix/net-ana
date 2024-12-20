#include "../../../capture/capture_utils.h"
#include "../../../capture/packet_utils.h"
#include "../dhcp/dhcp.h"
#include "bootp.h"
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>

#ifdef __linux__
#include <netinet/ether.h>
#endif

extern enum verbosity_level verbosity;
extern int payload_length;

void print_bootp_frame(const struct bootp *bootp) {
  print_protocol_spacing();
  printf("BOOTP");

  if (verbosity <= LOW && is_dhcp(bootp)) {
    printf("/DHCP");
  }

  switch (bootp->bp_op) {
  case BOOTREQUEST:
    printf(", request");

    if (verbosity <= LOW)
      return;

    printf(" from %s (oui %s)",
           ether_ntoa((const struct ether_addr *)bootp->bp_chaddr),
           get_oui(bootp->bp_chaddr));
    break;
  case BOOTREPLY:
    printf(", reply");
    break;
  default:
    printf(", invalid operation (%d)", bootp->bp_op);
  }

  if (verbosity <= LOW)
    return;

  printf(", htype %d", bootp->bp_htype);
  printf(", hlen %d", bootp->bp_hlen);
  printf(", hops %d", bootp->bp_hops);
  printf(", xid %u", htonl(bootp->bp_xid));
  printf(", secs %d", htons(bootp->bp_secs));

  if (verbosity == MEDIUM) {
    if (strcmp(inet_ntoa(bootp->bp_ciaddr), "0.0.0.0") != 0) {
      printf(", ciaddr %s", inet_ntoa(bootp->bp_ciaddr));
    }
    if (strcmp(inet_ntoa(bootp->bp_yiaddr), "0.0.0.0") != 0) {
      printf(", yiaddr %s", inet_ntoa(bootp->bp_yiaddr));
    }
    if (strcmp(inet_ntoa(bootp->bp_siaddr), "0.0.0.0") != 0) {
      printf(", siaddr %s", inet_ntoa(bootp->bp_siaddr));
    }
    if (strcmp(inet_ntoa(bootp->bp_giaddr), "0.0.0.0") != 0) {
      printf(", giaddr %s", inet_ntoa(bootp->bp_giaddr));
    }
  }

  if (verbosity == HIGH) {
    printf(", ciaddr %s", inet_ntoa(bootp->bp_ciaddr));
    printf(", yiaddr %s", inet_ntoa(bootp->bp_yiaddr));
    printf(", siaddr %s", inet_ntoa(bootp->bp_siaddr));
    printf(", giaddr %s", inet_ntoa(bootp->bp_giaddr));
    printf(", chaaddr %s",
           ether_ntoa((const struct ether_addr *)bootp->bp_chaddr));
    printf(", sname %s", strlen((char *)bootp->bp_sname) >= 1
                             ? bootp->bp_sname
                             : (unsigned char *)"empty");
    printf(", file %s", strlen((char *)bootp->bp_file) >= 1
                            ? bootp->bp_file
                            : (unsigned char *)"empty");
  }

  struct vend *vendor = (struct vend *)bootp->bp_vend;

  printf(", vend 0x");
  for (size_t i = 0; i < 4; i++)
    printf("%02x", vendor->v_magic[i]);

  if (is_dhcp(bootp)) {
    payload_length = sizeof(struct vend) - 4;
    print_dhcp_frame(bootp->bp_vend + 4);
  }
}

bool is_dhcp(const struct bootp *bootp) {
  unsigned char magic_cookie[4] = DHCP_MAGIC_COOKIE;

  return memcmp(bootp->bp_vend, magic_cookie, 4) == 0 &&
         bootp->bp_vend[4] == 0x35;
}

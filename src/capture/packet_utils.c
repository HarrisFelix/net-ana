#include "packet_utils.h"
#include <ctype.h>

/* https://stackoverflow.com/questions/2408976/struct-timeval-to-printable-format
 */
void print_timestamp(const struct pcap_pkthdr *header) {
  time_t nowtime;
  struct tm *nowtm;
  char tmbuf[64], buf[64];

  nowtime = header->ts.tv_sec;
  nowtm = localtime(&nowtime);
  strftime(tmbuf, sizeof tmbuf, "%H:%M:%S", nowtm);
  snprintf(buf, sizeof buf, "%s.%06d", tmbuf, header->ts.tv_usec);
  printf("[%s]", buf);
}

void print_packet_bytes(const u_char *packet, uint len) {
  for (uint i = 0; i < len; i++) {
    /* HEX */
    if (i % 16 == 0)
      printf("\n\t0x%04x: ", i);
    if (i % 2 == 0)
      printf(" %02x", packet[i]);
    else
      printf("%02x", packet[i]);

    /* ASCII */
    if ((i + 1) % 16 == 0 || i == len - 1) {
      /* Some explanation, a typical HEX block would be " 0000" and would be
       * comprised of 2 bytes, so each byte occupy half the length of that,
       * which is 2.5 We multiply the length occupied by a byte by the number of
       * bytes left we need to fill row */
      int padding = ((16 - ((i + 1) % 16)) % 16) * 2.5;
      printf(" %*s ", padding, "");

      /* Replace the cursor at the start of the line */
      for (uint j = i - (i % 16); j <= i; j++) {
        if (isprint(packet[j]))
          printf("%c", packet[j]);
        else
          printf(".");
      }
    }
  }
}

/* https://datatracker.ietf.org/doc/html/rfc1071
 * Little endian implementation of a checksum */
uint16_t validate_checksum(const void *pseudo_header, const void *packet,
                           uint num_32bit_words) {
  uint32_t sum = 0;

  /* If there's a pseudo IPv6 header, sum it
   * Its length is always 10 32-bit words */
  if (pseudo_header) {
    for (uint i = 0; i < 20; i++) {
      sum += htons(((uint16_t *)pseudo_header)[i]);
    }
  }

  /* We multiply it by two to get the number of 16-bit words */
  for (uint i = 0; i < num_32bit_words * 2; i++) {
    sum += htons(((uint16_t *)packet)[i]);
  }

  /* Bit manipiulation to add the carry and not consider it in the complement */
  return (uint16_t)~(sum + (sum >> 16) & 0xffff);
}

#include "../../../capture/capture.h"
#include "../../../capture/packet_utils.h"
#include "imap.h"
#include <stdio.h>

extern int payload_length;
extern enum verbosity_level verbosity;

void print_imap_frame(const char *imap) {
  printf(": IMAP");

  if (verbosity >= MEDIUM && payload_length) {
    printf(", length %d", payload_length);

    print_clear_text(imap);

    payload_length = LET_ENCAPSULATED_PROTOCOL_PRINT_PAYLOAD_LENGTH;
  }
}

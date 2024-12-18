#include "../../../capture/capture.h"
#include "../../../capture/packet_utils.h"
#include "smtp.h"
#include <stdio.h>

extern int payload_length;
extern enum verbosity_level verbosity;

void print_smtp_frame(const char *smtp) {
  printf(": SMTP");

  if (verbosity >= MEDIUM && payload_length) {
    printf(", length %d", payload_length);

    print_clear_text(smtp);

    payload_length = LET_ENCAPSULATED_PROTOCOL_PRINT_PAYLOAD_LENGTH;
  }
}

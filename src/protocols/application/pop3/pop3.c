#include "../../../capture/capture.h"
#include "../../../capture/packet_utils.h"
#include "pop3.h"
#include <stdio.h>

extern int payload_length;
extern enum verbosity_level verbosity;

void print_pop3_frame(const char *pop3) {
  printf(": POP3");

  if (verbosity >= MEDIUM && payload_length) {
    printf(", length %d", payload_length);

    print_clear_text(pop3);

    payload_length = LET_ENCAPSULATED_PROTOCOL_PRINT_PAYLOAD_LENGTH;
  }
}

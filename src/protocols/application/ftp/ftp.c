#include "../../../capture/capture.h"
#include "../../../capture/packet_utils.h"
#include "ftp.h"
#include <stdio.h>

extern int payload_length;
extern enum verbosity_level verbosity;

void print_ftp_frame(const char *ftp) {
  printf(": FTP");

  if (verbosity >= MEDIUM && payload_length) {
    printf(", length %d", payload_length);

    print_clear_text(ftp);

    payload_length = LET_ENCAPSULATED_PROTOCOL_PRINT_PAYLOAD_LENGTH;
  }
}

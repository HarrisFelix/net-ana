#include "../../../capture/capture.h"
#include "../../../capture/packet_utils.h"
#include "http.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>

extern int payload_length;
extern enum verbosity_level verbosity;

void print_http_frame(const char *http, bool is_http_alt) {
  print_protocol_spacing();
  printf("HTTP");

  if (is_http_alt)
    printf(" (alternative)");

  if (verbosity <= LOW) {
    if (http[0] == 'G')
      printf("/GET");
    else if (http[0] == 'P')
      printf("/POST");
  }

  if (verbosity >= MEDIUM && payload_length) {
    printf(", length %d", payload_length);

    print_clear_text(http);

    payload_length = LET_ENCAPSULATED_PROTOCOL_PRINT_PAYLOAD_LENGTH;
  }
}

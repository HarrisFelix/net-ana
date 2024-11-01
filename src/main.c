#include "capture/capture.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char const *program_name;

void usage() {
  printf(
      "Usage: %s [ -i interface ] [ -o file ] [ -f filter ] [ -v verbosity ]\n",
      program_name);
}

int main(int argc, char **argv) {
  program_name = argv[0];

  char *interface = NULL;
  char *file = NULL;
  char *filter = NULL;
  int verbosity = 1;
  bool supplied_verbosity = false;

  int index;
  int c;
  while ((c = getopt(argc, argv, "i:o:f:v:")) != -1) {
    switch (c) {
    case 'i':
      interface = optarg;
      break;
    case 'o':
      file = optarg;
      break;
    case 'f':
      filter = optarg;
      break;
    case 'v':
      verbosity = atoi(optarg);
      supplied_verbosity = true;
      break;
    case '?':
      usage();
      return EXIT_FAILURE;
    default:
      abort();
      break;
    }
  }

  /* Doesn't allow the verbosity to be set outside range, but if it wasn't
   * supplied set it to 0 for a minimal output, equivalent to tcpdump -q */
  if (verbosity < 1 || verbosity > 3) {
    fputs("-v must be set between 1 and 3.\n", stderr);
    return EXIT_FAILURE;
  } else if (!supplied_verbosity) {
    verbosity = 0;
  }

  for (index = optind; index < argc; index++) {
    fprintf(stderr, "%s: unrecognized argument %s\n", program_name,
            argv[index]);
    usage();
    return EXIT_FAILURE;
  }

  if (interface && file) {
    printf("%s: defaulting to file analyzer because both arguments were "
           "provided\n",
           program_name);

    interface = NULL;
  }

  capture_loop(interface, file, filter, (u_int)verbosity);

  return EXIT_SUCCESS;
}

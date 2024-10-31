#include "capture.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void usage(char *program_name) {
  printf(
      "Usage: %s [ -i interface ] [ -o file ] [ -f filter ] [ -v verbosity ]\n",
      program_name);
}

int main(int argc, char **argv) {
  int c;

  char *interface = NULL;
  char *file = NULL;
  char *filter = NULL;
  int verbosity = 1;
  bool supplied_verbosity = false;

  int index;

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
      if (optopt == 'i' || optopt == 'f' || optopt == 'v')
        fprintf(stderr, "%s: option -%c requires an argument.\n", argv[0],
                optopt);
      else if (isprint(optopt))
        fprintf(stderr, "%s: unrecognized option `-%c'.\n", argv[0], optopt);
      else
        fprintf(stderr, "%s: unknown option character `\\x%x'.\n", argv[0],
                optopt);

      usage(argv[0]);
      return EXIT_FAILURE;
    default:
      abort();
      break;
    }
  }

  if (verbosity < 1 || verbosity > 3) {
    fputs("-v must be set between 1 and 3.\n", stderr);
    return EXIT_FAILURE;
  }

  for (index = optind; index < argc; index++) {
    fprintf(stderr, "%s: unrecognized argument %s\n", argv[0], argv[index]);
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  if (interface && file) {
    printf("%s: defaulting to file analyzer because both arguments were "
           "provided\n",
           argv[0]);

    interface = NULL;
  }

  capture_loop(argv[0], interface, file, filter, (u_int)verbosity,
               supplied_verbosity);

  return EXIT_SUCCESS;
}

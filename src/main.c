#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include "capture.h"

int main(int argc, char **argv) {
    int c;

    char *interface = NULL;
    char *file = NULL;
    char *filter = NULL;
    int verbosity = 0;

    int index;
    
    while ((c = getopt (argc, argv, "i:o:f:v:")) != -1) {
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
                break;
            case '?':
                if (optopt == 'i' || optopt == 'f' || optopt == 'v')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr,
                        "Unknown option character `\\x%x'.\n",
                        optopt);
                
                return EXIT_FAILURE;
            default:
                abort();
                break;
        }
    }
    
    if (!(interface || file) || (interface && file)) {
        fprintf(stderr, "Needs to define exactly either option -i or -f.\n");
        exit(EXIT_FAILURE);
    }

    if (verbosity < 1 || verbosity > 3) {
        fprintf(stderr, "Verbosity must be between 1 and 3 included.\n");
        exit(EXIT_FAILURE);
    }

    for (index = optind; index < argc; index++) {
        printf ("Non-option argument %s\n", argv[index]);
        return EXIT_FAILURE;
    }

    capture_loop(argv[0], interface, file, filter, verbosity);

    return EXIT_SUCCESS;
}
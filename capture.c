#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include "utils.h"
#include "capture.h"

pcap_t *handle;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    /* Define packet handling related structures. */
    struct pcap_handler_args *packet_args = (struct pcap_handler_args *) args;
    const struct ether_header *ethernet;
    const struct ip *ip;

    /* Cast ethernet and ip frame. */
    int size_ethernet = sizeof(struct ether_header);
    ethernet = (struct ether_header*)(packet);
    ip = (struct ip*)(packet + size_ethernet);

    print_timestamp(header);

    /* https://en.wikipedia.org/wiki/EtherType */

    printf("\n");
}

void capture_loop(char *program_name, char *interface, char* file, char *filter, int verbosity) {
    char errbuf[PCAP_ERRBUF_SIZE];
    int data_link = 0;
    struct pcap_handler_args args = { verbosity };

    if (interface) {
        handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
        if (!handle) {
            fprintf(stderr, "%s\n", errbuf);

            /* Check if the error message corresponds to the PCAP_ERROR_NO_SUCH_DEVICE message. */
            if (!strncmp(pcap_statustostr(PCAP_ERROR_NO_SUCH_DEVICE), errbuf + sizeof(interface) - 2, 21))
                print_devices();
            
            exit(EXIT_FAILURE);
        }

        signal(SIGINT, print_live_capture_summary);
    } else {
        handle = pcap_open_offline(file, errbuf);

        if (!handle) {
            fprintf(stderr, "%s\n", errbuf);
            exit(EXIT_FAILURE);
        }
    }

    data_link = pcap_datalink(handle);
    printf("%s: data link type %s (%s)\n", program_name, pcap_datalink_val_to_name(data_link), pcap_datalink_val_to_description(data_link));

    pcap_loop(handle, 0, got_packet, (u_char *) &args);

    pcap_close(handle);
}
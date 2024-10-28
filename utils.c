#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include "utils.h"
#include <time.h>
#include <string.h>

extern pcap_t *handle;

void print_live_capture_summary() {
    int stats_err = 0;
    struct pcap_stat packet_stats;

    pcap_breakloop(handle);

    stats_err = pcap_stats(handle, &packet_stats);
    if (stats_err == PCAP_ERROR || stats_err == PCAP_ERROR_NOT_ACTIVATED) {
        fprintf(stderr, "%s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    printf("\n\n%d packet%c captured.\n", packet_stats.ps_recv, packet_stats.ps_recv != 1 ? 's' : 0);
    printf("%d packet%c dropped by kernel.\n", packet_stats.ps_drop, packet_stats.ps_drop != 1 ? 's' : 0);
    printf("%d packet%c dropped by device.\n", packet_stats.ps_ifdrop, packet_stats.ps_ifdrop != 1 ? 's' : 0);
}

void print_devices() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    int i = 0;
    
    if(pcap_findalldevs(&interfaces, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Couldn't list interfaces.\n");
    }

    printf("Available interfaces:\n");
    for(; interfaces; interfaces = interfaces->next)
        printf("%d: %s\n", i++, interfaces->name);
}

/* https://stackoverflow.com/questions/2408976/struct-timeval-to-printable-format */
void print_timestamp(const struct pcap_pkthdr *header) {
    time_t nowtime;
    struct tm *nowtm;
    char tmbuf[64], buf[64];

    nowtime = header->ts.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof tmbuf, "%H:%M:%S", nowtm);
    snprintf(buf, sizeof buf, "%s.%06d", tmbuf, header->ts.tv_usec);
    printf("%s ", buf);
}

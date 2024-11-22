// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_DATA_LINK_H_
#define SRC_PROTOCOLS_DATA_LINK_H_

#include "../capture/capture_utils.h"
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <pcap/pcap.h>

/* If the value is higher than 0x0600, it is an EtherType (Ethernet II),
 * otherwise it is a length corresponding to a IEEE 802.3 Frame
 * https://ipcisco.com/lesson/ethernet-basics/ */
#define ETH_FRAME_TYPE_THRESHOLD 0x0600

/* Technically we should apply a mask to look only a the first 7 higher bits to
 * be semantical, and FEFE only corresponds to OSI which could be other
 * protocols such as ES-IS and not directly IS-IS, but I chose to remain simple
 * and assume we're only receive IS-IS OSI frames */
#define LSAP_ISIS 0xFEFE
#define LSAP_SNAP 0xAAAA
#define LSAP_NULL 0x0000

/* Loopback protocols can have multiple values that are equivalent to a single
 * EtherType */
#define LOOPBACK_IP 2
#define LOOPBACK_IP6_1 24
#define LOOPBACK_IP6_2 28
#define LOOPBACK_IP6_3 30
#define LOOPBACK_OSI 7
#define LOOPBACK_IPX 23

struct name_value_pair_t {
  u_short value;
  const char *name;
};

/* Associates an EtherType with its corresponding name, keeping semantical
 * meaning */
typedef struct name_value_pair_t ether_type_t;
extern ether_type_t ether_types[];

/* https://en.wikipedia.org/wiki/IEEE_802.2#LSAP_values */
typedef struct name_value_pair_t lsap_t;
extern lsap_t lsaps[];

/* https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html */
struct bsd_loopback_hdr {
  u_int32_t protocol_type;
};

typedef struct name_value_pair_t bsd_lo_protocol_t;
extern bsd_lo_protocol_t bsd_lo_protocols[];

/* Allows us to keep semantical meaning even if the structs are identical */
typedef struct name_value_pair_t arp_hardware_t;
extern arp_hardware_t arp_hardwares[];

/* https://en.wikipedia.org/wiki/Address_Resolution_Protocol
 *
 * The protocol type of ARP shares a numbering space with the ones for the
 * EtherType, so we are gonna transparently point to the ether_types table while
 * remaining semantical by redefining the stucts */
typedef ether_type_t arp_protocol_t;
extern arp_protocol_t *arp_protocols;

ether_type_t get_ether_type_name(u_short ether_value);
u_short print_ethernet_header(const struct ether_header *ethernet,
                              bpf_u_int32 len, enum verbosity_level verbosity);
u_short print_loopback_header(const struct bsd_loopback_hdr *lo,
                              enum verbosity_level verbosity);
void print_arp_header(const struct arphdr *arp);
void print_arp_frame(const struct arphdr *arp, enum verbosity_level verbosity);

#endif  // SRC_PROTOCOLS_DATA_LINK_H_

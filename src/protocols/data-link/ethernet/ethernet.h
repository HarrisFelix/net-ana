// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_DATA_LINK_ETHERNET_ETHERNET_H_
#define SRC_PROTOCOLS_DATA_LINK_ETHERNET_ETHERNET_H_

#include "../../../utils/utils.h"
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdint.h>

/* If the value is higher than 0x0600, it is an EtherType (Ethernet II),
 * otherwise it is a length corresponding to a IEEE 802.3 Frame
 * https://ipcisco.com/lesson/ethernet-basics/ */
#define ETH_FRAME_TYPE_THRESHOLD 0x0600

/* https://en.wikipedia.org/wiki/EtherType */
#define ETHERTYPE_DECMOP 0x6002

/* Technically we should apply a mask to look only a the first 7 higher bits to
 * be semantical, and FEFE only corresponds to OSI which could be other
 * protocols such as ES-IS and not directly IS-IS, but I chose to remain simple
 * and assume we're only receive IS-IS OSI frames */
#define LSAP_ISIS 0xFEFE
#define LSAP_SNAP 0xAAAA
#define LSAP_NULL 0x0000

/* Associates an EtherType with its corresponding name, keeping semantical
 * meaning */
typedef struct name_value_pair_t ether_type_t;
extern ether_type_t ether_types[];

/* https://en.wikipedia.org/wiki/IEEE_802.2#LSAP_values */
typedef struct name_value_pair_t lsap_t;
extern lsap_t lsaps[];

ether_type_t get_ether_type_name(u_short ether_value);
uint16_t print_ethernet_header(const struct ether_header *ethernet,
                               bpf_u_int32 len);

#endif  // SRC_PROTOCOLS_DATA_LINK_ETHERNET_ETHERNET_H_

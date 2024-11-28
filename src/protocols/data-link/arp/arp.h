// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_DATA_LINK_ARP_ARP_H_
#define SRC_PROTOCOLS_DATA_LINK_ARP_ARP_H_

#include "../../../utils/utils.h"
#include "../ethernet/ethernet.h"
#include <net/if_arp.h>

#ifdef __linux__
#define ARPHRD_FRELAY ARPHRD_DLCI
#define ARPHRD_IEEE1394_EUI64 ARPHRD_IEEE1394
#define ARPOP_REVREQUEST                                                       \
  ARPOP_RREQUEST /* request protocol address given hardware */
#define ARPOP_REVREPLY ARPOP_RREPLY      /* response giving protocol address */
#define ARPOP_INVREQUEST ARPOP_InREQUEST /* request to identify peer */
#define ARPOP_INVREPLY ARPOP_InREPLY     /* response identifying peer */
#endif

/* Allows us to keep semantical meaning even if the structs are identical
 * We support many types even though we only obverse Ethernet ARP frames,
 * https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml */
typedef struct name_value_pair_t arp_hardware_t;
extern arp_hardware_t arp_hardwares[];

/* https://en.wikipedia.org/wiki/Address_Resolution_Protocol
 *
 * The protocol type of ARP shares a numbering space with the ones for the
 * EtherType, so we are gonna transparently point to the ether_types table while
 * remaining semantical by redefining the stucts */
typedef ether_type_t arp_protocol_t;
extern arp_protocol_t *arp_protocols;

void print_arp_header(const struct arphdr *arp);
void print_arp_frame(const struct arphdr *arp);

#endif  // SRC_PROTOCOLS_DATA_LINK_ARP_ARP_H_

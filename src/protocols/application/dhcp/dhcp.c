#include "../../../capture/capture_utils.h"
#include "dhcp.h"
#include <stdio.h>

extern int payload_length;
extern enum verbosity_level verbosity;

void print_dhcp_frame(const unsigned char *dhcp) {
  print_protocol_spacing();
  printf("DHCP");

  const unsigned char *end = dhcp + payload_length;

  for (unsigned char *option = (unsigned char *)dhcp; option < end; option++) {
    if (*option == DHCP_OPTION_END) {
      break;
    }

    int length = *(option + 1);
    print_dhcp_option(option + 2, *option);
    option += length + 1;
  }
}

void print_dhcp_option(const unsigned char *option_content, int option) {
  if (verbosity <= MEDIUM) {
    printf(", option %d", option);
    return;
  }

  switch (option) {
  case DHCP_OPTION_PAD:
    printf(", pad (%d)", DHCP_OPTION_PAD);
    break;
  case DHCP_OPTION_SUBNET_MASK:
    printf(", subnet mask (%d) %s", DHCP_OPTION_SUBNET_MASK,
           inet_ntoa(*(struct in_addr *)option_content));
    break;
  case DHCP_OPTION_TIME_OFFSET:
    printf(", time offset (%d) %d", DHCP_OPTION_TIME_OFFSET,
           ntohl(*(unsigned int *)option_content));
    break;
  case DHCP_OPTION_ROUTER:
    printf(", router (%d) %s", DHCP_OPTION_ROUTER,
           inet_ntoa(*(struct in_addr *)option_content));
    break;
  case DHCP_OPTION_DOMAIN_NAME_SERVER:
    printf(", dns (%d) %s", DHCP_OPTION_DOMAIN_NAME_SERVER,
           inet_ntoa(*(struct in_addr *)option_content));
    break;
  case DHCP_OPTION_HOST_NAME:
    printf(", hostname (%d) %s", DHCP_OPTION_HOST_NAME, option_content);
    break;
  case DHCP_OPTION_DOMAIN_NAME:
    printf(", domain name (%d) %s", DHCP_OPTION_DOMAIN_NAME, option_content);
    break;
  case DHCP_OPTION_BROADCAST_ADDRESS:
    printf(", broadcast address (%d) %s", DHCP_OPTION_BROADCAST_ADDRESS,
           inet_ntoa(*(struct in_addr *)option_content));
    break;
  case DHCP_OPTION_REQUESTED_IP_ADDRESS:
    printf(", requested IP address (%d) %s", DHCP_OPTION_REQUESTED_IP_ADDRESS,
           inet_ntoa(*(struct in_addr *)option_content));
    break;
  case DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
    printf(", IP address lease time (%d) %d", DHCP_OPTION_IP_ADDRESS_LEASE_TIME,
           ntohl(*(unsigned int *)option_content));
    break;
  case DHCP_OPTION_MESSAGE_TYPE:
    printf(", message type %s (%d)",
           get_dhcp_message_type_name(*option_content), *option_content);
    break;
  case DHCP_OPTION_SERVER_IDENTIFIER:
    printf(", server identifier (%d) %s", DHCP_OPTION_SERVER_IDENTIFIER,
           inet_ntoa(*(struct in_addr *)option_content));
    break;
  case DHCP_OPTION_PARAMETER_REQUEST_LIST:
    printf(", parameter request list (%d)", DHCP_OPTION_PARAMETER_REQUEST_LIST);
    break;
  case DHCP_OPTION_RENEWAL_TIME:
    printf(", renewal time (%d) %d", DHCP_OPTION_RENEWAL_TIME,
           ntohl(*(unsigned int *)option_content));
    break;
  case DHCP_OPTION_REBINDING_TIME:
    printf(", rebinding time (%d) %d", DHCP_OPTION_REBINDING_TIME,
           ntohl(*(unsigned int *)option_content));
    break;
  case DHCP_OPTION_CLIENT_IDENTIFIER:
    printf(", client identifier (%d) %s", DHCP_OPTION_CLIENT_IDENTIFIER,
           option_content);
    break;
  default:
    printf(", unsupported option %d", option);
    break;
  }
}

const char *get_dhcp_message_type_name(int message_type) {
  switch (message_type) {
  case DHCP_DISCOVER:
    return "discover";
  case DHCP_OFFER:
    return "offer";
  case DHCP_REQUEST:
    return "request";
  case DHCP_DECLINE:
    return "decline";
  case DHCP_ACK:
    return "ack";
  case DHCP_NAK:
    return "nak";
  case DHCP_RELEASE:
    return "release";
  case DHCP_INFORM:
    return "inform";
  default:
    return "unknown";
  }
}

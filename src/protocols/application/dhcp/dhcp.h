// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_APPLICATION_DHCP_DHCP_H_
#define SRC_PROTOCOLS_APPLICATION_DHCP_DHCP_H_

enum dhcp_options {
  DHCP_OPTION_PAD = 0x00,
  DHCP_OPTION_SUBNET_MASK = 0x01,
  DHCP_OPTION_TIME_OFFSET = 0x02,
  DHCP_OPTION_ROUTER = 0x03,
  DHCP_OPTION_DOMAIN_NAME_SERVER = 0x06,
  DHCP_OPTION_HOST_NAME = 0x0C,
  DHCP_OPTION_DOMAIN_NAME = 0x0F,
  DHCP_OPTION_BROADCAST_ADDRESS = 0x1C,
  DHCP_OPTION_REQUESTED_IP_ADDRESS = 0x32,
  DHCP_OPTION_IP_ADDRESS_LEASE_TIME = 0x33,
  DHCP_OPTION_MESSAGE_TYPE = 0x35,
  DHCP_OPTION_SERVER_IDENTIFIER = 0x36,
  DHCP_OPTION_PARAMETER_REQUEST_LIST = 0x37,
  DHCP_OPTION_RENEWAL_TIME = 0x3A,
  DHCP_OPTION_REBINDING_TIME = 0x3B,
  DHCP_OPTION_CLIENT_IDENTIFIER = 0x3D,
  DHCP_OPTION_END = 0xFF
};

enum dhcp_message_types {
  DHCP_DISCOVER = 1,
  DHCP_OFFER = 2,
  DHCP_REQUEST = 3,
  DHCP_DECLINE = 4,
  DHCP_ACK = 5,
  DHCP_NAK = 6,
  DHCP_RELEASE = 7,
  DHCP_INFORM = 8
};

void print_dhcp_frame(const unsigned char *dhcp);
void print_dhcp_option(const unsigned char *option_content, int option);
const char *get_dhcp_message_type_name(int message_type);

#endif  // SRC_PROTOCOLS_APPLICATION_DHCP_DHCP_H_

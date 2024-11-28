// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_APPLICATION_H_
#define SRC_PROTOCOLS_APPLICATION_H_

#include <stdint.h>
#define BOOTP 1
typedef uint8_t u_char;

void get_application_protocol(const void *header, u_char protocol);

#endif  // SRC_PROTOCOLS_APPLICATION_H_

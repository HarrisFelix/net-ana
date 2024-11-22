// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_APPLICATION_H_
#define SRC_PROTOCOLS_APPLICATION_H_

#include <stdint.h>
#include <sys/_types/_u_char.h>
#define BOOTP 1

void get_application_protocol(const void *header, u_char protocol);

#endif  // SRC_PROTOCOLS_APPLICATION_H_

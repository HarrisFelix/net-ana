// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_UTILS_UTILS_H_
#define SRC_UTILS_UTILS_H_

#include <stddef.h>
#include <stdint.h>

char *string_to_upper(char *str);

struct name_value_pair_t {
  uint16_t value;
  const char *name;
};

struct name_value_pair_t
get_name_value_pair(uint16_t type, struct name_value_pair_t *name_value_pairs,
                    size_t len);

#endif  // SRC_UTILS_UTILS_H_

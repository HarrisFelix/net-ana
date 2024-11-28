#include "utils.h"
#include <ctype.h>
#include <stddef.h>

char *string_to_upper(char *str) {
  char *upper = str;

  while (*upper) {
    *upper = toupper(*upper);
    upper++;
  }

  return str;
}

struct name_value_pair_t
get_name_value_pair(uint16_t type, struct name_value_pair_t *name_value_pairs,
                    size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (name_value_pairs[i].value == type) {
      return name_value_pairs[i];
    }
  }

  return (struct name_value_pair_t){type, "UNKNOWN"};
}

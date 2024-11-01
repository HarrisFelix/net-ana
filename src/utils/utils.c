#include <ctype.h>

char *string_to_upper(char *str) {
  char *upper = str;

  while (*upper) {
    *upper = toupper(*upper);
    upper++;
  }

  return str;
}

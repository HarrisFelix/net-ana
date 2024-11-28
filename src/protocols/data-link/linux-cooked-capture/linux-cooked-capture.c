#include "../../../capture/capture_utils.h"
#include "../../../utils/utils.h"
#include "../ethernet/ethernet.h"
#include "linux-cooked-capture.h"
#include <stdint.h>
#include <stdio.h>

extern enum verbosity_level verbosity;
extern ether_type_t ether_types[];
extern const size_t ETHERTYPES_LEN;

uint16_t print_linux_cooked_header(const struct sll2_header *sll2) {
  struct name_value_pair_t name_value_pair = get_name_value_pair(
      htons(sll2->sll2_protocol), (struct name_value_pair_t *)ether_types,
      ETHERTYPES_LEN);

  printf(" %s", name_value_pair.name);
  if (verbosity == HIGH)
    printf(" (%d)", sll2->sll2_protocol);

  return name_value_pair.value;
}

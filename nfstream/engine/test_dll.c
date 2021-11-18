#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

uint16_t get_ndpi_api_version(void) {
  return ndpi_get_api_version();
}
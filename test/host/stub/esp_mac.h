#pragma once
// Host stand-in for esp_mac.h: the test defines the function.
#include <stdint.h>
#include "esp_err.h"
esp_err_t esp_efuse_mac_get_default(uint8_t *mac);

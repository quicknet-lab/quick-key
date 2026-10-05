#pragma once
#include <stdint.h>
#include <stddef.h>

// CTAP1/U2F raw message (ISO 7816 APDU framing). Returns response length.
size_t u2f_process(const uint8_t *req, size_t len, uint8_t *resp, size_t cap);

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// One CTAP2 request (command byte + CBOR). Writes status byte + CBOR to resp.
size_t ctap2_process(const uint8_t *req, size_t len, uint8_t *resp, size_t cap);
// alwaysUv: user verification for every request; U2F is disabled.
bool ctap2_always_uv(void);

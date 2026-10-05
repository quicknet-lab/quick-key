#pragma once
// Binds PINs to this chip. In the secure build an HMAC key sits in eFuse,
// read-protected: the HMAC peripheral uses it, software never sees it. A PIN
// checked through it can't be brute-forced off the chip, even from a
// decrypted flash dump, and every guess on the chip costs a chain of HMACs.
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Secure build: finds the key, or on the first start burns a new one and
// then forbids read-protecting any further eFuse (WR_DIS_RD_DIS, which the
// bootloader leaves for this). False: PINs can't be bound safely. Development
// build (no flash encryption): no eFuse is touched, a fixed software key
// stands in.
bool chipkey_init(void);
// out = HMAC(...HMAC(HMAC(in))), `rounds` times in a row.
bool chipkey_stretch(const uint8_t *in, size_t len, uint32_t rounds, uint8_t out[32]);
// Rounds that take about a quarter of a second on this chip.
uint32_t chipkey_rounds(void);

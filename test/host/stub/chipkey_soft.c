// Host stand-in for core/chipkey.c: the development build's software key,
// with few rounds so the tests stay fast.
#include "core/chipkey.h"
#include "core/crypto.h"
#include <string.h>

bool chipkey_init(void)
{
    return true;
}

bool chipkey_stretch(const uint8_t *in, size_t len, uint32_t rounds, uint8_t out[32])
{
    static const char soft_key[] = "quick-key development";
    uint8_t x[32];
    hmac_sha256((const uint8_t *)soft_key, sizeof(soft_key) - 1, in, len, x);
    for (uint32_t i = 1; i < rounds; i++) hmac_sha256((const uint8_t *)soft_key, sizeof(soft_key) - 1, x, 32, x);
    memcpy(out, x, sizeof(x));
    return true;
}

uint32_t chipkey_rounds(void)
{
    return 4;
}

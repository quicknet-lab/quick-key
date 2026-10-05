#include "vault.h"
#include "crypto.h"
#include <string.h>

size_t aead_seal(const uint8_t key[32], const uint8_t *in, size_t len, uint8_t *blob)
{
    blob[0] = SEAL_VERSION;
    crypto_random(blob + 1, 12);
    if (!aes256_gcm(true, key, blob + 1, in, blob + SEAL_OVERHEAD, len, blob + 13)) return 0;
    return len + SEAL_OVERHEAD;
}

bool aead_open(const uint8_t key[32], const uint8_t *blob, size_t blen, uint8_t *out, size_t *len)
{
    if (blen < SEAL_OVERHEAD || blob[0] != SEAL_VERSION) return false;
    uint8_t tag[16];
    memcpy(tag, blob + 13, 16);
    *len = blen - SEAL_OVERHEAD;
    return aes256_gcm(false, key, blob + 1, blob + SEAL_OVERHEAD, out, *len, tag);
}

void pin_kek(const uint8_t *pin, size_t pin_len, const uint8_t salt[KDF_SALT_LEN], uint8_t kek[32])
{
    pbkdf2_sha256(pin, pin_len, salt, KDF_SALT_LEN, KDF_ITER, kek, 32);
}

void pin_wrap(const uint8_t *pin, size_t pin_len, const uint8_t key[32], uint8_t out[PIN_WRAP_LEN])
{
    uint8_t kek[32];
    crypto_random(out, KDF_SALT_LEN);
    pin_kek(pin, pin_len, out, kek);
    aead_seal(kek, key, 32, out + KDF_SALT_LEN);
    memset(kek, 0, sizeof(kek));
}

bool pin_unwrap(const uint8_t *pin, size_t pin_len, const uint8_t in[PIN_WRAP_LEN], uint8_t key[32])
{
    uint8_t kek[32];
    size_t n;
    pin_kek(pin, pin_len, in, kek);
    bool ok = aead_open(kek, in + KDF_SALT_LEN, PIN_WRAP_LEN - KDF_SALT_LEN, key, &n) && n == 32;
    memset(kek, 0, sizeof(kek));
    if (!ok) memset(key, 0, 32);
    return ok;
}

bool vault_create(uint8_t priv[32], uint8_t pub[64])
{
    return p256_keygen(priv, pub);
}

static void vault_key(const uint8_t shared[32], const uint8_t eph_pub[64], uint8_t key[32])
{
    hkdf_sha256(eph_pub, 64, shared, 32, "quick-key vault", key, 32);
}

size_t vault_seal(const uint8_t pub[64], const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t eph[32], shared[32], key[32];
    bool ok = p256_keygen(eph, out) && p256_ecdh(eph, pub, shared);
    memset(eph, 0, sizeof(eph));
    if (!ok) return 0;
    vault_key(shared, out, key);
    size_t n = aead_seal(key, in, len, out + 64);
    memset(shared, 0, sizeof(shared));
    memset(key, 0, sizeof(key));
    return n ? n + 64 : 0;
}

bool vault_open(const uint8_t priv[32], const uint8_t *in, size_t len, uint8_t *out, size_t *olen)
{
    uint8_t shared[32], key[32];
    if (len < VAULT_OVERHEAD || !p256_ecdh(priv, in, shared)) return false;
    vault_key(shared, in, key);
    bool ok = aead_open(key, in + 64, len - 64, out, olen);
    memset(shared, 0, sizeof(shared));
    memset(key, 0, sizeof(key));
    return ok;
}

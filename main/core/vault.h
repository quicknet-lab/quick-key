#pragma once
// Secrets at rest protected by PINs (platform-independent, host-tested).
//
// Symmetric: AES-256-GCM blobs, keys derived from PINs with PBKDF2.
// Vault: a P-256 key pair per application. Secrets are sealed to the public
// key (ECDH + AES-GCM), so they can be written without a PIN; the private key
// is stored wrapped under each PIN and is needed to read them.
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Sealed blob: version(1) | iv(12) | tag(16) | AES-256-GCM ciphertext.
#define SEAL_VERSION    1
#define SEAL_OVERHEAD   (1 + 12 + 16)
size_t aead_seal(const uint8_t key[32], const uint8_t *in, size_t len, uint8_t *blob);
// Returns false on a wrong key, tampering or an unknown version.
bool aead_open(const uint8_t key[32], const uint8_t *blob, size_t blen, uint8_t *out, size_t *len);

// Key-encryption key from a PIN: PBKDF2-SHA256.
#define KDF_SALT_LEN    16
#define KDF_ITER        10000
void pin_kek(const uint8_t *pin, size_t pin_len, const uint8_t salt[KDF_SALT_LEN], uint8_t kek[32]);

// A 32-byte key wrapped under a PIN: salt(16) | sealed key. One blob, so a
// power cut can't leave salt and key out of sync. A wrong PIN fails the GCM tag.
#define PIN_WRAP_LEN    (KDF_SALT_LEN + 32 + SEAL_OVERHEAD)
void pin_wrap(const uint8_t *pin, size_t pin_len, const uint8_t key[32], uint8_t out[PIN_WRAP_LEN]);
bool pin_unwrap(const uint8_t *pin, size_t pin_len, const uint8_t in[PIN_WRAP_LEN], uint8_t key[32]);

// Vault sealing: ephemeral public key(64) | sealed data.
#define VAULT_OVERHEAD  (64 + SEAL_OVERHEAD)
bool vault_create(uint8_t priv[32], uint8_t pub[64]);
size_t vault_seal(const uint8_t pub[64], const uint8_t *in, size_t len, uint8_t *out);
bool vault_open(const uint8_t priv[32], const uint8_t *in, size_t len, uint8_t *out, size_t *olen);

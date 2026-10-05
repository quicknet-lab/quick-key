#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

void crypto_init(void);
void crypto_random(void *buf, size_t len);
// mbedTLS-compatible RNG callback.
int crypto_rng(void *ctx, unsigned char *buf, size_t len);

void sha1(const uint8_t *in, size_t len, uint8_t out[20]);
void sha256(const uint8_t *in, size_t len, uint8_t out[32]);
void sha512(const uint8_t *in, size_t len, uint8_t out[64]);
void hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *in, size_t len, uint8_t out[32]);
// md: 1 = SHA1, 2 = SHA256, 3 = SHA512. Returns digest size.
size_t hmac_any(int md, const uint8_t *key, size_t klen, const uint8_t *in, size_t len, uint8_t *out);
void hkdf_sha256(const uint8_t *salt, size_t slen, const uint8_t *ikm, size_t ilen,
                 const char *info, uint8_t *out, size_t olen);
void pbkdf2_sha256(const uint8_t *pw, size_t plen, const uint8_t *salt, size_t slen,
                   uint32_t iter, uint8_t *out, size_t olen);

// AES-256-CBC without padding, len must be a multiple of 16.
bool aes256_cbc(bool enc, const uint8_t key[32], const uint8_t iv[16],
                const uint8_t *in, uint8_t *out, size_t len);
// AES-256-GCM. Returns false on tag mismatch (decrypt).
bool aes256_gcm(bool enc, const uint8_t key[32], const uint8_t iv[12],
                const uint8_t *in, uint8_t *out, size_t len, uint8_t tag[16]);

// NIST P-256. Public keys are raw X||Y (64 bytes).
bool p256_keygen(uint8_t priv[32], uint8_t pub[64]);
bool p256_pubkey(const uint8_t priv[32], uint8_t pub[64]);
// Turns arbitrary 32 bytes into a valid private key (rehashes until valid).
void p256_fix_privkey(uint8_t priv[32]);
bool p256_sign(const uint8_t priv[32], const uint8_t *hash, size_t hlen, uint8_t sig_rs[64]);
bool p256_ecdh(const uint8_t priv[32], const uint8_t peer[64], uint8_t shared_x[32]);
// ECDH returning the full shared point X||Y.
bool p256_ecdh_point(const uint8_t priv[32], const uint8_t peer[64], uint8_t shared[64]);
// Raw r||s to DER. Returns DER length (<= 72).
size_t ecdsa_sig_to_der(const uint8_t rs[64], uint8_t *der);

// Ed25519 (RFC 8032) keyed by a 32-byte seed; X25519 (RFC 7748). Monocypher.
void ed25519_pubkey(const uint8_t seed[32], uint8_t pub[32]);
void ed25519_sign(const uint8_t seed[32], const uint8_t *msg, size_t len, uint8_t sig[64]);
void x25519_pubkey(const uint8_t priv[32], uint8_t pub[32]);
// False if the shared secret is all zeros (low-order peer key).
bool x25519(const uint8_t priv[32], const uint8_t peer[32], uint8_t shared[32]);

bool ct_equal(const void *a, const void *b, size_t len);

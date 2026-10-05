#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Credential ID: meta(1) || nonce(16) || tag(16). The private key is derived
// from the master secret, meta, nonce and RP ID hash, so nothing is stored for
// non-discoverable credentials and U2F key handles. The tag authenticates meta.
//
// meta bits 0-1: kind (1 = non-discoverable, 2 = discoverable; a discoverable
//                credential stops working once deleted from storage)
//      bit 2:    created with hmac-secret
//      bit 3:    Ed25519 key (else P-256)
//      bit 6:    created with largeBlobKey
//      bits 4-5: credProtect level (0 = not requested, behaves as 1)
#define CRED_ID_LEN     33
#define CRED_ID_VER     0x01    // plain non-discoverable (also U2F key handles)
#define CRED_ID_VER_RK  0x02
#define CRED_KIND(m)    ((m) & 0x03)
#define CRED_HMAC       0x04
#define CRED_ED25519    0x08
#define CRED_LBK        0x40
#define CRED_CP(m)      (((m) >> 4) & 0x03)
#define CRED_META(kind, hmac, cp) ((uint8_t)((kind) | ((hmac) ? CRED_HMAC : 0) | ((cp) << 4)))

extern const uint8_t fido_aaguid[16];

void fido_init(void);
// Wipe all FIDO state and generate a new master secret.
void fido_reset(void);
void fido_new_cred(const uint8_t rp_id_hash[32], uint8_t meta, uint8_t cred_id[CRED_ID_LEN], uint8_t priv[32]);
// hmac-secret CredRandom for a credential (separate values with and without UV).
void fido_cred_random(const uint8_t cred_id[CRED_ID_LEN], bool uv, uint8_t out[32]);
// largeBlobKey of a credential (derived, nothing stored).
void fido_large_blob_key(const uint8_t cred_id[CRED_ID_LEN], uint8_t out[32]);
bool fido_open_cred(const uint8_t rp_id_hash[32], const uint8_t *cred_id, size_t len, uint8_t priv[32]);
// Advances the signature counter; false if the new value could not be stored
// (the counter must never go back after a reboot).
bool fido_next_counter(uint32_t *ctr);
const uint8_t *fido_att_priv(void);
const uint8_t *fido_att_cert(size_t *len);

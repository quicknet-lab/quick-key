#include "ctap2.h"
#include "cbor.h"
#include "fido.h"
#include "core/crypto.h"
#include "core/devpin.h"
#include "core/store.h"
#include "core/up.h"
#include "apps/admin.h"
#include <stdio.h>
#include <string.h>
#include "esp_timer.h"

#define CMD_MAKE_CREDENTIAL     0x01
#define CMD_GET_ASSERTION       0x02
#define CMD_GET_INFO            0x04
#define CMD_CLIENT_PIN          0x06
#define CMD_RESET               0x07
#define CMD_GET_NEXT_ASSERTION  0x08
#define CMD_CRED_MGMT           0x0A
#define CMD_SELECTION           0x0B
#define CMD_LARGE_BLOBS         0x0C
#define CMD_CONFIG              0x0D
#define CMD_CRED_MGMT_PRE       0x41

#define ERR_OK                      0x00
#define ERR_INVALID_COMMAND         0x01
#define ERR_INVALID_PARAMETER       0x02
#define ERR_INVALID_LENGTH          0x03
#define ERR_INVALID_SEQ             0x04
#define ERR_CBOR_UNEXPECTED_TYPE    0x11
#define ERR_INVALID_CBOR            0x12
#define ERR_MISSING_PARAMETER       0x14
#define ERR_LIMIT_EXCEEDED          0x15
#define ERR_LARGE_BLOB_STORAGE_FULL 0x18
#define ERR_CREDENTIAL_EXCLUDED     0x19
#define ERR_UNSUPPORTED_ALGORITHM   0x26
#define ERR_OPERATION_DENIED        0x27
#define ERR_KEY_STORE_FULL          0x28
#define ERR_INVALID_OPTION          0x2C
#define ERR_KEEPALIVE_CANCEL        0x2D
#define ERR_NO_CREDENTIALS          0x2E
#define ERR_USER_ACTION_TIMEOUT     0x2F
#define ERR_NOT_ALLOWED             0x30
#define ERR_PIN_INVALID             0x31
#define ERR_PIN_BLOCKED             0x32
#define ERR_PIN_AUTH_INVALID        0x33
#define ERR_PIN_AUTH_BLOCKED        0x34
#define ERR_PIN_NOT_SET             0x35
#define ERR_PUAT_REQUIRED           0x36
#define ERR_PIN_POLICY_VIOLATION    0x37
#define ERR_INTEGRITY_FAILURE       0x3D
#define ERR_INVALID_SUBCOMMAND      0x3E
#define ERR_UNAUTHORIZED_PERMISSION 0x40
#define ERR_OTHER                   0x7F

#define FLAG_UP 0x01
#define FLAG_UV 0x04
#define FLAG_AT 0x40
#define FLAG_ED 0x80

#define PERM_MC 0x01
#define PERM_GA 0x02
#define PERM_CM 0x04
#define PERM_LBW 0x10
#define PERM_ACFG 0x20

#define COSE_ES256      (-7)
#define COSE_EDDSA      (-8)
#define UP_TIMEOUT_MS   30000
#define MAX_RK          100
#define MAX_LIST        16
#define MAX_MSG         7609
#define LB_MAX          2048    // maxSerializedLargeBlobArray
#define LB_FRAGMENT     (MAX_MSG - 64)
#define RESET_WINDOW_US (10 * 1000000LL)
#define NEXT_ASSERTION_US (30 * 1000000LL)

typedef struct {
    uint8_t rp_id_hash[32];
    uint8_t cred_id[CRED_ID_LEN];
    uint8_t user_id[64];
    uint8_t user_id_len;
    char user_name[65];
    char display_name[65];
    char rp_id[65];
    uint32_t seq;
} rk_t;

static uint8_t s_ka_priv[32], s_ka_pub[64];
static uint8_t s_token[32];
static uint8_t s_token_perms;
static uint8_t s_token_proto;
static uint8_t s_token_rp[32];
static bool s_token_has_rp, s_token_valid;
static bool s_token_used;
static int64_t s_token_issued;
static uint32_t s_token_pin_gen;

#define TOKEN_FIRST_USE_US  (30 * 1000000LL)    // CTAP 2.1 initial usage time limit
#define TOKEN_LIFETIME_US   (600 * 1000000LL)   // maximum usage period
static uint8_t s_pin_fails;     // consecutive mismatches since power-up
static bool s_initialized;
static bool s_always_uv;        // authenticatorConfig toggleAlwaysUv, stored as "alwaysuv"

static struct {
    bool active;
    uint8_t rp_id_hash[32];
    uint8_t cdh[32];
    uint8_t flags;
    int slots[MAX_LIST];
    int count, pos;
    int64_t ts;
} s_next;

// hmac-secret request of the current getAssertion (reused by getNextAssertion).
static struct {
    bool present;
    uint8_t proto;
    uint8_t shared[64];
    uint8_t salts[64];
    size_t salt_len;
} s_hmac;

static bool s_lbk_requested;    // largeBlobKey asked for in the current getAssertion

// Large-blob array write in progress (authenticatorLargeBlobs set).
static uint8_t s_lb_buf[LB_MAX];
static size_t s_lb_expected, s_lb_off;

static rk_t s_rk;   // scratch, keeps big structs off the stack

// ---- helpers ----

static void rk_key(int i, char *k)
{
    snprintf(k, 8, "rk%02d", i);
}

static bool rk_load(int i, rk_t *rk)
{
    char k[8];
    rk_key(i, k);
    return store_read(NS_FIDO, k, rk, sizeof(*rk));
}

static int rk_find_id(const uint8_t *cred_id, size_t len)
{
    if (len != CRED_ID_LEN) return -1;
    for (int i = 0; i < MAX_RK; i++) {
        if (rk_load(i, &s_rk) && memcmp(s_rk.cred_id, cred_id, CRED_ID_LEN) == 0) return i;
    }
    return -1;
}

// A credential ID is usable if it authenticates for this RP and, for a
// discoverable credential, still exists in storage.
static bool cred_usable(const uint8_t rp_id_hash[32], const uint8_t *id, size_t len, uint8_t priv[32])
{
    if (!fido_open_cred(rp_id_hash, id, len, priv)) return false;
    if (CRED_KIND(id[0]) == CRED_ID_VER_RK && rk_find_id(id, len) < 0) {
        memset(priv, 0, 32);
        return false;
    }
    return true;
}

// credProtect: 3 needs UV; 2 needs UV unless the RP named the credential.
static bool cp_allows(uint8_t meta, bool uv, bool listed)
{
    uint8_t cp = CRED_CP(meta);
    if (cp == 3) return uv;
    if (cp == 2) return uv || listed;
    return true;
}

static uint8_t up_result_err(up_result_t r)
{
    return r == UP_CANCEL ? ERR_KEEPALIVE_CANCEL : ERR_USER_ACTION_TIMEOUT;
}

static void regen_key_agreement(void)
{
    p256_keygen(s_ka_priv, s_ka_pub);
}

static void reset_token(void)
{
    crypto_random(s_token, sizeof(s_token));
    s_token_valid = false;
    s_token_perms = 0;
    s_token_has_rp = false;
    s_token_used = false;
}

static void ctap2_init(void)
{
    store_del(NS_FIDO, "pin");     // own PIN of older firmware; the device PIN is used now
    uint8_t v;
    s_always_uv = store_read(NS_FIDO, "alwaysuv", &v, 1) && v;
    regen_key_agreement();
    reset_token();
    s_initialized = true;
}

static void put_cose_key(cbor_w *w, const uint8_t pub[64], int alg)
{
    cbor_put_map(w, 5);
    cbor_put_int(w, 1);
    cbor_put_int(w, 2);         // kty: EC2
    cbor_put_int(w, 3);
    cbor_put_int(w, alg);
    cbor_put_int(w, -1);
    cbor_put_int(w, 1);         // crv: P-256
    cbor_put_int(w, -2);
    cbor_put_bytes(w, pub, 32);
    cbor_put_int(w, -3);
    cbor_put_bytes(w, pub + 32, 32);
}

// Public key of a credential as COSE: EC2 P-256 or OKP Ed25519.
static void put_cred_cose(cbor_w *w, uint8_t meta, const uint8_t priv[32])
{
    uint8_t pub[64];
    if (!(meta & CRED_ED25519)) {
        p256_pubkey(priv, pub);
        put_cose_key(w, pub, COSE_ES256);
        return;
    }
    ed25519_pubkey(priv, pub);
    cbor_put_map(w, 4);
    cbor_put_int(w, 1);
    cbor_put_int(w, 1);         // kty: OKP
    cbor_put_int(w, 3);
    cbor_put_int(w, COSE_EDDSA);
    cbor_put_int(w, -1);
    cbor_put_int(w, 6);         // crv: Ed25519
    cbor_put_int(w, -2);
    cbor_put_bytes(w, pub, 32);
}

static bool parse_cose_key(cbor_r *r, uint8_t pub[64])
{
    size_t n;
    bool hx = false, hy = false;
    if (!cbor_get_map(r, &n)) return false;
    for (size_t i = 0; i < n; i++) {
        int64_t k;
        const uint8_t *d;
        size_t dl;
        if (!cbor_get_int(r, &k)) return false;
        if ((k == -2 || k == -3) && cbor_peek(r) == CBOR_BYTES) {
            if (!cbor_get_bytes(r, &d, &dl) || dl != 32) return false;
            memcpy(pub + (k == -2 ? 0 : 32), d, 32);
            if (k == -2) hx = true;
            else hy = true;
        } else if (!cbor_skip(r)) {
            return false;
        }
    }
    return hx && hy;
}

// Credential descriptor {"id": bytes, "type": "public-key", ...}
static bool parse_cred_desc(cbor_r *r, const uint8_t **id, size_t *idlen, bool *is_pk)
{
    size_t n;
    *id = NULL;
    *is_pk = false;
    if (!cbor_get_map(r, &n)) return false;
    for (size_t i = 0; i < n; i++) {
        if (cbor_text_eq(r, "id")) {
            if (!cbor_get_bytes(r, id, idlen)) return false;
        } else if (cbor_text_eq(r, "type")) {
            *is_pk = cbor_text_eq(r, "public-key");
            if (!*is_pk && !cbor_skip(r)) return false;
        } else {
            if (!cbor_skip(r) || !cbor_skip(r)) return false;
        }
    }
    return *id != NULL;
}

static void copy_text(char *dst, size_t cap, const char *s, size_t n)
{
    if (n >= cap) n = cap - 1;  // truncation as allowed by CTAP2 (64 bytes)
    memcpy(dst, s, n);
    dst[n] = 0;
}

// ---- PIN/UV auth protocols 1 and 2 ----

static bool proto_ok(uint64_t p)
{
    return p == 1 || p == 2;
}

// shared: v1 -> [0..32] key; v2 -> [0..32] HMAC key, [32..64] AES key
static bool shared_secret(uint8_t proto, const uint8_t peer[64], uint8_t shared[64])
{
    uint8_t z[32];
    if (!p256_ecdh(s_ka_priv, peer, z)) return false;
    if (proto == 1) {
        sha256(z, 32, shared);
    } else {
        uint8_t salt[32] = {0};
        hkdf_sha256(salt, 32, z, 32, "CTAP2 HMAC key", shared, 32);
        hkdf_sha256(salt, 32, z, 32, "CTAP2 AES key", shared + 32, 32);
    }
    memset(z, 0, sizeof(z));
    return true;
}

// pt holds cap bytes; longer input is rejected before anything is written.
static bool pin_decrypt(uint8_t proto, const uint8_t shared[64], const uint8_t *ct, size_t len,
                        uint8_t *pt, size_t cap, size_t *ptlen)
{
    static const uint8_t zero_iv[16] = {0};
    if (proto == 1) {
        if (len == 0 || len % 16 || len > cap) return false;
        *ptlen = len;
        return aes256_cbc(false, shared, zero_iv, ct, pt, len);
    }
    if (len < 32 || len % 16 || len - 16 > cap) return false;
    *ptlen = len - 16;
    return aes256_cbc(false, shared + 32, ct, ct + 16, pt, len - 16);
}

static size_t pin_encrypt(uint8_t proto, const uint8_t shared[64], const uint8_t *pt, size_t len, uint8_t *ct)
{
    static const uint8_t zero_iv[16] = {0};
    if (proto == 1) {
        aes256_cbc(true, shared, zero_iv, pt, ct, len);
        return len;
    }
    crypto_random(ct, 16);
    aes256_cbc(true, shared + 32, ct, pt, ct + 16, len);
    return len + 16;
}

static bool pin_verify_mac(uint8_t proto, const uint8_t *key, const uint8_t *msg, size_t mlen,
                           const uint8_t *param, size_t plen)
{
    uint8_t mac[32];
    hmac_sha256(key, 32, msg, mlen, mac);
    size_t need = proto == 1 ? 16 : 32;
    return plen == need && ct_equal(mac, param, need);
}

// True if param is a valid MAC over msg with the current pinUvAuthToken. A
// token must be used within 30 s, lives at most 10 minutes and dies with any
// change of the device PIN (also through OpenPGP or PIV).
static bool token_mac_ok(uint64_t proto, const uint8_t *msg, size_t len, const uint8_t *param, size_t plen)
{
    if (!s_token_valid || proto != s_token_proto) return false;
    int64_t age = esp_timer_get_time() - s_token_issued;
    if (age > TOKEN_LIFETIME_US || (!s_token_used && age > TOKEN_FIRST_USE_US) ||
        s_token_pin_gen != devpin_generation()) {
        reset_token();
        return false;
    }
    if (!pin_verify_mac(proto, s_token, msg, len, param, plen)) return false;
    s_token_used = true;
    return true;
}

static uint8_t check_token(uint64_t proto, const uint8_t *param, size_t plen, const uint8_t cdh[32],
                           uint8_t perm, const uint8_t rp_id_hash[32])
{
    if (!token_mac_ok(proto, cdh, 32, param, plen)) return ERR_PIN_AUTH_INVALID;
    if (!(s_token_perms & perm)) return ERR_PIN_AUTH_INVALID;
    if (s_token_has_rp && memcmp(s_token_rp, rp_id_hash, 32) != 0) return ERR_PIN_AUTH_INVALID;
    if (!s_token_has_rp) {
        memcpy(s_token_rp, rp_id_hash, 32);
        s_token_has_rp = true;
    }
    // One makeCredential/getAssertion per token (CTAP 2.1: all permissions
    // but largeBlobWrite are cleared after use).
    s_token_perms &= PERM_LBW;
    return ERR_OK;
}

// Zero-length pinUvAuthParam: the platform asks the user to pick this device.
static uint8_t select_by_touch(void)
{
    up_result_t r = up_wait("Select", "Press to use this key", UP_TIMEOUT_MS);
    if (r != UP_OK) return r == UP_CANCEL ? ERR_KEEPALIVE_CANCEL : ERR_OPERATION_DENIED;
    return ERR_PIN_INVALID;
}

// ---- authenticatorGetInfo ----

static uint8_t get_info(cbor_w *w)
{
    cbor_put_map(w, 14);

    cbor_put_uint(w, 0x01);
    // U2F is disabled while alwaysUv is on.
    cbor_put_array(w, s_always_uv ? 3 : 4);
    if (!s_always_uv) cbor_put_text(w, "U2F_V2");
    cbor_put_text(w, "FIDO_2_0");
    cbor_put_text(w, "FIDO_2_1_PRE");
    cbor_put_text(w, "FIDO_2_1");

    cbor_put_uint(w, 0x02);
    cbor_put_array(w, 3);
    cbor_put_text(w, "credProtect");
    cbor_put_text(w, "hmac-secret");
    cbor_put_text(w, "largeBlobKey");

    cbor_put_uint(w, 0x03);
    cbor_put_bytes(w, fido_aaguid, 16);

    cbor_put_uint(w, 0x04);
    // Canonical CBOR: keys sorted by length, then bytewise.
    cbor_put_map(w, 11);
    cbor_put_text(w, "rk");
    cbor_put_bool(w, true);
    cbor_put_text(w, "up");
    cbor_put_bool(w, true);
    cbor_put_text(w, "plat");
    cbor_put_bool(w, false);
    cbor_put_text(w, "alwaysUv");
    cbor_put_bool(w, s_always_uv);
    cbor_put_text(w, "credMgmt");
    cbor_put_bool(w, true);
    cbor_put_text(w, "authnrCfg");
    cbor_put_bool(w, true);
    cbor_put_text(w, "clientPin");
    cbor_put_bool(w, true);         // the device PIN always exists
    cbor_put_text(w, "largeBlobs");
    cbor_put_bool(w, true);
    cbor_put_text(w, "pinUvAuthToken");
    cbor_put_bool(w, true);
    cbor_put_text(w, "makeCredUvNotRqd");
    cbor_put_bool(w, !s_always_uv);
    cbor_put_text(w, "credentialMgmtPreview");
    cbor_put_bool(w, true);

    cbor_put_uint(w, 0x05);
    cbor_put_uint(w, MAX_MSG);

    cbor_put_uint(w, 0x06);
    cbor_put_array(w, 2);
    cbor_put_uint(w, 2);
    cbor_put_uint(w, 1);

    cbor_put_uint(w, 0x07);
    cbor_put_uint(w, MAX_LIST);

    cbor_put_uint(w, 0x08);
    cbor_put_uint(w, CRED_ID_LEN);

    cbor_put_uint(w, 0x09);
    cbor_put_array(w, 1);
    cbor_put_text(w, "usb");

    cbor_put_uint(w, 0x0A);
    cbor_put_array(w, 2);
    cbor_put_map(w, 2);
    cbor_put_text(w, "alg");
    cbor_put_int(w, COSE_ES256);
    cbor_put_text(w, "type");
    cbor_put_text(w, "public-key");
    cbor_put_map(w, 2);
    cbor_put_text(w, "alg");
    cbor_put_int(w, COSE_EDDSA);
    cbor_put_text(w, "type");
    cbor_put_text(w, "public-key");

    cbor_put_uint(w, 0x0B);
    cbor_put_uint(w, LB_MAX);

    // The factory PIN guards nothing: the platform has to change it first.
    cbor_put_uint(w, 0x0C);
    cbor_put_bool(w, devpin_is_default(DEVPIN_USER));        // forcePINChange

    cbor_put_uint(w, 0x0D);
    cbor_put_uint(w, DEVPIN_USER_MIN);

    uint8_t v[3];
    fw_version(v);
    cbor_put_uint(w, 0x0E);
    cbor_put_uint(w, ((uint32_t)v[0] << 16) | (v[1] << 8) | v[2]);     // firmwareVersion

    return ERR_OK;
}

// ---- authenticatorMakeCredential ----

static size_t build_auth_data(uint8_t *ad, const uint8_t rp_id_hash[32], uint8_t flags, uint32_t ctr,
                              const uint8_t *cred_id, const uint8_t *priv, const uint8_t *ext, size_t ext_len)
{
    if (ext_len) flags |= FLAG_ED;
    memcpy(ad, rp_id_hash, 32);
    ad[32] = flags;
    ad[33] = ctr >> 24;
    ad[34] = ctr >> 16;
    ad[35] = ctr >> 8;
    ad[36] = ctr;
    size_t n = 37;
    if (flags & FLAG_AT) {
        memcpy(ad + n, fido_aaguid, 16);
        n += 16;
        ad[n++] = 0;
        ad[n++] = CRED_ID_LEN;
        memcpy(ad + n, cred_id, CRED_ID_LEN);
        n += CRED_ID_LEN;
        cbor_w kw;
        cbor_w_init(&kw, ad + n, 100);
        put_cred_cose(&kw, cred_id[0], priv);
        n += kw.len;
    }
    memcpy(ad + n, ext, ext_len);
    return n + ext_len;
}

static bool sign_ad_cdh(const uint8_t priv[32], const uint8_t *ad, size_t adlen, const uint8_t cdh[32],
                        uint8_t *der, size_t *derlen)
{
    uint8_t buf[256], hash[32], rs[64];
    if (adlen + 32 > sizeof(buf)) return false;
    memcpy(buf, ad, adlen);
    memcpy(buf + adlen, cdh, 32);
    sha256(buf, adlen + 32, hash);
    if (!p256_sign(priv, hash, 32, rs)) return false;
    *derlen = ecdsa_sig_to_der(rs, der);
    return true;
}

// Assertion signature with a credential key: DER ECDSA or raw Ed25519 (64 bytes).
static bool sign_cred(uint8_t meta, const uint8_t priv[32], const uint8_t *ad, size_t adlen,
                      const uint8_t cdh[32], uint8_t *sig, size_t *siglen)
{
    if (!(meta & CRED_ED25519)) return sign_ad_cdh(priv, ad, adlen, cdh, sig, siglen);
    uint8_t buf[256];
    if (adlen + 32 > sizeof(buf)) return false;
    memcpy(buf, ad, adlen);
    memcpy(buf + adlen, cdh, 32);
    ed25519_sign(priv, buf, adlen + 32, sig);
    *siglen = 64;
    return true;
}

static int rk_store(const uint8_t rp_id_hash[32], const uint8_t *cred_id, const uint8_t *uid, size_t uid_len,
                    const char *name, size_t name_len, const char *dname, size_t dname_len,
                    const char *rp_id, size_t rp_id_len)
{
    int free_slot = -1, slot = -1;
    uint32_t max_seq = 0;
    for (int i = 0; i < MAX_RK; i++) {
        if (!rk_load(i, &s_rk)) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (s_rk.seq > max_seq) max_seq = s_rk.seq;
        // Same RP and user handle: overwrite.
        if (slot < 0 && memcmp(s_rk.rp_id_hash, rp_id_hash, 32) == 0 &&
            s_rk.user_id_len == uid_len && memcmp(s_rk.user_id, uid, uid_len) == 0) {
            slot = i;
        }
    }
    if (slot < 0) slot = free_slot;
    if (slot < 0) return -1;

    memset(&s_rk, 0, sizeof(s_rk));
    memcpy(s_rk.rp_id_hash, rp_id_hash, 32);
    memcpy(s_rk.cred_id, cred_id, CRED_ID_LEN);
    memcpy(s_rk.user_id, uid, uid_len);
    s_rk.user_id_len = uid_len;
    if (name) copy_text(s_rk.user_name, sizeof(s_rk.user_name), name, name_len);
    if (dname) copy_text(s_rk.display_name, sizeof(s_rk.display_name), dname, dname_len);
    copy_text(s_rk.rp_id, sizeof(s_rk.rp_id), rp_id, rp_id_len);
    s_rk.seq = max_seq + 1;
    char k[8];
    rk_key(slot, k);
    return store_set(NS_FIDO, k, &s_rk, sizeof(s_rk)) == ESP_OK ? slot : -1;
}

static uint8_t make_credential(cbor_r *r, cbor_w *w)
{
    const uint8_t *cdh = NULL, *uid = NULL, *pin_param = NULL;
    const char *rp_id = NULL, *uname = NULL, *dname = NULL;
    size_t rp_id_len = 0, uid_len = 0, uname_len = 0, dname_len = 0, pin_param_len = 0, len;
    const uint8_t *excl[MAX_LIST];
    size_t excl_len[MAX_LIST], nexcl = 0;
    bool have_user = false, have_params = false;
    int64_t cred_alg = 0;   // first supported entry of pubKeyCredParams (RP preference order)
    bool opt_rk = false, opt_uv = false, opt_up = true, ext_hmac = false, ext_lbk = false;
    uint64_t proto = 0, ext_cp = 0;
    size_t n;

    if (!cbor_get_map(r, &n)) return ERR_INVALID_CBOR;
    for (size_t i = 0; i < n; i++) {
        uint64_t key;
        size_t m;
        if (!cbor_get_uint(r, &key)) return ERR_INVALID_CBOR;
        switch (key) {
        case 1:
            if (!cbor_get_bytes(r, &cdh, &len)) return ERR_CBOR_UNEXPECTED_TYPE;
            if (len != 32) return ERR_INVALID_LENGTH;
            break;
        case 2:
            if (!cbor_get_map(r, &m)) return ERR_CBOR_UNEXPECTED_TYPE;
            for (size_t j = 0; j < m; j++) {
                if (cbor_text_eq(r, "id")) {
                    if (!cbor_get_text(r, &rp_id, &rp_id_len)) return ERR_CBOR_UNEXPECTED_TYPE;
                } else if (!cbor_skip(r) || !cbor_skip(r)) {
                    return ERR_INVALID_CBOR;
                }
            }
            break;
        case 3:
            if (!cbor_get_map(r, &m)) return ERR_CBOR_UNEXPECTED_TYPE;
            have_user = true;
            for (size_t j = 0; j < m; j++) {
                if (cbor_text_eq(r, "id")) {
                    if (!cbor_get_bytes(r, &uid, &uid_len)) return ERR_CBOR_UNEXPECTED_TYPE;
                    if (uid_len > 64) return ERR_INVALID_LENGTH;
                } else if (cbor_text_eq(r, "name")) {
                    if (!cbor_get_text(r, &uname, &uname_len)) return ERR_CBOR_UNEXPECTED_TYPE;
                } else if (cbor_text_eq(r, "displayName")) {
                    if (!cbor_get_text(r, &dname, &dname_len)) return ERR_CBOR_UNEXPECTED_TYPE;
                } else if (!cbor_skip(r) || !cbor_skip(r)) {
                    return ERR_INVALID_CBOR;
                }
            }
            break;
        case 4:
            if (!cbor_get_array(r, &m)) return ERR_CBOR_UNEXPECTED_TYPE;
            have_params = true;
            for (size_t j = 0; j < m; j++) {
                size_t pm;
                int64_t alg = 0;
                bool is_pk = false;
                if (!cbor_get_map(r, &pm)) return ERR_CBOR_UNEXPECTED_TYPE;
                for (size_t k = 0; k < pm; k++) {
                    if (cbor_text_eq(r, "alg")) {
                        if (!cbor_get_int(r, &alg)) return ERR_CBOR_UNEXPECTED_TYPE;
                    } else if (cbor_text_eq(r, "type")) {
                        is_pk = cbor_text_eq(r, "public-key");
                        if (!is_pk && !cbor_skip(r)) return ERR_INVALID_CBOR;
                    } else if (!cbor_skip(r) || !cbor_skip(r)) {
                        return ERR_INVALID_CBOR;
                    }
                }
                if (is_pk && !cred_alg && (alg == COSE_ES256 || alg == COSE_EDDSA)) cred_alg = alg;
            }
            break;
        case 5:
            if (!cbor_get_array(r, &m)) return ERR_CBOR_UNEXPECTED_TYPE;
            for (size_t j = 0; j < m; j++) {
                const uint8_t *id;
                size_t idl;
                bool is_pk;
                if (!parse_cred_desc(r, &id, &idl, &is_pk)) return ERR_INVALID_CBOR;
                if (is_pk && nexcl < MAX_LIST) {
                    excl[nexcl] = id;
                    excl_len[nexcl++] = idl;
                }
            }
            break;
        case 6:
            if (!cbor_get_map(r, &m)) return ERR_CBOR_UNEXPECTED_TYPE;
            for (size_t j = 0; j < m; j++) {
                if (cbor_text_eq(r, "credProtect")) {
                    if (!cbor_get_uint(r, &ext_cp)) return ERR_CBOR_UNEXPECTED_TYPE;
                    if (ext_cp > 3) ext_cp = 0;
                } else if (cbor_text_eq(r, "hmac-secret")) {
                    if (!cbor_get_bool(r, &ext_hmac)) return ERR_CBOR_UNEXPECTED_TYPE;
                } else if (cbor_text_eq(r, "largeBlobKey")) {
                    if (!cbor_get_bool(r, &ext_lbk)) return ERR_CBOR_UNEXPECTED_TYPE;
                    if (!ext_lbk) return ERR_INVALID_OPTION;
                } else if (!cbor_skip(r) || !cbor_skip(r)) {
                    return ERR_INVALID_CBOR;
                }
            }
            break;
        case 7:
            if (!cbor_get_map(r, &m)) return ERR_CBOR_UNEXPECTED_TYPE;
            for (size_t j = 0; j < m; j++) {
                bool *opt = cbor_text_eq(r, "rk") ? &opt_rk : cbor_text_eq(r, "uv") ? &opt_uv
                          : cbor_text_eq(r, "up") ? &opt_up : NULL;
                if (opt) {
                    if (!cbor_get_bool(r, opt)) return ERR_CBOR_UNEXPECTED_TYPE;
                } else if (!cbor_skip(r) || !cbor_skip(r)) {
                    return ERR_INVALID_CBOR;
                }
            }
            break;
        case 8:
            if (!cbor_get_bytes(r, &pin_param, &pin_param_len)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        case 9:
            if (!cbor_get_uint(r, &proto)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        default:
            if (!cbor_skip(r)) return ERR_INVALID_CBOR;
            break;
        }
    }
    if (!cdh || !rp_id || !have_user || !uid || !have_params) return ERR_MISSING_PARAMETER;

    if (pin_param && pin_param_len == 0) return select_by_touch();
    if (pin_param && !proto) return ERR_MISSING_PARAMETER;
    if (pin_param && !proto_ok(proto)) return ERR_INVALID_PARAMETER;
    if (!cred_alg) return ERR_UNSUPPORTED_ALGORITHM;
    if (opt_uv || !opt_up) return ERR_INVALID_OPTION;
    if (ext_lbk && !opt_rk) return ERR_INVALID_OPTION;     // largeBlobKey needs a discoverable credential

    uint8_t rp_id_hash[32];
    sha256((const uint8_t *)rp_id, rp_id_len, rp_id_hash);

    uint8_t flags = FLAG_UP | FLAG_AT;
    if (pin_param) {
        uint8_t e = check_token(proto, pin_param, pin_param_len, cdh, PERM_MC, rp_id_hash);
        if (e) return e;
        flags |= FLAG_UV;
    } else if (s_always_uv || opt_rk) {
        return ERR_PUAT_REQUIRED;
    }

    char prompt[80];
    snprintf(prompt, sizeof(prompt), "%.*s", (int)rp_id_len, rp_id);

    uint8_t priv[32];
    for (size_t i = 0; i < nexcl; i++) {
        if (cred_usable(rp_id_hash, excl[i], excl_len[i], priv) && cp_allows(excl[i][0], flags & FLAG_UV, true)) {
            memset(priv, 0, sizeof(priv));
            up_result_t ur = up_wait("Excluded", prompt, UP_TIMEOUT_MS);
            return ur == UP_OK ? ERR_CREDENTIAL_EXCLUDED : up_result_err(ur);
        }
    }

    up_result_t ur = up_wait("Register", prompt, UP_TIMEOUT_MS);
    if (ur != UP_OK) return up_result_err(ur);

    uint8_t cred_id[CRED_ID_LEN];
    uint8_t meta = CRED_META(opt_rk ? CRED_ID_VER_RK : CRED_ID_VER, ext_hmac, ext_cp);
    if (cred_alg == COSE_EDDSA) meta |= CRED_ED25519;
    if (ext_lbk) meta |= CRED_LBK;
    fido_new_cred(rp_id_hash, meta, cred_id, priv);

    if (opt_rk && rk_store(rp_id_hash, cred_id, uid, uid_len, uname, uname_len, dname, dname_len,
                           rp_id, rp_id_len) < 0) {
        memset(priv, 0, sizeof(priv));
        return ERR_KEY_STORE_FULL;
    }

    uint8_t ext[48];
    cbor_w ew;
    cbor_w_init(&ew, ext, sizeof(ext));
    if (ext_cp || ext_hmac) {
        cbor_put_map(&ew, (ext_cp != 0) + ext_hmac);
        if (ext_cp) {
            cbor_put_text(&ew, "credProtect");
            cbor_put_uint(&ew, ext_cp);
        }
        if (ext_hmac) {
            cbor_put_text(&ew, "hmac-secret");
            cbor_put_bool(&ew, true);
        }
    }

    uint8_t ad[300], sig[72];
    uint32_t ctr;
    if (!fido_next_counter(&ctr)) {
        memset(priv, 0, sizeof(priv));
        return ERR_OTHER;
    }
    size_t adlen = build_auth_data(ad, rp_id_hash, flags, ctr, cred_id, priv, ext, ew.len);
    memset(priv, 0, sizeof(priv));
    size_t siglen;
    if (!sign_ad_cdh(fido_att_priv(), ad, adlen, cdh, sig, &siglen)) return ERR_OTHER;

    size_t cert_len;
    const uint8_t *cert = fido_att_cert(&cert_len);
    cbor_put_map(w, ext_lbk ? 4 : 3);
    cbor_put_uint(w, 1);
    cbor_put_text(w, "packed");
    cbor_put_uint(w, 2);
    cbor_put_bytes(w, ad, adlen);
    cbor_put_uint(w, 3);
    cbor_put_map(w, 3);
    cbor_put_text(w, "alg");
    cbor_put_int(w, COSE_ES256);
    cbor_put_text(w, "sig");
    cbor_put_bytes(w, sig, siglen);
    cbor_put_text(w, "x5c");
    cbor_put_array(w, 1);
    cbor_put_bytes(w, cert, cert_len);
    if (ext_lbk) {
        uint8_t lbk[32];
        fido_large_blob_key(cred_id, lbk);
        cbor_put_uint(w, 5);
        cbor_put_bytes(w, lbk, 32);
        memset(lbk, 0, sizeof(lbk));
    }
    return ERR_OK;
}

// ---- authenticatorGetAssertion / GetNextAssertion ----

// Emits one assertion. slot >= 0: resident credential; else cred_id given.
static uint8_t emit_assertion(cbor_w *w, const uint8_t rp_id_hash[32], const uint8_t cdh[32], uint8_t flags,
                              int slot, const uint8_t *cred_id, int total)
{
    if (slot >= 0) {
        if (!rk_load(slot, &s_rk)) return ERR_NO_CREDENTIALS;
        cred_id = s_rk.cred_id;
    }
    uint8_t priv[32];
    if (!fido_open_cred(rp_id_hash, cred_id, CRED_ID_LEN, priv)) return ERR_NO_CREDENTIALS;

    // hmac-secret: outputs = enc(HMAC(CredRandom, salt1) [|| HMAC(CredRandom, salt2)])
    uint8_t ext[128];
    cbor_w ew;
    cbor_w_init(&ew, ext, sizeof(ext));
    if (s_hmac.present && (cred_id[0] & CRED_HMAC)) {
        uint8_t cr[32], out[64], ct[80];
        fido_cred_random(cred_id, flags & FLAG_UV, cr);
        hmac_sha256(cr, 32, s_hmac.salts, 32, out);
        if (s_hmac.salt_len == 64) hmac_sha256(cr, 32, s_hmac.salts + 32, 32, out + 32);
        size_t ctlen = pin_encrypt(s_hmac.proto, s_hmac.shared, out, s_hmac.salt_len, ct);
        memset(cr, 0, sizeof(cr));
        memset(out, 0, sizeof(out));
        cbor_put_map(&ew, 1);
        cbor_put_text(&ew, "hmac-secret");
        cbor_put_bytes(&ew, ct, ctlen);
    }

    uint8_t ad[37 + sizeof(ext)], sig[72];
    uint32_t ctr;
    if (!fido_next_counter(&ctr)) {
        memset(priv, 0, sizeof(priv));
        return ERR_OTHER;
    }
    size_t adlen = build_auth_data(ad, rp_id_hash, flags, ctr, NULL, NULL, ext, ew.len);
    size_t siglen;
    bool ok = sign_cred(cred_id[0], priv, ad, adlen, cdh, sig, &siglen);
    memset(priv, 0, sizeof(priv));
    if (!ok) return ERR_OTHER;

    bool uv = flags & FLAG_UV;
    bool lbk = s_lbk_requested && (cred_id[0] & CRED_LBK);
    cbor_put_map(w, 3 + (slot >= 0) + (total > 1) + lbk);
    cbor_put_uint(w, 1);
    cbor_put_map(w, 2);
    cbor_put_text(w, "id");
    cbor_put_bytes(w, cred_id, CRED_ID_LEN);
    cbor_put_text(w, "type");
    cbor_put_text(w, "public-key");
    cbor_put_uint(w, 2);
    cbor_put_bytes(w, ad, adlen);
    cbor_put_uint(w, 3);
    cbor_put_bytes(w, sig, siglen);
    if (slot >= 0) {
        bool has_name = uv && s_rk.user_name[0], has_dname = uv && s_rk.display_name[0];
        cbor_put_uint(w, 4);
        cbor_put_map(w, 1 + has_name + has_dname);
        cbor_put_text(w, "id");
        cbor_put_bytes(w, s_rk.user_id, s_rk.user_id_len);
        if (has_name) {
            cbor_put_text(w, "name");
            cbor_put_text(w, s_rk.user_name);
        }
        if (has_dname) {
            cbor_put_text(w, "displayName");
            cbor_put_text(w, s_rk.display_name);
        }
    }
    if (total > 1) {
        cbor_put_uint(w, 5);
        cbor_put_uint(w, total);
    }
    if (lbk) {
        uint8_t key[32];
        fido_large_blob_key(cred_id, key);
        cbor_put_uint(w, 7);
        cbor_put_bytes(w, key, 32);
        memset(key, 0, sizeof(key));
    }
    return ERR_OK;
}

static uint8_t get_assertion(cbor_r *r, cbor_w *w)
{
    const uint8_t *cdh = NULL, *pin_param = NULL;
    const char *rp_id = NULL;
    size_t rp_id_len = 0, pin_param_len = 0, len, n, m;
    const uint8_t *allow[MAX_LIST];
    size_t allow_len[MAX_LIST], nallow = 0;
    bool have_allow = false, opt_up = true, opt_uv = false;
    uint64_t proto = 0;
    // hmac-secret input
    uint8_t hs_peer[64];
    const uint8_t *hs_salt = NULL, *hs_auth = NULL;
    size_t hs_salt_len = 0, hs_auth_len = 0;
    uint64_t hs_proto = 1;
    bool hs = false;

    s_hmac.present = false;
    s_lbk_requested = false;
    if (!cbor_get_map(r, &n)) return ERR_INVALID_CBOR;
    for (size_t i = 0; i < n; i++) {
        uint64_t key;
        if (!cbor_get_uint(r, &key)) return ERR_INVALID_CBOR;
        switch (key) {
        case 1:
            if (!cbor_get_text(r, &rp_id, &rp_id_len)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        case 2:
            if (!cbor_get_bytes(r, &cdh, &len)) return ERR_CBOR_UNEXPECTED_TYPE;
            if (len != 32) return ERR_INVALID_LENGTH;
            break;
        case 3:
            if (!cbor_get_array(r, &m)) return ERR_CBOR_UNEXPECTED_TYPE;
            have_allow = m > 0;
            for (size_t j = 0; j < m; j++) {
                const uint8_t *id;
                size_t idl;
                bool is_pk;
                if (!parse_cred_desc(r, &id, &idl, &is_pk)) return ERR_INVALID_CBOR;
                if (is_pk && nallow < MAX_LIST) {
                    allow[nallow] = id;
                    allow_len[nallow++] = idl;
                }
            }
            break;
        case 4:
            if (!cbor_get_map(r, &m)) return ERR_CBOR_UNEXPECTED_TYPE;
            for (size_t j = 0; j < m; j++) {
                if (cbor_text_eq(r, "largeBlobKey")) {
                    if (!cbor_get_bool(r, &s_lbk_requested)) return ERR_CBOR_UNEXPECTED_TYPE;
                    if (!s_lbk_requested) return ERR_INVALID_OPTION;
                    continue;
                }
                if (!cbor_text_eq(r, "hmac-secret")) {
                    if (!cbor_skip(r) || !cbor_skip(r)) return ERR_INVALID_CBOR;
                    continue;
                }
                size_t hm;
                bool have_peer = false;
                if (!cbor_get_map(r, &hm)) return ERR_CBOR_UNEXPECTED_TYPE;
                for (size_t k = 0; k < hm; k++) {
                    uint64_t hk;
                    if (!cbor_get_uint(r, &hk)) return ERR_INVALID_CBOR;
                    if (hk == 1) {
                        if (!parse_cose_key(r, hs_peer)) return ERR_INVALID_PARAMETER;
                        have_peer = true;
                    } else if (hk == 2) {
                        if (!cbor_get_bytes(r, &hs_salt, &hs_salt_len)) return ERR_CBOR_UNEXPECTED_TYPE;
                    } else if (hk == 3) {
                        if (!cbor_get_bytes(r, &hs_auth, &hs_auth_len)) return ERR_CBOR_UNEXPECTED_TYPE;
                    } else if (hk == 4) {
                        if (!cbor_get_uint(r, &hs_proto)) return ERR_CBOR_UNEXPECTED_TYPE;
                    } else if (!cbor_skip(r)) {
                        return ERR_INVALID_CBOR;
                    }
                }
                if (!have_peer || !hs_salt || !hs_auth) return ERR_MISSING_PARAMETER;
                hs = true;
            }
            break;
        case 5:
            if (!cbor_get_map(r, &m)) return ERR_CBOR_UNEXPECTED_TYPE;
            for (size_t j = 0; j < m; j++) {
                bool *opt = cbor_text_eq(r, "up") ? &opt_up : cbor_text_eq(r, "uv") ? &opt_uv : NULL;
                if (opt) {
                    if (!cbor_get_bool(r, opt)) return ERR_CBOR_UNEXPECTED_TYPE;
                } else if (cbor_text_eq(r, "rk")) {
                    return ERR_INVALID_OPTION;
                } else if (!cbor_skip(r) || !cbor_skip(r)) {
                    return ERR_INVALID_CBOR;
                }
            }
            break;
        case 6:
            if (!cbor_get_bytes(r, &pin_param, &pin_param_len)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        case 7:
            if (!cbor_get_uint(r, &proto)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        default:
            if (!cbor_skip(r)) return ERR_INVALID_CBOR;
            break;
        }
    }
    if (!rp_id || !cdh) return ERR_MISSING_PARAMETER;
    if (pin_param && pin_param_len == 0) return select_by_touch();
    if (pin_param && !proto) return ERR_MISSING_PARAMETER;
    if (pin_param && !proto_ok(proto)) return ERR_INVALID_PARAMETER;
    if (opt_uv) return ERR_INVALID_OPTION;

    uint8_t rp_id_hash[32];
    sha256((const uint8_t *)rp_id, rp_id_len, rp_id_hash);

    uint8_t flags = 0;
    if (pin_param) {
        uint8_t e = check_token(proto, pin_param, pin_param_len, cdh, PERM_GA, rp_id_hash);
        if (e) return e;
        flags |= FLAG_UV;
    } else if (s_always_uv) {
        return ERR_PUAT_REQUIRED;
    }

    if (hs) {
        if (!proto_ok(hs_proto)) return ERR_INVALID_PARAMETER;
        s_hmac.proto = hs_proto;
        if (!shared_secret(hs_proto, hs_peer, s_hmac.shared)) return ERR_INVALID_PARAMETER;
        if (!pin_verify_mac(hs_proto, s_hmac.shared, hs_salt, hs_salt_len, hs_auth, hs_auth_len)) {
            return ERR_PIN_AUTH_INVALID;
        }
        if (!pin_decrypt(hs_proto, s_hmac.shared, hs_salt, hs_salt_len, s_hmac.salts, sizeof(s_hmac.salts),
                         &s_hmac.salt_len) ||
            (s_hmac.salt_len != 32 && s_hmac.salt_len != 64)) {
            return ERR_INVALID_LENGTH;
        }
        s_hmac.present = true;
    }

    // Collect matching credentials.
    const uint8_t *found_id = NULL;
    int slots[MAX_LIST], nslots = 0;
    uint8_t priv[32];
    if (have_allow) {
        for (size_t i = 0; i < nallow && !found_id; i++) {
            if (cred_usable(rp_id_hash, allow[i], allow_len[i], priv) && cp_allows(allow[i][0], flags & FLAG_UV, true)) {
                found_id = allow[i];
            }
        }
        memset(priv, 0, sizeof(priv));
        if (!found_id) return ERR_NO_CREDENTIALS;
    } else {
        uint32_t seqs[MAX_LIST];
        for (int i = 0; i < MAX_RK; i++) {
            if (!rk_load(i, &s_rk) || memcmp(s_rk.rp_id_hash, rp_id_hash, 32) != 0) continue;
            if (!cp_allows(s_rk.cred_id[0], flags & FLAG_UV, false)) continue;
            // Insert sorted by seq, newest first.
            int pos = nslots < MAX_LIST ? nslots : MAX_LIST - 1;
            if (nslots == MAX_LIST && s_rk.seq < seqs[pos]) continue;
            while (pos > 0 && seqs[pos - 1] < s_rk.seq) {
                slots[pos] = slots[pos - 1];
                seqs[pos] = seqs[pos - 1];
                pos--;
            }
            slots[pos] = i;
            seqs[pos] = s_rk.seq;
            if (nslots < MAX_LIST) nslots++;
        }
        if (nslots == 0) return ERR_NO_CREDENTIALS;
    }

    if (opt_up) {
        char prompt[80];
        snprintf(prompt, sizeof(prompt), "%.*s", (int)rp_id_len, rp_id);
        up_result_t ur = up_wait("Sign in", prompt, UP_TIMEOUT_MS);
        if (ur != UP_OK) return up_result_err(ur);
        flags |= FLAG_UP;
    }

    if (found_id) return emit_assertion(w, rp_id_hash, cdh, flags, -1, found_id, 1);

    if (nslots > 1) {
        s_next.active = true;
        memcpy(s_next.rp_id_hash, rp_id_hash, 32);
        memcpy(s_next.cdh, cdh, 32);
        s_next.flags = flags;
        memcpy(s_next.slots, slots, sizeof(int) * nslots);
        s_next.count = nslots;
        s_next.pos = 1;
        s_next.ts = esp_timer_get_time();
    }
    return emit_assertion(w, rp_id_hash, cdh, flags, slots[0], NULL, nslots);
}

static uint8_t get_next_assertion(cbor_w *w)
{
    if (!s_next.active || s_next.pos >= s_next.count ||
        esp_timer_get_time() - s_next.ts > NEXT_ASSERTION_US) {
        s_next.active = false;
        return ERR_NOT_ALLOWED;
    }
    s_next.ts = esp_timer_get_time();
    int slot = s_next.slots[s_next.pos++];
    return emit_assertion(w, s_next.rp_id_hash, s_next.cdh, s_next.flags, slot, NULL, 1);
}

// ---- authenticatorClientPIN ----

// On success vpriv gets the vault key (needed to change the PIN).
static uint8_t pin_hash_check(uint8_t proto, const uint8_t shared[64], const uint8_t *enc, size_t enc_len,
                              uint8_t vpriv[32])
{
    if (devpin_tries(DEVPIN_USER) == 0) return ERR_PIN_BLOCKED;
    if (s_pin_fails >= 3) return ERR_PIN_AUTH_BLOCKED;

    uint8_t ph[32];
    size_t phlen;
    if (!pin_decrypt(proto, shared, enc, enc_len, ph, sizeof(ph), &phlen) || phlen != 16) return ERR_PIN_AUTH_INVALID;

    devpin_res_t res = devpin_verify_hash(DEVPIN_USER, ph, vpriv);
    if (res != DEVPIN_OK) {
        regen_key_agreement();
        s_pin_fails++;
        if (res == DEVPIN_BLOCKED) return ERR_PIN_BLOCKED;
        if (res == DEVPIN_ERROR) return ERR_OTHER;
        if (s_pin_fails >= 3) return ERR_PIN_AUTH_BLOCKED;
        return ERR_PIN_INVALID;
    }
    s_pin_fails = 0;
    return ERR_OK;
}

static uint8_t set_new_pin(uint8_t proto, const uint8_t shared[64], const uint8_t *enc, size_t enc_len,
                           const uint8_t vpriv[32])
{
    uint8_t pin[64];
    size_t plen;
    if (!pin_decrypt(proto, shared, enc, enc_len, pin, sizeof(pin), &plen) || plen != 64) return ERR_PIN_AUTH_INVALID;
    size_t n = 0;
    while (n < 64 && pin[n]) n++;
    bool ok = devpin_set(DEVPIN_USER, vpriv, pin, n);
    memset(pin, 0, sizeof(pin));
    if (!ok) return ERR_PIN_POLICY_VIOLATION;
    reset_token();
    return ERR_OK;
}

static uint8_t client_pin(cbor_r *r, cbor_w *w)
{
    uint64_t proto = 0, sub = 0, perms = 0;
    const uint8_t *param = NULL, *new_pin = NULL, *pin_hash = NULL;
    size_t param_len = 0, new_pin_len = 0, pin_hash_len = 0, n;
    const char *rp_id = NULL;
    size_t rp_id_len = 0;
    uint8_t peer[64];
    bool have_peer = false, have_sub = false;

    if (!cbor_get_map(r, &n)) return ERR_INVALID_CBOR;
    for (size_t i = 0; i < n; i++) {
        uint64_t key;
        if (!cbor_get_uint(r, &key)) return ERR_INVALID_CBOR;
        switch (key) {
        case 1:
            if (!cbor_get_uint(r, &proto)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        case 2:
            if (!cbor_get_uint(r, &sub)) return ERR_CBOR_UNEXPECTED_TYPE;
            have_sub = true;
            break;
        case 3:
            if (!parse_cose_key(r, peer)) return ERR_INVALID_PARAMETER;
            have_peer = true;
            break;
        case 4:
            if (!cbor_get_bytes(r, &param, &param_len)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        case 5:
            if (!cbor_get_bytes(r, &new_pin, &new_pin_len)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        case 6:
            if (!cbor_get_bytes(r, &pin_hash, &pin_hash_len)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        case 9:
            if (!cbor_get_uint(r, &perms)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        case 10:
            if (!cbor_get_text(r, &rp_id, &rp_id_len)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        default:
            if (!cbor_skip(r)) return ERR_INVALID_CBOR;
            break;
        }
    }
    if (!have_sub) return ERR_MISSING_PARAMETER;

    if (sub == 0x01) {                          // getPINRetries
        cbor_put_map(w, 2);
        cbor_put_uint(w, 3);
        cbor_put_uint(w, devpin_tries(DEVPIN_USER));
        cbor_put_uint(w, 4);
        cbor_put_bool(w, s_pin_fails >= 3);     // powerCycleState
        return ERR_OK;
    }

    if (!proto) return ERR_MISSING_PARAMETER;
    if (!proto_ok(proto)) return ERR_INVALID_PARAMETER;

    uint8_t shared[64];
    uint8_t e;
    switch (sub) {
    case 0x02:                                  // getKeyAgreement
        cbor_put_map(w, 1);
        cbor_put_uint(w, 1);
        put_cose_key(w, s_ka_pub, -25);         // ECDH-ES+HKDF-256
        return ERR_OK;

    case 0x03:                                  // setPIN
        // The device PIN is always set: only changePIN applies.
        if (!have_peer || !param || !new_pin) return ERR_MISSING_PARAMETER;
        return ERR_NOT_ALLOWED;

    case 0x04: {                                // changePIN
        if (!have_peer || !param || !new_pin || !pin_hash) return ERR_MISSING_PARAMETER;
        if (devpin_tries(DEVPIN_USER) == 0) return ERR_PIN_BLOCKED;
        if (!shared_secret(proto, peer, shared)) return ERR_INVALID_PARAMETER;
        uint8_t msg[80 + 32];                   // protocol 2: IV + 64 bytes, IV + 16 bytes
        if (new_pin_len + pin_hash_len > sizeof(msg)) return ERR_INVALID_LENGTH;
        memcpy(msg, new_pin, new_pin_len);
        memcpy(msg + new_pin_len, pin_hash, pin_hash_len);
        if (!pin_verify_mac(proto, shared, msg, new_pin_len + pin_hash_len, param, param_len)) {
            return ERR_PIN_AUTH_INVALID;
        }
        uint8_t vpriv[32];
        if ((e = pin_hash_check(proto, shared, pin_hash, pin_hash_len, vpriv)) != ERR_OK) return e;
        e = set_new_pin(proto, shared, new_pin, new_pin_len, vpriv);
        memset(vpriv, 0, sizeof(vpriv));
        return e;
    }

    case 0x05:                                  // getPinToken
    case 0x09:                                  // getPinUvAuthTokenUsingPinWithPermissions
        if (!have_peer || !pin_hash) return ERR_MISSING_PARAMETER;
        if (sub == 0x09) {
            if (perms == 0) return ERR_INVALID_PARAMETER;
            if (perms & ~(uint64_t)(PERM_MC | PERM_GA | PERM_CM | PERM_LBW | PERM_ACFG)) {
                return ERR_UNAUTHORIZED_PERMISSION;
            }
        }
        if (!shared_secret(proto, peer, shared)) return ERR_INVALID_PARAMETER;
        {
            uint8_t vpriv[32];
            e = pin_hash_check(proto, shared, pin_hash, pin_hash_len, vpriv);
            memset(vpriv, 0, sizeof(vpriv));
            if (e != ERR_OK) return e;
        }
        if (devpin_is_default(DEVPIN_USER)) return ERR_PIN_POLICY_VIOLATION;     // forcePINChange
        reset_token();
        s_token_valid = true;
        s_token_proto = proto;
        s_token_issued = esp_timer_get_time();
        s_token_pin_gen = devpin_generation();
        // Legacy getPinToken also covers credential management (FIDO_2_1_PRE platforms).
        s_token_perms = sub == 0x05 ? (PERM_MC | PERM_GA | PERM_CM) : (uint8_t)perms;
        if (sub == 0x09 && rp_id) {
            sha256((const uint8_t *)rp_id, rp_id_len, s_token_rp);
            s_token_has_rp = true;
        }
        {
            uint8_t ct[48];
            size_t ctlen = pin_encrypt(proto, shared, s_token, 32, ct);
            cbor_put_map(w, 1);
            cbor_put_uint(w, 2);
            cbor_put_bytes(w, ct, ctlen);
        }
        return ERR_OK;

    default:
        return ERR_INVALID_SUBCOMMAND;
    }
}

// ---- authenticatorCredentialManagement ----

enum { CM_IDLE, CM_RPS, CM_CREDS };

static struct {
    int state;
    int slots[MAX_RK];
    int count, pos;
} s_cm;

static void cm_put_rp(cbor_w *w, int slot, bool with_total, int total)
{
    rk_load(slot, &s_rk);
    cbor_put_map(w, with_total ? 3 : 2);
    cbor_put_uint(w, 3);
    cbor_put_map(w, 1);
    cbor_put_text(w, "id");
    cbor_put_text(w, s_rk.rp_id);
    cbor_put_uint(w, 4);
    cbor_put_bytes(w, s_rk.rp_id_hash, 32);
    if (with_total) {
        cbor_put_uint(w, 5);
        cbor_put_uint(w, total);
    }
}

static uint8_t cm_put_cred(cbor_w *w, int slot, bool with_total, int total)
{
    uint8_t priv[32];
    if (!rk_load(slot, &s_rk) || !fido_open_cred(s_rk.rp_id_hash, s_rk.cred_id, CRED_ID_LEN, priv)) {
        return ERR_OTHER;
    }
    bool has_name = s_rk.user_name[0], has_dname = s_rk.display_name[0];
    cbor_put_map(w, with_total ? 5 : 4);
    cbor_put_uint(w, 6);
    cbor_put_map(w, 1 + has_name + has_dname);
    cbor_put_text(w, "id");
    cbor_put_bytes(w, s_rk.user_id, s_rk.user_id_len);
    if (has_name) {
        cbor_put_text(w, "name");
        cbor_put_text(w, s_rk.user_name);
    }
    if (has_dname) {
        cbor_put_text(w, "displayName");
        cbor_put_text(w, s_rk.display_name);
    }
    cbor_put_uint(w, 7);
    cbor_put_map(w, 2);
    cbor_put_text(w, "id");
    cbor_put_bytes(w, s_rk.cred_id, CRED_ID_LEN);
    cbor_put_text(w, "type");
    cbor_put_text(w, "public-key");
    cbor_put_uint(w, 8);
    put_cred_cose(w, s_rk.cred_id[0], priv);
    memset(priv, 0, sizeof(priv));
    if (with_total) {
        cbor_put_uint(w, 9);
        cbor_put_uint(w, total);
    }
    cbor_put_uint(w, 0x0A);
    cbor_put_uint(w, CRED_CP(s_rk.cred_id[0]) ? CRED_CP(s_rk.cred_id[0]) : 1);
    return ERR_OK;
}

static uint8_t cred_mgmt(cbor_r *r, cbor_w *w)
{
    uint64_t sub = 0, proto = 0;
    const uint8_t *param = NULL, *sp = NULL, *sp_end = NULL;
    size_t param_len = 0, n;
    bool have_sub = false;

    if (!cbor_get_map(r, &n)) return ERR_INVALID_CBOR;
    for (size_t i = 0; i < n; i++) {
        uint64_t key;
        if (!cbor_get_uint(r, &key)) return ERR_INVALID_CBOR;
        switch (key) {
        case 1:
            if (!cbor_get_uint(r, &sub)) return ERR_CBOR_UNEXPECTED_TYPE;
            have_sub = true;
            break;
        case 2:
            if (cbor_peek(r) != CBOR_MAP) return ERR_CBOR_UNEXPECTED_TYPE;
            sp = r->p;
            if (!cbor_skip(r)) return ERR_INVALID_CBOR;
            sp_end = r->p;
            break;
        case 3:
            if (!cbor_get_uint(r, &proto)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        case 4:
            if (!cbor_get_bytes(r, &param, &param_len)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        default:
            if (!cbor_skip(r)) return ERR_INVALID_CBOR;
            break;
        }
    }
    if (!have_sub) return ERR_MISSING_PARAMETER;

    // Continuations of an enumeration need no authentication.
    if (sub == 0x03 || sub == 0x05) {
        if (s_cm.state != (sub == 0x03 ? CM_RPS : CM_CREDS) || s_cm.pos >= s_cm.count) {
            s_cm.state = CM_IDLE;
            return ERR_NOT_ALLOWED;
        }
        int slot = s_cm.slots[s_cm.pos++];
        if (sub == 0x03) {
            cm_put_rp(w, slot, false, 0);
            return ERR_OK;
        }
        return cm_put_cred(w, slot, false, 0);
    }
    s_cm.state = CM_IDLE;

    // Parse subCommandParams: 1 rpIDHash, 2 credentialID, 3 user.
    const uint8_t *rp_hash = NULL, *cid = NULL, *uid = NULL;
    const char *uname = NULL, *dname = NULL;
    size_t cid_len = 0, uid_len = 0, uname_len = 0, dname_len = 0;
    bool have_user = false;
    if (sp) {
        cbor_r pr;
        size_t pm, len;
        cbor_r_init(&pr, sp, sp_end - sp);
        cbor_get_map(&pr, &pm);
        for (size_t i = 0; i < pm; i++) {
            uint64_t key;
            if (!cbor_get_uint(&pr, &key)) return ERR_INVALID_CBOR;
            if (key == 1) {
                if (!cbor_get_bytes(&pr, &rp_hash, &len) || len != 32) return ERR_INVALID_PARAMETER;
            } else if (key == 2) {
                bool is_pk;
                if (!parse_cred_desc(&pr, &cid, &cid_len, &is_pk)) return ERR_INVALID_CBOR;
            } else if (key == 3) {
                size_t um;
                if (!cbor_get_map(&pr, &um)) return ERR_CBOR_UNEXPECTED_TYPE;
                have_user = true;
                for (size_t j = 0; j < um; j++) {
                    if (cbor_text_eq(&pr, "id")) {
                        if (!cbor_get_bytes(&pr, &uid, &uid_len)) return ERR_CBOR_UNEXPECTED_TYPE;
                    } else if (cbor_text_eq(&pr, "name")) {
                        if (!cbor_get_text(&pr, &uname, &uname_len)) return ERR_CBOR_UNEXPECTED_TYPE;
                    } else if (cbor_text_eq(&pr, "displayName")) {
                        if (!cbor_get_text(&pr, &dname, &dname_len)) return ERR_CBOR_UNEXPECTED_TYPE;
                    } else if (!cbor_skip(&pr) || !cbor_skip(&pr)) {
                        return ERR_INVALID_CBOR;
                    }
                }
            } else if (!cbor_skip(&pr)) {
                return ERR_INVALID_CBOR;
            }
        }
    }

    // pinUvAuthParam = authenticate(token, subCommand || subCommandParams)
    if (!param) return ERR_PUAT_REQUIRED;
    if (!proto) return ERR_MISSING_PARAMETER;
    if (!proto_ok(proto)) return ERR_INVALID_PARAMETER;
    uint8_t msg[1 + 512];
    size_t sp_len = sp ? (size_t)(sp_end - sp) : 0;
    if (sp_len > sizeof(msg) - 1) return ERR_INVALID_LENGTH;
    msg[0] = (uint8_t)sub;
    if (sp_len) memcpy(msg + 1, sp, sp_len);
    if (!token_mac_ok(proto, msg, 1 + sp_len, param, param_len)) return ERR_PIN_AUTH_INVALID;
    if (!(s_token_perms & PERM_CM)) return ERR_PIN_AUTH_INVALID;

    switch (sub) {
    case 0x01: {                                // getCredsMetadata
        if (s_token_has_rp) return ERR_PIN_AUTH_INVALID;
        int used = 0;
        for (int i = 0; i < MAX_RK; i++) used += rk_load(i, &s_rk);
        cbor_put_map(w, 2);
        cbor_put_uint(w, 1);
        cbor_put_uint(w, used);
        cbor_put_uint(w, 2);
        cbor_put_uint(w, MAX_RK - used);
        return ERR_OK;
    }
    case 0x02: {                                // enumerateRPsBegin
        if (s_token_has_rp) return ERR_PIN_AUTH_INVALID;
        static uint8_t seen[MAX_RK][32];   // 3.2 KB, off the worker stack
        s_cm.count = 0;
        for (int i = 0; i < MAX_RK; i++) {
            if (!rk_load(i, &s_rk)) continue;
            bool dup = false;
            for (int j = 0; j < s_cm.count && !dup; j++) dup = memcmp(seen[j], s_rk.rp_id_hash, 32) == 0;
            if (dup) continue;
            memcpy(seen[s_cm.count], s_rk.rp_id_hash, 32);
            s_cm.slots[s_cm.count++] = i;
        }
        if (s_cm.count == 0) return ERR_NO_CREDENTIALS;
        s_cm.state = CM_RPS;
        s_cm.pos = 1;
        cm_put_rp(w, s_cm.slots[0], true, s_cm.count);
        return ERR_OK;
    }
    case 0x04:                                  // enumerateCredentialsBegin
        if (!rp_hash) return ERR_MISSING_PARAMETER;
        if (s_token_has_rp && memcmp(s_token_rp, rp_hash, 32) != 0) return ERR_PIN_AUTH_INVALID;
        s_cm.count = 0;
        for (int i = 0; i < MAX_RK; i++) {
            if (rk_load(i, &s_rk) && memcmp(s_rk.rp_id_hash, rp_hash, 32) == 0) s_cm.slots[s_cm.count++] = i;
        }
        if (s_cm.count == 0) return ERR_NO_CREDENTIALS;
        s_cm.state = CM_CREDS;
        s_cm.pos = 1;
        return cm_put_cred(w, s_cm.slots[0], true, s_cm.count);

    case 0x06:                                  // deleteCredential
    case 0x07: {                                // updateUserInformation
        if (!cid) return ERR_MISSING_PARAMETER;
        int slot = rk_find_id(cid, cid_len);
        if (slot < 0) return ERR_NO_CREDENTIALS;
        if (s_token_has_rp && memcmp(s_token_rp, s_rk.rp_id_hash, 32) != 0) return ERR_PIN_AUTH_INVALID;
        char k[8];
        rk_key(slot, k);
        if (sub == 0x06) return store_del(NS_FIDO, k) == ESP_OK ? ERR_OK : ERR_OTHER;
        if (!have_user || !uid) return ERR_MISSING_PARAMETER;
        if (uid_len != s_rk.user_id_len || memcmp(uid, s_rk.user_id, uid_len) != 0) return ERR_INVALID_PARAMETER;
        s_rk.user_name[0] = s_rk.display_name[0] = 0;
        if (uname) copy_text(s_rk.user_name, sizeof(s_rk.user_name), uname, uname_len);
        if (dname) copy_text(s_rk.display_name, sizeof(s_rk.display_name), dname, dname_len);
        return store_set(NS_FIDO, k, &s_rk, sizeof(s_rk)) == ESP_OK ? ERR_OK : ERR_OTHER;
    }
    default:
        return ERR_INVALID_SUBCOMMAND;
    }
}

// ---- authenticatorReset / Selection ----

// ---- authenticatorLargeBlobs ----

// Stored serialized array; empty array (0x80 || LEFT(SHA-256(0x80), 16)) when unset.
static size_t lb_load(uint8_t *buf)
{
    size_t n = LB_MAX;
    if (store_get(NS_FIDO, "lblob", buf, &n) == ESP_OK) return n;
    buf[0] = 0x80;
    uint8_t h[32];
    sha256(buf, 1, h);
    memcpy(buf + 1, h, 16);
    return 17;
}

static uint8_t large_blobs(cbor_r *r, cbor_w *w)
{
    uint64_t get = 0, offset = 0, length = 0, proto = 0;
    const uint8_t *set = NULL, *pin_param = NULL;
    size_t set_len = 0, pin_param_len = 0, n;
    bool have_get = false, have_offset = false, have_length = false;

    if (!cbor_get_map(r, &n)) return ERR_INVALID_CBOR;
    for (size_t i = 0; i < n; i++) {
        uint64_t key;
        if (!cbor_get_uint(r, &key)) return ERR_INVALID_CBOR;
        bool ok = true;
        switch (key) {
        case 1: ok = cbor_get_uint(r, &get); have_get = true; break;
        case 2: ok = cbor_get_bytes(r, &set, &set_len); break;
        case 3: ok = cbor_get_uint(r, &offset); have_offset = true; break;
        case 4: ok = cbor_get_uint(r, &length); have_length = true; break;
        case 5: ok = cbor_get_bytes(r, &pin_param, &pin_param_len); break;
        case 6: ok = cbor_get_uint(r, &proto); break;
        default: ok = cbor_skip(r); break;
        }
        if (!ok) return ERR_CBOR_UNEXPECTED_TYPE;
    }
    if (!have_offset) return ERR_MISSING_PARAMETER;
    if (have_get == (set != NULL)) return ERR_INVALID_PARAMETER;

    if (have_get) {
        if (have_length) return ERR_INVALID_PARAMETER;
        if (get > LB_FRAGMENT) return ERR_INVALID_LENGTH;
        size_t len = lb_load(s_lb_buf);
        s_lb_expected = 0;                      // the buffer is shared with writes
        if (offset > len) return ERR_INVALID_PARAMETER;
        size_t out = len - offset < get ? len - offset : get;
        cbor_put_map(w, 1);
        cbor_put_uint(w, 1);
        cbor_put_bytes(w, s_lb_buf + offset, out);
        return ERR_OK;
    }

    if (set_len > LB_FRAGMENT) return ERR_INVALID_LENGTH;
    if (offset == 0) {
        if (!have_length) return ERR_INVALID_PARAMETER;
        if (length > LB_MAX) return ERR_LARGE_BLOB_STORAGE_FULL;
        if (length < 17) return ERR_INVALID_PARAMETER;
    } else {
        if (have_length) return ERR_INVALID_PARAMETER;
        if (!s_lb_expected || offset != s_lb_off) return ERR_INVALID_SEQ;
    }
    if (!pin_param) return ERR_PUAT_REQUIRED;
    if (!proto) return ERR_MISSING_PARAMETER;
    if (!proto_ok(proto)) return ERR_INVALID_PARAMETER;
    // 32 x 0xFF || 0x0C 0x00 || uint32LE(offset) || SHA-256(set)
    uint8_t msg[32 + 2 + 4 + 32];
    memset(msg, 0xFF, 32);
    msg[32] = CMD_LARGE_BLOBS;
    msg[33] = 0x00;
    for (int i = 0; i < 4; i++) msg[34 + i] = (uint8_t)(offset >> (8 * i));
    sha256(set, set_len, msg + 38);
    if (!token_mac_ok(proto, msg, sizeof(msg), pin_param, pin_param_len)) return ERR_PIN_AUTH_INVALID;
    if (!(s_token_perms & PERM_LBW)) return ERR_PIN_AUTH_INVALID;
    // Only an authorized write may start a new upload.
    if (offset == 0) {
        s_lb_expected = length;
        s_lb_off = 0;
    }
    if (offset + set_len > s_lb_expected) return ERR_INVALID_PARAMETER;
    memcpy(s_lb_buf + offset, set, set_len);
    s_lb_off += set_len;
    if (s_lb_off < s_lb_expected) return ERR_OK;

    // Complete: the array ends with LEFT(SHA-256(array), 16).
    size_t len = s_lb_expected;
    uint8_t h[32];
    s_lb_expected = 0;
    sha256(s_lb_buf, len - 16, h);
    if (!ct_equal(h, s_lb_buf + len - 16, 16)) return ERR_INTEGRITY_FAILURE;
    return store_set(NS_FIDO, "lblob", s_lb_buf, len) == ESP_OK ? ERR_OK : ERR_LARGE_BLOB_STORAGE_FULL;
}

// ---- authenticatorConfig ----

static uint8_t authnr_config(cbor_r *r)
{
    uint64_t sub = 0, proto = 0;
    const uint8_t *params = NULL, *pin_param = NULL;
    size_t params_len = 0, pin_param_len = 0, n;

    if (!cbor_get_map(r, &n)) return ERR_INVALID_CBOR;
    for (size_t i = 0; i < n; i++) {
        uint64_t key;
        if (!cbor_get_uint(r, &key)) return ERR_INVALID_CBOR;
        switch (key) {
        case 1:
            if (!cbor_get_uint(r, &sub)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        case 2:                                 // subCommandParams: raw bytes go into the MAC
            params = r->p;
            if (!cbor_skip(r)) return ERR_INVALID_CBOR;
            params_len = r->p - params;
            break;
        case 3:
            if (!cbor_get_uint(r, &proto)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        case 4:
            if (!cbor_get_bytes(r, &pin_param, &pin_param_len)) return ERR_CBOR_UNEXPECTED_TYPE;
            break;
        default:
            if (!cbor_skip(r)) return ERR_INVALID_CBOR;
            break;
        }
    }
    if (!sub) return ERR_MISSING_PARAMETER;

    if (!pin_param) return ERR_PUAT_REQUIRED;
    if (!proto) return ERR_MISSING_PARAMETER;
    if (!proto_ok(proto)) return ERR_INVALID_PARAMETER;
    // 32 x 0xFF || 0x0D || subCommand || subCommandParams
    uint8_t msg[32 + 2 + 64];
    if (params_len > 64) return ERR_INVALID_LENGTH;
    memset(msg, 0xFF, 32);
    msg[32] = CMD_CONFIG;
    msg[33] = (uint8_t)sub;
    if (params_len) memcpy(msg + 34, params, params_len);
    if (!token_mac_ok(proto, msg, 34 + params_len, pin_param, pin_param_len)) return ERR_PIN_AUTH_INVALID;
    if (!(s_token_perms & PERM_ACFG)) return ERR_PIN_AUTH_INVALID;

    switch (sub) {
    case 0x02: {                                // toggleAlwaysUv
        uint8_t v = !s_always_uv;
        if (store_set(NS_FIDO, "alwaysuv", &v, 1) != ESP_OK) return ERR_OTHER;
        s_always_uv = v;
        return ERR_OK;
    }
    default:
        return ERR_INVALID_SUBCOMMAND;
    }
}

bool ctap2_always_uv(void)
{
    if (!s_initialized) ctap2_init();
    return s_always_uv;
}

static uint8_t do_reset(void)
{
    if (esp_timer_get_time() > RESET_WINDOW_US) return ERR_NOT_ALLOWED;
    up_result_t ur = up_wait("Reset FIDO?", "All passkeys will be erased", UP_TIMEOUT_MS);
    if (ur != UP_OK) return up_result_err(ur);
    fido_reset();
    s_pin_fails = 0;
    s_always_uv = false;
    s_lb_expected = 0;
    regen_key_agreement();
    reset_token();
    s_next.active = false;
    return ERR_OK;
}

size_t ctap2_process(const uint8_t *req, size_t len, uint8_t *resp, size_t cap)
{
    if (!s_initialized) ctap2_init();

    cbor_r r;
    cbor_w w;
    cbor_r_init(&r, req + 1, len - 1);
    cbor_w_init(&w, resp + 1, cap - 1);
    uint8_t cmd = req[0];
    uint8_t status;

    if (cmd != CMD_GET_NEXT_ASSERTION) s_next.active = false;
    if (cmd != CMD_CRED_MGMT && cmd != CMD_CRED_MGMT_PRE) s_cm.state = CM_IDLE;

    switch (cmd) {
    case CMD_GET_INFO:
        status = get_info(&w);
        break;
    case CMD_MAKE_CREDENTIAL:
        status = make_credential(&r, &w);
        break;
    case CMD_GET_ASSERTION:
        status = get_assertion(&r, &w);
        break;
    case CMD_GET_NEXT_ASSERTION:
        status = get_next_assertion(&w);
        break;
    case CMD_CLIENT_PIN:
        status = client_pin(&r, &w);
        break;
    case CMD_RESET:
        status = do_reset();
        break;
    case CMD_CRED_MGMT:
    case CMD_CRED_MGMT_PRE:
        status = cred_mgmt(&r, &w);
        break;
    case CMD_LARGE_BLOBS:
        status = large_blobs(&r, &w);
        break;
    case CMD_CONFIG:
        status = authnr_config(&r);
        break;
    case CMD_SELECTION: {
        up_result_t ur = up_wait("Select", "Press to use this key", UP_TIMEOUT_MS);
        status = ur == UP_OK ? ERR_OK : up_result_err(ur);
        break;
    }
    default:
        status = ERR_INVALID_COMMAND;
        break;
    }

    if (status == ERR_OK && w.err) status = ERR_OTHER;
    resp[0] = status;
    return status == ERR_OK ? 1 + w.len : 1;
}

// PIV application (NIST SP 800-73-4 subset + common Yubico extensions):
// RSA-2048 and P-256 keys in slots 9A/9C/9D/9E, PIN/PUK, management key (3DES/AES), data objects,
// touch policy per key and GET METADATA.
#include "apps.h"
#include "core/crypto.h"
#include "core/devpin.h"
#include "core/up.h"
#include "core/vault.h"
#include "core/store.h"
#include <stdio.h>
#include <string.h>
#include "esp_mac.h"
#include "esp_timer.h"
#include "mbedtls/des.h"
#include "mbedtls/aes.h"
#include "mbedtls/rsa.h"

#define INS_VERIFY          0x20
#define INS_CHANGE_REF      0x24
#define INS_RESET_RETRY     0x2C
#define INS_GENERATE        0x47
#define INS_GENERAL_AUTH    0x87
#define INS_GET_DATA        0xCB
#define INS_PUT_DATA        0xDB
#define INS_YK_SET_MGMKEY   0xFF
#define INS_YK_RESET        0xFB
#define INS_YK_GET_VERSION  0xFD
#define INS_YK_GET_SERIAL   0xF8
#define INS_YK_GET_METADATA 0xF7

#define ALG_3DES    0x03
#define ALG_AES128  0x08
#define ALG_AES192  0x0A
#define ALG_AES256  0x0C
#define ALG_RSA2048 0x07
#define ALG_ECC256  0x11

#define KEY_MGMT    0x9B
#define PIN_REF     0x80
#define PUK_REF     0x81
#define OBJ_MAX     2048

#define PIN_POLICY_NEVER    0x01
#define PIN_POLICY_ONCE     0x02
#define PIN_POLICY_ALWAYS   0x03
#define TOUCH_POLICY_NEVER  0x01
#define TOUCH_POLICY_ALWAYS 0x02
#define TOUCH_POLICY_CACHED 0x03
#define TOUCH_CACHE_US      (15 * 1000000LL)
#define ORIGIN_GENERATED    0x01

// PIN and PUK are the device user and admin PINs (core/devpin).
typedef struct {
    uint8_t mgmt_alg;
    uint8_t mgmt_key[32];
} piv_state_t;

static const uint8_t s_aid[] = {0xA0, 0x00, 0x00, 0x03, 0x08};
static const uint8_t s_pix[] = {0x00, 0x00, 0x10, 0x00, 0x01, 0x00};
static const uint8_t s_default_mgmt[24] = {
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
};
static const uint8_t s_discovery[] = {
    0x7E, 0x12, 0x4F, 0x0B, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
    0x5F, 0x2F, 0x02, 0x40, 0x00,
};

static piv_state_t s_st;
static bool s_pin_ok, s_mgmt_ok;
static bool s_pin_9c;              // PIN verified and not yet used by 9C (PIN policy "always")
static uint8_t s_vpriv[32];        // valid while s_pin_ok
static uint32_t s_vault_gen;        // devpin_vault_generation() of s_vpriv
static uint8_t s_witness[16], s_challenge[16];
static bool s_have_witness, s_have_challenge;
static uint8_t s_obj[OBJ_MAX + 8];
static int64_t s_touched[4];       // last press per key slot, for the cached touch policy

// ---- state ----

static void save(void)
{
    store_set(NS_PIV, "state", &s_st, sizeof(s_st));
}

static void set_pin_ok(bool ok)
{
    s_pin_ok = s_pin_9c = ok;
    if (!ok) memset(s_vpriv, 0, sizeof(s_vpriv));
}

static void obj_name(uint32_t tag, char *k)
{
    snprintf(k, 12, "o%06X", (unsigned)tag);
}

static void make_default_objects(void)
{
    char k[12];
    uint8_t guid[16];
    crypto_random(guid, sizeof(guid));
    // CHUID: FASC-N (dummy), GUID, expiration, empty signature.
    uint8_t chuid[] = {
        0x53, 0x3B,
        0x30, 0x19, 0xD4, 0xE7, 0x39, 0xDA, 0x73, 0x9C, 0xED, 0x39, 0xCE, 0x73, 0x9D, 0x83, 0x68,
        0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xC8, 0x42, 0x10, 0xC3, 0xEB,
        0x34, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x35, 0x08, '2', '0', '9', '9', '1', '2', '3', '1',
        0x3E, 0x00,
        0xFE, 0x00,
    };
    memcpy(chuid + 2 + 27 + 2, guid, 16);
    obj_name(0x5FC102, k);
    store_set(NS_PIV, k, chuid, sizeof(chuid));
}

static void set_defaults(void)
{
    memset(&s_st, 0, sizeof(s_st));
    s_st.mgmt_alg = ALG_3DES;
    memcpy(s_st.mgmt_key, s_default_mgmt, 24);
    save();
    make_default_objects();
}

static void load(void)
{
    if (!store_read(NS_PIV, "state", &s_st, sizeof(s_st))) {
        // Fresh card, or data from an older storage format: start over.
        store_erase_ns(NS_PIV);
        set_defaults();
    }
}

// ---- management key cipher ----

static size_t mgmt_block(void)
{
    return s_st.mgmt_alg == ALG_3DES ? 8 : 16;
}

static size_t mgmt_key_len(uint8_t alg)
{
    switch (alg) {
    case ALG_3DES:   return 24;
    case ALG_AES128: return 16;
    case ALG_AES192: return 24;
    case ALG_AES256: return 32;
    default:         return 0;
    }
}

static void mgmt_crypt(bool enc, const uint8_t *in, uint8_t *out)
{
    if (s_st.mgmt_alg == ALG_3DES) {
        mbedtls_des3_context ctx;
        mbedtls_des3_init(&ctx);
        if (enc) mbedtls_des3_set3key_enc(&ctx, s_st.mgmt_key);
        else mbedtls_des3_set3key_dec(&ctx, s_st.mgmt_key);
        mbedtls_des3_crypt_ecb(&ctx, in, out);
        mbedtls_des3_free(&ctx);
    } else {
        mbedtls_aes_context ctx;
        unsigned bits = mgmt_key_len(s_st.mgmt_alg) * 8;
        mbedtls_aes_init(&ctx);
        if (enc) mbedtls_aes_setkey_enc(&ctx, s_st.mgmt_key, bits);
        else mbedtls_aes_setkey_dec(&ctx, s_st.mgmt_key, bits);
        mbedtls_aes_crypt_ecb(&ctx, enc ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, in, out);
        mbedtls_aes_free(&ctx);
    }
}

// ---- PIN ----

// PIN and PUK come as 8 bytes padded with 0xFF; returns the length without
// padding, or 0 if the format is wrong.
static size_t pin_len(const uint8_t *p)
{
    size_t n = 0;
    while (n < 8 && p[n] != 0xFF) n++;
    for (size_t i = n; i < 8; i++) if (p[i] != 0xFF) return 0;
    return n;
}

// On success vpriv gets the vault key.
static uint16_t pin_check(int who, const uint8_t *pin, uint8_t vpriv[32])
{
    switch (devpin_verify(who, pin, pin_len(pin), vpriv)) {
    case DEVPIN_OK:      return SW_OK;
    case DEVPIN_WRONG:   return SW_VERIFY_FAIL(devpin_tries(who));
    case DEVPIN_BLOCKED: return SW_AUTH_BLOCKED;
    default:             return SW_UNKNOWN;
    }
}

static uint16_t do_verify(const apdu_t *a)
{
    if (a->p2 != PIN_REF) return SW_REF_NOT_FOUND;
    if (a->p1 == 0xFF) {
        set_pin_ok(false);
        return SW_OK;
    }
    if (a->lc == 0) {
        if (s_pin_ok) return SW_OK;
        uint8_t t = devpin_tries(DEVPIN_USER);
        return t ? SW_VERIFY_FAIL(t) : SW_AUTH_BLOCKED;
    }
    if (a->lc != 8) return SW_WRONG_LENGTH;
    uint16_t sw = pin_check(DEVPIN_USER, a->data, s_vpriv);
    set_pin_ok(sw == SW_OK);
    s_vault_gen = devpin_vault_generation();
    return sw;
}

// Verifies the first 8 bytes as `check`, then sets the next 8 as `set`.
static uint16_t replace_pin(int check, int set, const uint8_t *data)
{
    uint8_t vpriv[32];
    uint16_t sw = pin_check(check, data, vpriv);
    if (sw != SW_OK) return sw;
    if (!devpin_set(set, vpriv, data + 8, pin_len(data + 8))) sw = SW_WRONG_DATA;
    memset(vpriv, 0, sizeof(vpriv));
    return sw;
}

static uint16_t do_change_ref(const apdu_t *a)
{
    if (a->lc != 16) return SW_WRONG_LENGTH;
    if (a->p2 == PIN_REF) return replace_pin(DEVPIN_USER, DEVPIN_USER, a->data);
    if (a->p2 == PUK_REF) return replace_pin(DEVPIN_ADMIN, DEVPIN_ADMIN, a->data);
    return SW_REF_NOT_FOUND;
}

static uint16_t do_reset_retry(const apdu_t *a)
{
    if (a->p2 != PIN_REF) return SW_REF_NOT_FOUND;
    if (a->lc != 16) return SW_WRONG_LENGTH;
    return replace_pin(DEVPIN_ADMIN, DEVPIN_USER, a->data);
}

// ---- data objects ----

static bool parse_obj_tag(const uint8_t *d, size_t len, uint32_t *tag, const uint8_t **rest, size_t *rest_len)
{
    if (len < 2 || d[0] != 0x5C || d[1] > 3 || len < 2u + d[1]) return false;
    *tag = 0;
    for (int i = 0; i < d[1]; i++) *tag = (*tag << 8) | d[2 + i];
    *rest = d + 2 + d[1];
    *rest_len = len - 2 - d[1];
    return true;
}

// SP 800-73-4: fingerprints, printed information, facial image and iris are
// read only after the PIN. ykman keeps a PIN-protected management key in
// printed information (5FC109).
static bool obj_needs_pin(uint32_t tag)
{
    return tag == 0x5FC103 || tag == 0x5FC108 || tag == 0x5FC109 || tag == 0x5FC121;
}

static uint16_t do_get_data(const apdu_t *a, rbuf_t *r)
{
    if (a->p1 != 0x3F || a->p2 != 0xFF) return SW_INCORRECT_P1P2;
    uint32_t tag;
    const uint8_t *rest;
    size_t rest_len;
    if (!parse_obj_tag(a->data, a->lc, &tag, &rest, &rest_len)) return SW_WRONG_DATA;
    if (tag == 0x7E) {
        rb_put(r, s_discovery, sizeof(s_discovery));
        return SW_OK;
    }
    if (obj_needs_pin(tag) && !s_pin_ok) return SW_SECURITY_NOT_SATISFIED;
    char k[12];
    size_t n = sizeof(s_obj);
    obj_name(tag, k);
    if (store_get(NS_PIV, k, s_obj, &n) != ESP_OK) return SW_FILE_NOT_FOUND;
    rb_put(r, s_obj, n);
    return SW_OK;
}

// Writable objects: the SP 800-73-4 range 5FC101-5FC123 and the Yubico range
// 5FFF00-5FFF0F (ykman's PIVMAN data). The bound keeps PUT DATA from filling
// the flash that the PIN retry counters need.
static bool obj_writable(uint32_t tag)
{
    return (tag >= 0x5FC101 && tag <= 0x5FC123) || (tag >= 0x5FFF00 && tag <= 0x5FFF0F);
}

static uint16_t do_put_data(const apdu_t *a)
{
    if (a->p1 != 0x3F || a->p2 != 0xFF) return SW_INCORRECT_P1P2;
    if (!s_mgmt_ok) return SW_SECURITY_NOT_SATISFIED;
    uint32_t tag;
    const uint8_t *rest;
    size_t rest_len;
    if (!parse_obj_tag(a->data, a->lc, &tag, &rest, &rest_len)) return SW_WRONG_DATA;
    if (!obj_writable(tag)) return SW_FILE_NOT_FOUND;
    if (rest_len < 2 || rest[0] != 0x53 || rest_len > OBJ_MAX) return SW_WRONG_DATA;
    char k[12];
    obj_name(tag, k);
    // "53 00" deletes the object.
    if (rest_len == 2 && rest[1] == 0) return store_del(NS_PIV, k) == ESP_OK ? SW_OK : SW_UNKNOWN;
    return store_set(NS_PIV, k, rest, rest_len) == ESP_OK ? SW_OK : SW_NOT_ENOUGH_SPACE;
}

// ---- keys ----

// RSA private key as stored: p || q || e (big endian). P-256 keys are the
// 32-byte scalar; the stored length tells the two apart.
typedef struct {
    uint8_t p[128], q[128], e[4];
} rsa_blob_t;

static bool slot_valid(uint8_t slot)
{
    return slot == 0x9A || slot == 0x9C || slot == 0x9D || slot == 0x9E;
}

static void key_name(uint8_t slot, char *k)
{
    snprintf(k, 8, "k%02x", slot);
}

static int slot_index(uint8_t slot)
{
    switch (slot) {
    case 0x9A: return 0;
    case 0x9C: return 1;
    case 0x9D: return 2;
    default:   return 3;
    }
}

// Fixed per slot: 9C asks for the PIN before every use, 9E never.
static uint8_t pin_policy(uint8_t slot)
{
    if (slot == 0x9C) return PIN_POLICY_ALWAYS;
    if (slot == 0x9E) return PIN_POLICY_NEVER;
    return PIN_POLICY_ONCE;
}

// Key metadata kept in the clear next to the key for GET METADATA: "m<slot>" =
// algorithm || touch policy, "p<slot>" = public key (contents of 7F49). The
// touch policy that is enforced is the copy stored with the key itself.
typedef struct {
    uint8_t alg, touch;
} key_meta_t;

static bool meta_load(uint8_t slot, key_meta_t *m)
{
    char k[8];
    snprintf(k, sizeof(k), "m%02x", slot);
    return store_read(NS_PIV, k, m, sizeof(*m));
}

// Stores the metadata and answers GENERATE with the public key.
static uint16_t finish_generate(uint8_t slot, uint8_t alg, uint8_t touch, const uint8_t *pub, size_t len, rbuf_t *r)
{
    char k[8];
    key_meta_t m = {alg, touch};
    snprintf(k, sizeof(k), "p%02x", slot);
    if (store_set(NS_PIV, k, pub, len) != ESP_OK) return SW_NOT_ENOUGH_SPACE;
    k[0] = 'm';
    if (store_set(NS_PIV, k, &m, sizeof(m)) != ESP_OK) return SW_NOT_ENOUGH_SPACE;
    s_touched[slot_index(slot)] = 0;
    rb_tlv(r, 0x7F49, pub, len);
    return SW_OK;
}

static bool touch_confirm(uint8_t slot, uint8_t touch)
{
    if (touch != TOUCH_POLICY_ALWAYS && touch != TOUCH_POLICY_CACHED) return true;
    int64_t *t = &s_touched[slot_index(slot)];
    if (touch == TOUCH_POLICY_CACHED && *t && esp_timer_get_time() - *t < TOUCH_CACHE_US) return true;
    char label[12];
    snprintf(label, sizeof(label), "Slot %02X", slot);
    if (up_wait("Use PIV key?", label, 30000) != UP_OK) return false;
    *t = esp_timer_get_time();
    return true;
}

// Keys are sealed to the vault, except 9E (card authentication): it is used
// without a PIN, so it is stored in the clear. The touch policy is stored
// as a last byte with the key, so both are written in one go.
static bool key_save(uint8_t slot, const void *priv, size_t len, uint8_t touch)
{
    char k[8];
    uint8_t plain[sizeof(rsa_blob_t) + 1], blob[sizeof(plain) + VAULT_OVERHEAD];
    key_name(slot, k);
    memcpy(plain, priv, len);
    plain[len] = touch;
    bool ok;
    if (slot == 0x9E) {
        ok = store_set(NS_PIV, k, plain, len + 1) == ESP_OK;
    } else {
        size_t n = vault_seal(devpin_vpub(), plain, len + 1, blob);
        ok = n && store_set(NS_PIV, k, blob, n) == ESP_OK;
    }
    memset(plain, 0, sizeof(plain));
    return ok;
}

// priv must hold sizeof(rsa_blob_t) + 1; *alg gets the key's algorithm and
// *touch its touch policy (never for keys stored without one).
static bool key_load(uint8_t slot, uint8_t *priv, uint8_t *alg, uint8_t *touch)
{
    char k[8];
    uint8_t blob[sizeof(rsa_blob_t) + 1 + VAULT_OVERHEAD];
    size_t n = sizeof(blob), len;
    key_name(slot, k);
    if (slot == 0x9E) {
        len = sizeof(rsa_blob_t) + 1;
        if (store_get(NS_PIV, k, priv, &len) != ESP_OK) return false;
    } else if (!s_pin_ok || store_get(NS_PIV, k, blob, &n) != ESP_OK || !vault_open(s_vpriv, blob, n, priv, &len)) {
        return false;
    }
    *touch = TOUCH_POLICY_NEVER;
    if (len == 33 || len == sizeof(rsa_blob_t) + 1) *touch = priv[--len];
    if (len == 32) *alg = ALG_ECC256;
    else if (len == sizeof(rsa_blob_t)) *alg = ALG_RSA2048;
    else return false;
    return true;
}

static uint16_t gen_rsa(uint8_t slot, uint8_t touch, rbuf_t *r)
{
    mbedtls_rsa_context rsa;
    rsa_blob_t b;
    uint8_t n[256];
    mbedtls_rsa_init(&rsa);
    int rc = mbedtls_rsa_gen_key(&rsa, crypto_rng, NULL, 2048, 65537);
    if (rc == 0) rc = mbedtls_rsa_export_raw(&rsa, n, 256, b.p, 128, b.q, 128, NULL, 0, b.e, 4);
    mbedtls_rsa_free(&rsa);
    bool ok = rc == 0 && key_save(slot, &b, sizeof(b), touch);
    memset(&b, 0, sizeof(b));
    if (!ok) return rc ? SW_UNKNOWN : SW_NOT_ENOUGH_SPACE;

    static const uint8_t e[] = {0x01, 0x00, 0x01};
    uint8_t inner[4 + 256 + 2 + 3];
    rbuf_t in = {.data = inner, .cap = sizeof(inner)};
    rb_tlv(&in, 0x81, n, 256);
    rb_tlv(&in, 0x82, e, sizeof(e));
    return finish_generate(slot, ALG_RSA2048, touch, inner, in.len, r);
}

static uint16_t do_generate(const apdu_t *a, rbuf_t *r)
{
    if (!s_mgmt_ok) return SW_SECURITY_NOT_SATISFIED;
    if (devpin_any_default()) return SW_CONDITIONS_NOT_SATISFIED;
    if (!slot_valid(a->p2)) return SW_INCORRECT_P1P2;
    size_t lac, l80, laa, lab;
    const uint8_t *ac = tlv_find(a->data, a->lc, 0xAC, &lac);
    const uint8_t *alg = ac ? tlv_find(ac, lac, 0x80, &l80) : NULL;
    if (!alg || l80 != 1) return SW_WRONG_DATA;
    // The PIN policy is fixed per slot; only "default" or the same value passes.
    const uint8_t *pp = tlv_find(ac, lac, 0xAA, &laa);
    if (pp && (laa != 1 || (pp[0] && pp[0] != pin_policy(a->p2)))) return SW_FUNC_NOT_SUPPORTED;
    const uint8_t *tp = tlv_find(ac, lac, 0xAB, &lab);
    if (tp && (lab != 1 || tp[0] > TOUCH_POLICY_CACHED)) return SW_WRONG_DATA;
    uint8_t touch = tp && tp[0] ? tp[0] : TOUCH_POLICY_NEVER;
    if (alg[0] == ALG_RSA2048) return gen_rsa(a->p2, touch, r);
    if (alg[0] != ALG_ECC256) return SW_FUNC_NOT_SUPPORTED;

    uint8_t priv[32], pub[65];
    pub[0] = 0x04;
    bool ok = p256_keygen(priv, pub + 1) && key_save(a->p2, priv, 32, touch);
    memset(priv, 0, sizeof(priv));
    if (!ok) return SW_NOT_ENOUGH_SPACE;

    uint8_t inner[70];
    rbuf_t in = {.data = inner, .cap = sizeof(inner)};
    rb_tlv(&in, 0x86, pub, 65);
    return finish_generate(a->p2, ALG_ECC256, touch, inner, in.len, r);
}

// Management key mutual/external authentication (key reference 9B).
static uint16_t auth_mgmt(uint8_t alg, const uint8_t *tpl, size_t len, rbuf_t *r)
{
    if (alg != s_st.mgmt_alg) return SW_INCORRECT_P1P2;
    size_t bs = mgmt_block(), l80, l81, l82;
    const uint8_t *witness = tlv_find(tpl, len, 0x80, &l80);
    const uint8_t *chal = tlv_find(tpl, len, 0x81, &l81);
    const uint8_t *resp = tlv_find(tpl, len, 0x82, &l82);
    uint8_t out[2 + 2 + 16], blk[16];

    if (witness && l80 == 0) {                  // step 1: send encrypted witness
        crypto_random(s_witness, bs);
        s_have_witness = true;
        s_mgmt_ok = false;
        mgmt_crypt(true, s_witness, blk);
        rbuf_t t = {.data = out, .cap = sizeof(out)};
        rb_tlv(&t, 0x80, blk, bs);
        rb_tlv(r, 0x7C, out, t.len);
        return SW_OK;
    }
    if (witness && l80 == bs && chal && l81 == bs) {    // step 2: verify witness, answer challenge
        bool ok = s_have_witness && ct_equal(witness, s_witness, bs);
        s_have_witness = false;
        if (!ok) return SW_SECURITY_NOT_SATISFIED;
        s_mgmt_ok = true;
        mgmt_crypt(true, chal, blk);
        rbuf_t t = {.data = out, .cap = sizeof(out)};
        rb_tlv(&t, 0x82, blk, bs);
        rb_tlv(r, 0x7C, out, t.len);
        return SW_OK;
    }
    if (chal && l81 == 0) {                     // external auth step 1: send challenge
        crypto_random(s_challenge, bs);
        s_have_challenge = true;
        s_mgmt_ok = false;
        rbuf_t t = {.data = out, .cap = sizeof(out)};
        rb_tlv(&t, 0x81, s_challenge, bs);
        rb_tlv(r, 0x7C, out, t.len);
        return SW_OK;
    }
    if (resp && l82 == bs) {                    // external auth step 2: check response
        mgmt_crypt(true, s_challenge, blk);
        bool ok = s_have_challenge && ct_equal(blk, resp, bs);
        s_have_challenge = false;
        if (!ok) return SW_SECURITY_NOT_SATISFIED;
        s_mgmt_ok = true;
        return SW_OK;
    }
    return SW_WRONG_DATA;
}

static uint16_t do_general_auth(const apdu_t *a, rbuf_t *r)
{
    size_t len;
    const uint8_t *tpl = tlv_find(a->data, a->lc, 0x7C, &len);
    if (!tpl) return SW_WRONG_DATA;
    if (a->p2 == KEY_MGMT) return auth_mgmt(a->p1, tpl, len, r);

    if (!slot_valid(a->p2)) return SW_INCORRECT_P1P2;
    if (a->p1 != ALG_ECC256 && a->p1 != ALG_RSA2048) return SW_INCORRECT_P1P2;
    // 9E (card authentication) needs no PIN; the others do.
    if (a->p2 != 0x9E && !s_pin_ok) return SW_SECURITY_NOT_SATISFIED;
    if (a->p2 == 0x9C && !s_pin_9c) return SW_SECURITY_NOT_SATISFIED;

    uint8_t priv[sizeof(rsa_blob_t) + 1], key_alg, touch;
    if (!key_load(a->p2, priv, &key_alg, &touch)) return SW_REF_NOT_FOUND;
    if (key_alg != a->p1) {
        memset(priv, 0, sizeof(priv));
        return SW_INCORRECT_P1P2;
    }
    if (!touch_confirm(a->p2, touch)) {
        memset(priv, 0, sizeof(priv));
        return SW_SECURITY_NOT_SATISFIED;
    }

    size_t l81, l85;
    const uint8_t *chal = tlv_find(tpl, len, 0x81, &l81);
    const uint8_t *peer = tlv_find(tpl, len, 0x85, &l85);
    uint8_t out[4 + 256];
    rbuf_t t = {.data = out, .cap = sizeof(out)};
    uint16_t sw = SW_OK;

    if (key_alg == ALG_RSA2048) {               // raw RSA: the host pads (sign) or unpads (decrypt)
        const rsa_blob_t *b = (const rsa_blob_t *)priv;
        mbedtls_rsa_context rsa;
        uint8_t res[256];
        mbedtls_rsa_init(&rsa);
        if (!chal || l81 != 256) sw = SW_WRONG_DATA;
        else if (mbedtls_rsa_import_raw(&rsa, NULL, 0, b->p, 128, b->q, 128, NULL, 0, b->e, 4) != 0 ||
                 mbedtls_rsa_complete(&rsa) != 0) sw = SW_UNKNOWN;
        else if (mbedtls_rsa_private(&rsa, crypto_rng, NULL, chal, res) != 0) sw = SW_WRONG_DATA;
        else rb_tlv(&t, 0x82, res, 256);
        mbedtls_rsa_free(&rsa);
        memset(res, 0, sizeof(res));
    } else if (chal) {                          // ECDSA signature over the hash
        uint8_t rs[64], der[72];
        if (l81 == 0 || l81 > 64 || !p256_sign(priv, chal, l81, rs)) sw = SW_WRONG_DATA;
        else rb_tlv(&t, 0x82, der, ecdsa_sig_to_der(rs, der));
    } else if (peer) {                          // ECDH
        uint8_t z[32];
        if (l85 != 65 || peer[0] != 0x04 || !p256_ecdh(priv, peer + 1, z)) sw = SW_WRONG_DATA;
        else rb_tlv(&t, 0x82, z, 32);
        memset(z, 0, sizeof(z));
    } else {
        sw = SW_WRONG_DATA;
    }
    memset(priv, 0, sizeof(priv));
    // PIN policy "always" for the digital signature slot; the other slots
    // stay unlocked ("once").
    if (a->p2 == 0x9C) s_pin_9c = false;
    if (sw == SW_OK) rb_tlv(r, 0x7C, out, t.len);
    memset(out, 0, sizeof(out));
    return sw;
}

// ---- Yubico extensions ----

static uint16_t do_set_mgmt_key(const apdu_t *a)
{
    if (!s_mgmt_ok) return SW_SECURITY_NOT_SATISFIED;
    if (a->p1 != 0xFF || (a->p2 != 0xFF && a->p2 != 0xFE)) return SW_INCORRECT_P1P2;
    if (a->lc < 3 || a->data[1] != KEY_MGMT) return SW_WRONG_DATA;
    uint8_t alg = a->data[0];
    size_t klen = mgmt_key_len(alg);
    if (!klen || a->data[2] != klen || a->lc != 3 + klen) return SW_WRONG_DATA;
    s_st.mgmt_alg = alg;
    memset(s_st.mgmt_key, 0, sizeof(s_st.mgmt_key));
    memcpy(s_st.mgmt_key, a->data + 3, klen);
    save();
    return SW_OK;
}

static uint16_t do_metadata(const apdu_t *a, rbuf_t *r)
{
    uint8_t p2 = a->p2;
    if (p2 == PIN_REF || p2 == PUK_REF) {
        int who = p2 == PIN_REF ? DEVPIN_USER : DEVPIN_ADMIN;
        uint8_t alg = 0xFF, policy[2] = {0, 0}, def = devpin_is_default(who);
        uint8_t tries[2] = {who == DEVPIN_USER ? DEVPIN_USER_TRIES : DEVPIN_ADMIN_TRIES, devpin_tries(who)};
        rb_tlv(r, 0x01, &alg, 1);
        rb_tlv(r, 0x02, policy, 2);
        rb_tlv(r, 0x05, &def, 1);
        rb_tlv(r, 0x06, tries, 2);
        return SW_OK;
    }
    if (p2 == KEY_MGMT) {
        uint8_t policy[2] = {0, TOUCH_POLICY_NEVER};
        uint8_t def = s_st.mgmt_alg == ALG_3DES && memcmp(s_st.mgmt_key, s_default_mgmt, 24) == 0;
        rb_tlv(r, 0x01, &s_st.mgmt_alg, 1);
        rb_tlv(r, 0x02, policy, 2);
        rb_tlv(r, 0x05, &def, 1);
        return SW_OK;
    }
    if (!slot_valid(p2)) return SW_REF_NOT_FOUND;
    char k[8];
    key_meta_t m;
    uint8_t pub[4 + 256 + 2 + 3];
    size_t n = sizeof(pub);
    snprintf(k, sizeof(k), "p%02x", p2);
    if (!meta_load(p2, &m) || store_get(NS_PIV, k, pub, &n) != ESP_OK) return SW_REF_NOT_FOUND;
    uint8_t policy[2] = {pin_policy(p2), m.touch}, origin = ORIGIN_GENERATED;
    rb_tlv(r, 0x01, &m.alg, 1);
    rb_tlv(r, 0x02, policy, 2);
    rb_tlv(r, 0x03, &origin, 1);
    rb_tlv(r, 0x04, pub, n);
    return SW_OK;
}

static uint16_t do_reset(void)
{
    // With the PUK (admin PIN) blocked no secret can be opened any more: only
    // a reset of the whole device helps. `ykman piv reset` gets here, as it
    // blocks PIN and PUK first.
    if (devpin_tries(DEVPIN_ADMIN) == 0) {
        if (up_wait("FACTORY RESET", "Erase ALL keys and data", 30000) != UP_OK) return SW_SECURITY_NOT_SATISFIED;
        factory_reset();
        return SW_OK;
    }
    if (up_wait("Reset PIV?", "PIV keys and certificates erased", 30000) != UP_OK) return SW_SECURITY_NOT_SATISFIED;
    store_erase_ns(NS_PIV);
    set_defaults();
    set_pin_ok(false);
    s_mgmt_ok = false;
    memset(s_touched, 0, sizeof(s_touched));
    return SW_OK;
}

// ---- application ----

static void piv_deselect(void)
{
    set_pin_ok(false);
    s_mgmt_ok = false;
}

static uint16_t piv_select(const apdu_t *a, rbuf_t *r)
{
    load();
    set_pin_ok(false);
    s_mgmt_ok = false;
    s_have_witness = s_have_challenge = false;

    uint8_t inner[32];
    rbuf_t in = {.data = inner, .cap = sizeof(inner)};
    uint8_t auth[7] = {0x4F, 0x05};
    memcpy(auth + 2, s_aid, 5);
    rb_tlv(&in, 0x4F, s_pix, sizeof(s_pix));
    rb_tlv(&in, 0x79, auth, sizeof(auth));
    rb_tlv(r, 0x61, inner, in.len);
    return SW_OK;
}

static uint16_t piv_process(const apdu_t *a, rbuf_t *r)
{
    // A PIN change elsewhere replaced the vault key: the one held is stale.
    if (s_pin_ok && s_vault_gen != devpin_vault_generation()) set_pin_ok(false);
    switch (a->ins) {
    case INS_VERIFY:        return do_verify(a);
    case INS_CHANGE_REF:    return do_change_ref(a);
    case INS_RESET_RETRY:   return do_reset_retry(a);
    case INS_GET_DATA:      return do_get_data(a, r);
    case INS_PUT_DATA:      return do_put_data(a);
    case INS_GENERATE:      return do_generate(a, r);
    case INS_GENERAL_AUTH:  return do_general_auth(a, r);
    case INS_YK_SET_MGMKEY: return do_set_mgmt_key(a);
    case INS_YK_RESET:      return do_reset();
    case INS_YK_GET_VERSION: {
        // 5.4.3: tools enable GET METADATA (5.3) and AES management keys (5.4).
        static const uint8_t v[] = {0x05, 0x04, 0x03};
        rb_put(r, v, sizeof(v));
        return SW_OK;
    }
    case INS_YK_GET_METADATA: return do_metadata(a, r);
    case INS_YK_GET_SERIAL: {
        uint8_t mac[6];
        esp_efuse_mac_get_default(mac);
        rb_put(r, mac + 2, 4);
        return SW_OK;
    }
    default:
        return SW_INS_NOT_SUPPORTED;
    }
}

const app_t app_piv = {
    .name = "piv",
    .aid = s_aid,
    .aid_len = sizeof(s_aid),
    .select = piv_select,
    .process = piv_process,
    .deselect = piv_deselect,
};

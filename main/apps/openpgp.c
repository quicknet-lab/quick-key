// OpenPGP card application (spec 3.4 subset): RSA-2048, NIST P-256
// (ECDSA/ECDH), Ed25519 (EdDSA) and X25519 (ECDH), PIN handling, key generation/import, sign/decrypt/authenticate,
// touch confirmation per key (user interaction flag, DOs D6-D8).
// Private keys are sealed to the device vault; PW1 and PW3 are the device user
// and admin PINs (core/devpin), so a flash dump without a PIN doesn't reveal
// them. There is no Reset Code: PW1 is unblocked with PW3.
#include "apps.h"
#include "core/crypto.h"
#include "core/devpin.h"
#include "core/up.h"
#include "core/vault.h"
#include "core/store.h"
#include <string.h>
#include "esp_mac.h"
#include "mbedtls/rsa.h"

#define INS_VERIFY          0x20
#define INS_CHANGE_REF      0x24
#define INS_RESET_RETRY     0x2C
#define INS_PSO             0x2A
#define INS_GENERATE        0x47
#define INS_INTERNAL_AUTH   0x88
#define INS_GET_CHALLENGE   0x84
#define INS_GET_DATA        0xCA
#define INS_PUT_DATA        0xDA
#define INS_PUT_DATA_ODD    0xDB
#define INS_SELECT_DATA     0xA5
#define INS_TERMINATE       0xE6
#define INS_ACTIVATE        0x44

#define KEY_SIG 0
#define KEY_DEC 1
#define KEY_AUT 2

#define ALGO_RSA   0x01
#define ALGO_ECDH  0x12
#define ALGO_ECDSA 0x13
#define ALGO_EDDSA 0x16

// Key types derived from the algorithm attributes.
enum { KT_RSA, KT_P256, KT_ED25519, KT_X25519 };

#define CERT_MAX 2048

#define SW_TERMINATED 0x6285

// User interaction flag: off, on, or on until the card is reset.
#define UIF_OFF     0x00
#define UIF_ON      0x01
#define UIF_FIXED   0x02
#define UIF_BUTTON  0x20    // second byte: the confirmation is a button press

typedef struct {
    uint8_t pw1_multi;
    uint8_t attr[3][12];        // algo || OID (up to 10) || import format
    uint8_t attr_len[3];
    uint8_t key_status[3];      // 0 none, 1 generated, 2 imported
    uint8_t fp[3][20];
    uint8_t ca_fp[3][20];
    uint8_t date[3][4];
    uint32_t sig_count;
    uint8_t name[39];
    uint8_t name_len;
    uint8_t lang[8];
    uint8_t lang_len;
    uint8_t sex;
    uint8_t terminated;
} pgp_state_t;

// RSA private key as stored: p || q || e (big endian).
typedef struct {
    uint8_t p[128], q[128], e[4];
} rsa_blob_t;

static const uint8_t s_aid_prefix[] = {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
static const uint8_t s_hist[] = {0x00, 0x31, 0xC5, 0x73, 0xC0, 0x01, 0x40, 0x05, 0x90, 0x00};
static const uint8_t s_ext_caps[] = {
    0x74,       // GET CHALLENGE, key import, PW status changeable, algorithm attributes changeable
    0x00,       // no secure messaging
    0x00, 0xFF, // max GET CHALLENGE
    (CERT_MAX >> 8), (CERT_MAX & 0xFF),
    0x00, 0xFF, // max special DO
    0x00,       // PIN block 2 format not supported
    0x00,       // MSE not supported
};
static const uint8_t s_ext_len[] = {0x02, 0x02, 0x10, 0x00, 0x02, 0x02, 0x10, 0x00};
static const uint8_t s_features[] = {0x81, 0x01, UIF_BUTTON};     // general feature management: button
static const uint8_t s_attr_rsa2048[] = {ALGO_RSA, 0x08, 0x00, 0x00, 0x20, 0x00};
static const uint8_t s_oid_p256[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
static const uint8_t s_oid_ed25519[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01};
static const uint8_t s_oid_cv25519[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01};

static uint8_t s_aid[16];
static pgp_state_t s_st;
static uint8_t s_uif[3];        // kept apart from s_st so its storage format stays
static uint8_t s_vpriv[32];
static bool s_vault_open;
static uint32_t s_vault_gen;        // devpin_vault_generation() of s_vpriv
static bool s_pw1_81, s_pw1_82, s_pw3;
static uint8_t s_cert_sel;
static uint8_t s_tmp[1024];

// ---- state ----

static void save(void)
{
    store_set(NS_PGP, "state", &s_st, sizeof(s_st));
}

static void set_defaults(void)
{
    memset(&s_st, 0, sizeof(s_st));
    memset(s_uif, 0, sizeof(s_uif));
    for (int i = 0; i < 3; i++) {
        memcpy(s_st.attr[i], s_attr_rsa2048, sizeof(s_attr_rsa2048));
        s_st.attr_len[i] = sizeof(s_attr_rsa2048);
    }
}

static void vault_close(void)
{
    memset(s_vpriv, 0, sizeof(s_vpriv));
    s_vault_open = false;
}

static void load(void)
{
    if (!store_read(NS_PGP, "state", &s_st, sizeof(s_st))) {
        // Fresh card, or data from an older storage format: start over.
        store_erase_ns(NS_PGP);
        set_defaults();
        save();
    }
    if (!store_read(NS_PGP, "uif", s_uif, sizeof(s_uif))) memset(s_uif, 0, sizeof(s_uif));
    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);
    memcpy(s_aid, s_aid_prefix, 6);
    s_aid[6] = 0x03;            // spec version 3.4
    s_aid[7] = 0x04;
    s_aid[8] = 0xFF;            // manufacturer 0xFFFE: test card range
    s_aid[9] = 0xFE;
    memcpy(s_aid + 10, mac + 2, 4);
    s_aid[14] = 0;
    s_aid[15] = 0;
}

static const char *key_name(int k)
{
    static const char *n[] = {"k0", "k1", "k2"};
    return n[k];
}

// Public part stored in the clear: GENERATE P1=81 reads it without a PIN.
static const char *pub_name(int k)
{
    static const char *n[] = {"pk0", "pk1", "pk2"};
    return n[k];
}

static void delete_key(int k)
{
    store_del(NS_PGP, key_name(k));
    store_del(NS_PGP, pub_name(k));
    s_st.key_status[k] = 0;
    memset(s_st.fp[k], 0, 20);
    memset(s_st.date[k], 0, 4);
}

static uint8_t key_algo(int k)
{
    return s_st.attr[k][0];
}

// Attribute value is algo || OID, optionally followed by an import-format byte.
static bool attr_oid_is(const uint8_t *v, size_t len, const uint8_t *oid, size_t oid_len)
{
    return (len == 1 + oid_len || len == 2 + oid_len) && memcmp(v + 1, oid, oid_len) == 0;
}

static int key_type(int k)
{
    const uint8_t *v = s_st.attr[k];
    size_t len = s_st.attr_len[k];
    if (v[0] == ALGO_RSA) return KT_RSA;
    if (v[0] == ALGO_EDDSA) return KT_ED25519;
    if (v[0] == ALGO_ECDH && attr_oid_is(v, len, s_oid_cv25519, sizeof(s_oid_cv25519))) return KT_X25519;
    return KT_P256;
}

// ---- PIN verification ----

static int pw_who(uint8_t ref)
{
    return ref == 0x83 ? DEVPIN_ADMIN : DEVPIN_USER;
}

static uint16_t pw_check(int who, const uint8_t *pin, size_t len)
{
    uint8_t vpriv[32];
    switch (devpin_verify(who, pin, len, vpriv)) {
    case DEVPIN_OK:      break;
    case DEVPIN_WRONG:   return SW_VERIFY_FAIL(devpin_tries(who));
    case DEVPIN_BLOCKED: return SW_AUTH_BLOCKED;
    default:             return SW_UNKNOWN;
    }
    memcpy(s_vpriv, vpriv, 32);
    memset(vpriv, 0, sizeof(vpriv));
    s_vault_open = true;
    s_vault_gen = devpin_vault_generation();
    return SW_OK;
}

static void drop_unused_vault(void)
{
    if (!s_pw1_81 && !s_pw1_82 && !s_pw3) vault_close();
}

static uint16_t do_verify(const apdu_t *a)
{
    bool *flag;
    switch (a->p2) {
    case 0x81: flag = &s_pw1_81; break;
    case 0x82: flag = &s_pw1_82; break;
    case 0x83: flag = &s_pw3; break;
    default: return SW_INCORRECT_P1P2;
    }
    int who = pw_who(a->p2);
    if (a->p1 == 0xFF) {
        *flag = false;
        drop_unused_vault();
        return SW_OK;
    }
    if (a->p1 != 0x00) return SW_INCORRECT_P1P2;
    if (a->lc == 0) {
        if (*flag) return SW_OK;
        return devpin_tries(who) ? SW_VERIFY_FAIL(devpin_tries(who)) : SW_AUTH_BLOCKED;
    }
    uint16_t sw = pw_check(who, a->data, a->lc);
    *flag = sw == SW_OK;
    return sw;
}

// A refused new PIN: a bad length, else the factory value (or no storage).
static uint16_t set_fail_sw(int who, size_t len)
{
    return devpin_len_ok(who, len) ? SW_WRONG_DATA : SW_WRONG_LENGTH;
}

static uint16_t do_change_ref(const apdu_t *a)
{
    if (a->p1 != 0x00) return SW_INCORRECT_P1P2;
    if (a->p2 != 0x81 && a->p2 != 0x83) return SW_INCORRECT_P1P2;
    int who = pw_who(a->p2);
    size_t old = devpin_len(who);
    if (a->lc <= old) return SW_WRONG_LENGTH;
    uint16_t sw = pw_check(who, a->data, old);
    if (sw != SW_OK) return sw;
    if (!devpin_set(who, s_vpriv, a->data + old, a->lc - old)) sw = set_fail_sw(who, a->lc - old);
    if (a->p2 == 0x81) s_pw1_81 = s_pw1_82 = false;
    else s_pw3 = false;
    drop_unused_vault();
    return sw;
}

static uint16_t do_reset_retry(const apdu_t *a)
{
    if (a->p2 != 0x81) return SW_INCORRECT_P1P2;
    if (a->p1 == 0x00) return SW_SECURITY_NOT_SATISFIED;   // no Reset Code
    if (a->p1 != 0x02) return SW_INCORRECT_P1P2;
    if (!s_pw3) return SW_SECURITY_NOT_SATISFIED;
    return devpin_set(DEVPIN_USER, s_vpriv, a->data, a->lc) ? SW_OK : set_fail_sw(DEVPIN_USER, a->lc);
}

// ---- GET DATA ----

static void put_pw_status(rbuf_t *r)
{
    uint8_t v[7] = {s_st.pw1_multi, DEVPIN_MAX, DEVPIN_MAX, DEVPIN_MAX,
                    devpin_tries(DEVPIN_USER), 0, devpin_tries(DEVPIN_ADMIN)};
    rb_tlv(r, 0xC4, v, 7);
}

static void put_key_info(rbuf_t *r)
{
    uint8_t v[6] = {1, s_st.key_status[0], 2, s_st.key_status[1], 3, s_st.key_status[2]};
    rb_tlv(r, 0xDE, v, 6);
}

static uint16_t put_blob(rbuf_t *r, const char *key, uint16_t tag, bool wrap)
{
    size_t n = sizeof(s_tmp);
    uint8_t *buf = s_tmp;
    uint8_t big[CERT_MAX];
    if (tag == 0x7F21) {
        buf = big;
        n = sizeof(big);
    }
    if (store_get(NS_PGP, key, buf, &n) != ESP_OK) n = 0;
    if (wrap) rb_tlv(r, tag, buf, n);
    else rb_put(r, buf, n);
    return SW_OK;
}

static void build_app_data(rbuf_t *r)
{
    uint8_t disc[512];
    rbuf_t d = {.data = disc, .cap = sizeof(disc)};
    rb_tlv(&d, 0xC0, s_ext_caps, sizeof(s_ext_caps));
    for (int k = 0; k < 3; k++) rb_tlv(&d, 0xC1 + k, s_st.attr[k], s_st.attr_len[k]);
    put_pw_status(&d);
    rb_tlv(&d, 0xC5, s_st.fp, 60);
    rb_tlv(&d, 0xC6, s_st.ca_fp, 60);
    rb_tlv(&d, 0xCD, s_st.date, 12);
    put_key_info(&d);
    for (int k = 0; k < 3; k++) {
        uint8_t u[2] = {s_uif[k], UIF_BUTTON};
        rb_tlv(&d, 0xD6 + k, u, 2);
    }

    uint8_t inner[700];
    rbuf_t in = {.data = inner, .cap = sizeof(inner)};
    rb_tlv(&in, 0x4F, s_aid, sizeof(s_aid));
    rb_tlv(&in, 0x5F52, s_hist, sizeof(s_hist));
    rb_tlv(&in, 0x7F66, s_ext_len, sizeof(s_ext_len));
    rb_tlv(&in, 0x7F74, s_features, sizeof(s_features));
    rb_tlv(&in, 0x73, disc, d.len);
    rb_tlv(r, 0x6E, inner, in.len);
}

static uint16_t do_get_data(const apdu_t *a, rbuf_t *r)
{
    uint16_t tag = (a->p1 << 8) | a->p2;
    uint8_t buf[64];
    rbuf_t t = {.data = buf, .cap = sizeof(buf)};

    switch (tag) {
    case 0x004F: rb_put(r, s_aid, sizeof(s_aid)); break;
    case 0x5F52: rb_put(r, s_hist, sizeof(s_hist)); break;
    case 0x7F66: rb_put(r, s_ext_len, sizeof(s_ext_len)); break;
    case 0x00C0: rb_put(r, s_ext_caps, sizeof(s_ext_caps)); break;
    case 0x00C1:
    case 0x00C2:
    case 0x00C3: rb_put(r, s_st.attr[tag - 0xC1], s_st.attr_len[tag - 0xC1]); break;
    case 0x00C4: put_pw_status(&t); rb_put(r, buf + 2, 7); break;
    case 0x00C5: rb_put(r, s_st.fp, 60); break;
    case 0x00C6: rb_put(r, s_st.ca_fp, 60); break;
    case 0x00CD: rb_put(r, s_st.date, 12); break;
    case 0x00DE: put_key_info(&t); rb_put(r, buf + 2, 6); break;
    case 0x00D6:
    case 0x00D7:
    case 0x00D8: rb_byte(r, s_uif[tag - 0xD6]); rb_byte(r, UIF_BUTTON); break;
    case 0x7F74: rb_put(r, s_features, sizeof(s_features)); break;
    case 0x005B: rb_put(r, s_st.name, s_st.name_len); break;
    case 0x5F2D: rb_put(r, s_st.lang, s_st.lang_len); break;
    case 0x5F35: rb_put(r, &s_st.sex, s_st.sex ? 1 : 0); break;
    case 0x005E: return put_blob(r, "login", tag, false);
    case 0x5F50: return put_blob(r, "url", tag, false);
    case 0x7F21: {
        char k[6] = "cert0";
        k[4] = '0' + s_cert_sel;
        return put_blob(r, k, tag, false);
    }
    case 0x0065: {
        uint8_t ch[64];
        rbuf_t c = {.data = ch, .cap = sizeof(ch)};
        rb_tlv(&c, 0x5B, s_st.name, s_st.name_len);
        rb_tlv(&c, 0x5F2D, s_st.lang, s_st.lang_len);
        rb_tlv(&c, 0x5F35, &s_st.sex, 1);
        rb_put(r, ch, c.len);
        break;
    }
    case 0x006E: {
        uint8_t app[800];
        rbuf_t ad = {.data = app, .cap = sizeof(app)};
        build_app_data(&ad);
        // Strip the outer 6E tag: GET DATA returns the value only.
        size_t vlen;
        const uint8_t *v = tlv_find(app, ad.len, 0x6E, &vlen);
        rb_put(r, v, vlen);
        break;
    }
    case 0x007A: {
        uint8_t c[3] = {s_st.sig_count >> 16, s_st.sig_count >> 8, s_st.sig_count};
        rb_tlv(r, 0x93, c, 3);
        break;
    }
    case 0x0093: {
        uint8_t c[3] = {s_st.sig_count >> 16, s_st.sig_count >> 8, s_st.sig_count};
        rb_put(r, c, 3);
        break;
    }
    default:
        return SW_REF_NOT_FOUND;
    }
    return SW_OK;
}

// ---- PUT DATA ----

static bool attr_valid(int k, const uint8_t *v, size_t len)
{
    if (len < 1) return false;
    if (v[0] == ALGO_RSA) {
        // n = 2048 bits, e = 32 bits, standard import format (e, p, q).
        return len == 6 && v[1] == 0x08 && v[2] == 0x00 && v[3] == 0x00 && v[4] == 0x20 && v[5] == 0x00;
    }
    bool p256 = attr_oid_is(v, len, s_oid_p256, sizeof(s_oid_p256));
    if (v[0] == ALGO_ECDSA) return k != KEY_DEC && p256;
    if (v[0] == ALGO_EDDSA) return k != KEY_DEC && attr_oid_is(v, len, s_oid_ed25519, sizeof(s_oid_ed25519));
    if (v[0] == ALGO_ECDH) return k == KEY_DEC && (p256 || attr_oid_is(v, len, s_oid_cv25519, sizeof(s_oid_cv25519)));
    return false;
}

static uint16_t import_key(const uint8_t *d, size_t len);

static uint16_t do_put_data(const apdu_t *a)
{
    uint16_t tag = (a->p1 << 8) | a->p2;
    if (a->ins == INS_PUT_DATA_ODD) {
        if (tag != 0x3FFF) return SW_INCORRECT_P1P2;
        if (!s_pw3) return SW_SECURITY_NOT_SATISFIED;
        if (devpin_any_default()) return SW_CONDITIONS_NOT_SATISFIED;
        return import_key(a->data, a->lc);
    }
    if (!s_pw3) return SW_SECURITY_NOT_SATISFIED;

    const uint8_t *v = a->data;
    size_t n = a->lc;
    switch (tag) {
    case 0x005B:
        if (n > sizeof(s_st.name)) return SW_WRONG_LENGTH;
        memcpy(s_st.name, v, n);
        s_st.name_len = n;
        break;
    case 0x5F2D:
        if (n > sizeof(s_st.lang)) return SW_WRONG_LENGTH;
        memcpy(s_st.lang, v, n);
        s_st.lang_len = n;
        break;
    case 0x5F35:
        if (n != 1) return SW_WRONG_LENGTH;
        s_st.sex = v[0];
        break;
    case 0x005E:
    case 0x5F50:
        if (n > 0xFF) return SW_WRONG_LENGTH;
        store_set(NS_PGP, tag == 0x005E ? "login" : "url", v, n);
        return SW_OK;
    case 0x7F21: {
        if (n > CERT_MAX) return SW_WRONG_LENGTH;
        char k[6] = "cert0";
        k[4] = '0' + s_cert_sel;
        store_set(NS_PGP, k, v, n);
        return SW_OK;
    }
    case 0x00C1:
    case 0x00C2:
    case 0x00C3: {
        int k = tag - 0xC1;
        if (n > sizeof(s_st.attr[k]) || !attr_valid(k, v, n)) return SW_WRONG_DATA;
        if (n != s_st.attr_len[k] || memcmp(s_st.attr[k], v, n) != 0) {
            delete_key(k);
            memcpy(s_st.attr[k], v, n);
            s_st.attr_len[k] = n;
        }
        break;
    }
    case 0x00C4:
        if (n < 1) return SW_WRONG_LENGTH;
        s_st.pw1_multi = v[0] ? 1 : 0;
        break;
    case 0x00C7:
    case 0x00C8:
    case 0x00C9:
        if (n != 20) return SW_WRONG_LENGTH;
        memcpy(s_st.fp[tag - 0xC7], v, 20);
        break;
    case 0x00CA:
    case 0x00CB:
    case 0x00CC:
        if (n != 20) return SW_WRONG_LENGTH;
        memcpy(s_st.ca_fp[tag - 0xCA], v, 20);
        break;
    case 0x00CE:
    case 0x00CF:
    case 0x00D0:
        if (n != 4) return SW_WRONG_LENGTH;
        memcpy(s_st.date[tag - 0xCE], v, 4);
        break;
    case 0x00D3:
        return SW_FUNC_NOT_SUPPORTED;      // no Reset Code
    case 0x00D6:
    case 0x00D7:
    case 0x00D8: {
        int k = tag - 0xD6;
        if (n != 2) return SW_WRONG_LENGTH;
        if (v[0] > UIF_FIXED || v[1] != UIF_BUTTON) return SW_WRONG_DATA;
        if (s_uif[k] == UIF_FIXED) return SW_SECURITY_NOT_SATISFIED;   // only a card reset clears it
        s_uif[k] = v[0];
        return store_set(NS_PGP, "uif", s_uif, sizeof(s_uif)) == ESP_OK ? SW_OK : SW_NOT_ENOUGH_SPACE;
    }
    default:
        return SW_REF_NOT_FOUND;
    }
    save();
    return SW_OK;
}

// ---- keys ----

static int crt_to_key(const uint8_t *crt, size_t len)
{
    if (len < 1) return -1;
    switch (crt[0]) {
    case 0xB6: return KEY_SIG;
    case 0xB8: return KEY_DEC;
    case 0xA4: return KEY_AUT;
    default: return -1;
    }
}

// Private key blobs are sealed to the vault; reading needs a verified PIN.
static bool key_read(int k, void *out, size_t len)
{
    uint8_t blob[sizeof(rsa_blob_t) + VAULT_OVERHEAD], plain[sizeof(rsa_blob_t)];
    size_t n = sizeof(blob), olen;
    if (!s_vault_open || store_get(NS_PGP, key_name(k), blob, &n) != ESP_OK) return false;
    bool ok = vault_open(s_vpriv, blob, n, plain, &olen) && olen == len;
    if (ok) memcpy(out, plain, len);
    memset(plain, 0, sizeof(plain));
    return ok;
}

// Replaces key k with a new one that is already generated or validated, so a
// failed generation or a malformed import leaves the old key in place.
static uint16_t key_write(int k, const void *priv, size_t len, const uint8_t *pub, size_t pub_len)
{
    uint8_t blob[sizeof(rsa_blob_t) + VAULT_OVERHEAD];
    size_t n = vault_seal(devpin_vpub(), priv, len, blob);
    if (!n) return SW_UNKNOWN;
    delete_key(k);
    if (store_set(NS_PGP, key_name(k), blob, n) != ESP_OK ||
        store_set(NS_PGP, pub_name(k), pub, pub_len) != ESP_OK) {
        save();                 // the old key is gone: the state must say so
        return SW_NOT_ENOUGH_SPACE;
    }
    return SW_OK;
}

static bool rsa_load(int k, mbedtls_rsa_context *rsa)
{
    rsa_blob_t b;
    if (!key_read(k, &b, sizeof(b))) return false;
    mbedtls_rsa_init(rsa);
    bool ok = mbedtls_rsa_import_raw(rsa, NULL, 0, b.p, 128, b.q, 128, NULL, 0, b.e, 4) == 0 &&
              mbedtls_rsa_complete(rsa) == 0;
    memset(&b, 0, sizeof(b));
    if (!ok) mbedtls_rsa_free(rsa);
    return ok;
}

static bool ec_load(int k, uint8_t priv[32])
{
    return key_read(k, priv, 32);
}

// Stored public parts: RSA n(256) || e(4), P-256 X || Y, Ed25519/X25519 32 bytes.
static uint16_t put_public_key(int k, rbuf_t *r)
{
    uint8_t inner[300], pub[260];
    rbuf_t in = {.data = inner, .cap = sizeof(inner)};
    size_t n = sizeof(pub);
    if (store_get(NS_PGP, pub_name(k), pub, &n) != ESP_OK) return SW_REF_NOT_FOUND;
    if (key_algo(k) == ALGO_RSA) {
        if (n != 260) return SW_REF_NOT_FOUND;
        int i = 0;
        while (i < 3 && pub[256 + i] == 0) i++;
        rb_tlv(&in, 0x81, pub, 256);
        rb_tlv(&in, 0x82, pub + 256 + i, 4 - i);
    } else if (key_type(k) != KT_P256) {
        if (n != 32) return SW_REF_NOT_FOUND;
        rb_tlv(&in, 0x86, pub, 32);
    } else {
        if (n != 64) return SW_REF_NOT_FOUND;
        uint8_t pt[65] = {0x04};
        memcpy(pt + 1, pub, 64);
        rb_tlv(&in, 0x86, pt, 65);
    }
    rb_tlv(r, 0x7F49, inner, in.len);
    return SW_OK;
}

static uint16_t do_generate(const apdu_t *a, rbuf_t *r)
{
    int k = crt_to_key(a->data, a->lc);
    if (k < 0) return SW_WRONG_DATA;
    if (a->p1 == 0x81) return put_public_key(k, r);
    if (a->p1 != 0x80) return SW_INCORRECT_P1P2;
    if (!s_pw3) return SW_SECURITY_NOT_SATISFIED;
    if (devpin_any_default()) return SW_CONDITIONS_NOT_SATISFIED;

    uint16_t sw;
    if (key_algo(k) == ALGO_RSA) {
        mbedtls_rsa_context rsa;
        rsa_blob_t b;
        uint8_t pub[260];
        mbedtls_rsa_init(&rsa);
        int rc = mbedtls_rsa_gen_key(&rsa, crypto_rng, NULL, 2048, 65537);
        if (rc == 0) rc = mbedtls_rsa_export_raw(&rsa, pub, 256, b.p, 128, b.q, 128, NULL, 0, b.e, 4);
        mbedtls_rsa_free(&rsa);
        if (rc != 0) return SW_UNKNOWN;
        memcpy(pub + 256, b.e, 4);
        sw = key_write(k, &b, sizeof(b), pub, sizeof(pub));
        memset(&b, 0, sizeof(b));
    } else if (key_type(k) != KT_P256) {
        uint8_t priv[32], pub[32];
        crypto_random(priv, sizeof(priv));
        if (key_type(k) == KT_ED25519) ed25519_pubkey(priv, pub);
        else x25519_pubkey(priv, pub);
        sw = key_write(k, priv, 32, pub, 32);
        memset(priv, 0, sizeof(priv));
    } else {
        uint8_t priv[32], pub[64];
        if (!p256_keygen(priv, pub)) return SW_UNKNOWN;
        sw = key_write(k, priv, 32, pub, 64);
        memset(priv, 0, sizeof(priv));
    }
    if (sw != SW_OK) return sw;
    s_st.key_status[k] = 1;
    if (k == KEY_SIG) s_st.sig_count = 0;
    save();
    return put_public_key(k, r);
}

// Extended header list: 4D { CRT, 7F48 {tag/len list}, 5F48 {concatenated values} }
static uint16_t import_key(const uint8_t *d, size_t len)
{
    size_t l4d, ltl, ldata;
    const uint8_t *p = tlv_find(d, len, 0x4D, &l4d);
    if (!p || l4d < 2) return SW_WRONG_DATA;
    int k = crt_to_key(p, l4d);
    if (k < 0) return SW_WRONG_DATA;
    const uint8_t *tl = tlv_find(p + 2, l4d - 2, 0x7F48, &ltl);
    const uint8_t *data = tlv_find(p + 2, l4d - 2, 0x5F48, &ldata);
    if (!tl || !data) return SW_WRONG_DATA;

    const uint8_t *e = NULL, *pp = NULL, *q = NULL, *priv = NULL;
    size_t elen = 0, plen = 0, qlen = 0, privlen = 0, off = 0;
    for (size_t i = 0; i < ltl;) {
        uint8_t tag = tl[i++];
        if (i >= ltl) return SW_WRONG_DATA;
        size_t l = tl[i++];
        if (l == 0x81) {
            if (i >= ltl) return SW_WRONG_DATA;
            l = tl[i++];
        } else if (l == 0x82) {
            if (i + 1 >= ltl) return SW_WRONG_DATA;
            l = (tl[i] << 8) | tl[i + 1];
            i += 2;
        }
        if (off + l > ldata) return SW_WRONG_DATA;
        if (tag == 0x91) { e = data + off; elen = l; }
        if (tag == 0x92) { pp = data + off; plen = l; priv = pp; privlen = l; }
        if (tag == 0x93) { q = data + off; qlen = l; }
        off += l;
    }

    if (key_algo(k) == ALGO_RSA) {
        if (!e || !pp || !q || elen > 4 || plen != 128 || qlen != 128) return SW_WRONG_DATA;
        rsa_blob_t b = {0};
        memcpy(b.p, pp, 128);
        memcpy(b.q, q, 128);
        memcpy(b.e + 4 - elen, e, elen);
        mbedtls_rsa_context rsa;
        uint8_t pub[260];
        mbedtls_rsa_init(&rsa);
        bool ok = mbedtls_rsa_import_raw(&rsa, NULL, 0, b.p, 128, b.q, 128, NULL, 0, b.e, 4) == 0 &&
                  mbedtls_rsa_complete(&rsa) == 0 && mbedtls_rsa_check_privkey(&rsa) == 0 &&
                  mbedtls_rsa_export_raw(&rsa, pub, 256, NULL, 0, NULL, 0, NULL, 0, NULL, 0) == 0;
        mbedtls_rsa_free(&rsa);
        memcpy(pub + 256, b.e, 4);
        uint16_t sw = ok ? key_write(k, &b, sizeof(b), pub, sizeof(pub)) : SW_WRONG_DATA;
        memset(&b, 0, sizeof(b));
        if (sw != SW_OK) return sw;
    } else {
        uint8_t key[32] = {0}, pub[64];
        if (!priv || privlen > 32) return SW_WRONG_DATA;
        memcpy(key + 32 - privlen, priv, privlen);
        uint16_t sw;
        if (key_type(k) == KT_ED25519) {
            ed25519_pubkey(key, pub);
            sw = key_write(k, key, 32, pub, 32);
        } else if (key_type(k) == KT_X25519) {
            // GnuPG sends the X25519 scalar big-endian; X25519 uses little-endian.
            for (int i = 0; i < 16; i++) {
                uint8_t t = key[i];
                key[i] = key[31 - i];
                key[31 - i] = t;
            }
            x25519_pubkey(key, pub);
            sw = key_write(k, key, 32, pub, 32);
        } else {
            sw = p256_pubkey(key, pub) ? key_write(k, key, 32, pub, 64) : SW_WRONG_DATA;
        }
        memset(key, 0, sizeof(key));
        if (sw != SW_OK) return sw;
    }
    s_st.key_status[k] = 2;
    if (k == KEY_SIG) s_st.sig_count = 0;
    save();
    return SW_OK;
}

// PKCS#1 v1.5 type 1 signature over the caller-supplied DigestInfo.
static uint16_t rsa_sign(int k, const uint8_t *in, size_t len, rbuf_t *r)
{
    if (len > 256 - 11) return SW_WRONG_LENGTH;
    mbedtls_rsa_context rsa;
    if (!rsa_load(k, &rsa)) return SW_REF_NOT_FOUND;
    uint8_t em[256], sig[256];
    em[0] = 0x00;
    em[1] = 0x01;
    memset(em + 2, 0xFF, 256 - 3 - len);
    em[256 - len - 1] = 0x00;
    memcpy(em + 256 - len, in, len);
    int rc = mbedtls_rsa_private(&rsa, crypto_rng, NULL, em, sig);
    mbedtls_rsa_free(&rsa);
    if (rc != 0) return SW_UNKNOWN;
    rb_put(r, sig, 256);
    return SW_OK;
}

static uint16_t ec_sign(int k, const uint8_t *in, size_t len, rbuf_t *r)
{
    uint8_t priv[32], rs[64];
    if (!ec_load(k, priv)) return SW_REF_NOT_FOUND;
    bool ok = true;
    if (key_type(k) == KT_ED25519) ed25519_sign(priv, in, len, rs);     // EdDSA over the given data
    else ok = p256_sign(priv, in, len, rs);
    memset(priv, 0, sizeof(priv));
    if (!ok) return SW_UNKNOWN;
    rb_put(r, rs, 64);
    return SW_OK;
}

static uint16_t sign_with(int k, const uint8_t *in, size_t len, rbuf_t *r)
{
    if (!s_st.key_status[k]) return SW_REF_NOT_FOUND;
    return key_algo(k) == ALGO_RSA ? rsa_sign(k, in, len, r) : ec_sign(k, in, len, r);
}

static uint16_t decipher(const uint8_t *in, size_t len, rbuf_t *r)
{
    if (!s_st.key_status[KEY_DEC]) return SW_REF_NOT_FOUND;
    if (key_algo(KEY_DEC) == ALGO_RSA) {
        // 00 || cryptogram
        if (len != 257 || in[0] != 0x00) return SW_WRONG_DATA;
        mbedtls_rsa_context rsa;
        if (!rsa_load(KEY_DEC, &rsa)) return SW_REF_NOT_FOUND;
        uint8_t em[256];
        int rc = mbedtls_rsa_private(&rsa, crypto_rng, NULL, in + 1, em);
        mbedtls_rsa_free(&rsa);
        if (rc != 0) return SW_WRONG_DATA;
        // Strip PKCS#1 v1.5 type 2 padding.
        size_t i = 2;
        while (i < 256 && em[i] != 0) i++;
        uint16_t sw = SW_WRONG_DATA;
        if (em[0] == 0x00 && em[1] == 0x02 && i >= 10 && i < 256) {
            rb_put(r, em + i + 1, 255 - i);
            sw = SW_OK;
        }
        memset(em, 0, sizeof(em));
        return sw;
    }
    // A6 { 7F49 { 86 <04||X||Y> or X25519 point (32 bytes, optionally 0x40-prefixed)> } }
    size_t la6, l7f49, l86;
    const uint8_t *p = tlv_find(in, len, 0xA6, &la6);
    if (p) p = tlv_find(p, la6, 0x7F49, &l7f49);
    if (p) p = tlv_find(p, l7f49, 0x86, &l86);
    if (p && key_type(KEY_DEC) == KT_X25519) {
        if (l86 == 33 && p[0] == 0x40) {
            p++;
            l86--;
        }
        if (l86 != 32) return SW_WRONG_DATA;
        uint8_t priv[32], z[32];
        if (!ec_load(KEY_DEC, priv)) return SW_REF_NOT_FOUND;
        bool ok = x25519(priv, p, z);
        memset(priv, 0, sizeof(priv));
        if (!ok) return SW_WRONG_DATA;
        rb_put(r, z, 32);
        memset(z, 0, sizeof(z));
        return SW_OK;
    }
    if (!p || l86 != 65 || p[0] != 0x04) return SW_WRONG_DATA;
    uint8_t priv[32], shared[65];
    if (!ec_load(KEY_DEC, priv)) return SW_REF_NOT_FOUND;
    shared[0] = 0x04;
    bool ok = p256_ecdh_point(priv, p + 1, shared + 1);
    memset(priv, 0, sizeof(priv));
    if (ok) rb_put(r, shared, 65);
    memset(shared, 0, sizeof(shared));
    if (!ok) return SW_WRONG_DATA;
    return SW_OK;
}

// With the user interaction flag set, every use of the key needs a press.
static bool uif_confirm(int k)
{
    static const char *title[] = {"Sign?", "Decrypt?", "Authenticate?"};
    if (s_uif[k] == UIF_OFF || !s_st.key_status[k]) return true;
    return up_wait(title[k], "OpenPGP key", 30000) == UP_OK;
}

static uint16_t do_pso(const apdu_t *a, rbuf_t *r)
{
    uint16_t op = (a->p1 << 8) | a->p2;
    if (op == 0x9E9A) {                     // COMPUTE DIGITAL SIGNATURE
        if (!s_pw1_81) return SW_SECURITY_NOT_SATISFIED;
        if (!uif_confirm(KEY_SIG)) return SW_SECURITY_NOT_SATISFIED;
        uint16_t sw = sign_with(KEY_SIG, a->data, a->lc, r);
        if (sw == SW_OK) {
            if (!s_st.pw1_multi) s_pw1_81 = false;
            s_st.sig_count = (s_st.sig_count + 1) & 0xFFFFFF;
            save();
        }
        return sw;
    }
    if (op == 0x8086) {                     // DECIPHER
        if (!s_pw1_82) return SW_SECURITY_NOT_SATISFIED;
        if (!uif_confirm(KEY_DEC)) return SW_SECURITY_NOT_SATISFIED;
        return decipher(a->data, a->lc, r);
    }
    return SW_INCORRECT_P1P2;
}

// ---- application ----

static void pgp_deselect(void)
{
    s_pw1_81 = s_pw1_82 = s_pw3 = false;
    vault_close();
}

static uint16_t pgp_select(const apdu_t *a, rbuf_t *r)
{
    load();
    s_pw1_81 = s_pw1_82 = s_pw3 = false;
    vault_close();
    s_cert_sel = 0;
    return s_st.terminated ? SW_TERMINATED : SW_OK;
}

static uint16_t pgp_process(const apdu_t *a, rbuf_t *r)
{
    // A PIN change elsewhere replaced the vault key: the one held is stale.
    if (s_vault_open && s_vault_gen != devpin_vault_generation()) {
        s_pw1_81 = s_pw1_82 = s_pw3 = false;
        vault_close();
    }
    if (s_st.terminated) {
        if (a->ins != INS_ACTIVATE) return SW_TERMINATED;
        // With PW3 (admin PIN) blocked no secret can be opened any more: only
        // a reset of the whole device helps (gpg's factory-reset blocks PW3).
        if (devpin_tries(DEVPIN_ADMIN) == 0) {
            if (up_wait("FACTORY RESET", "Erase ALL keys and data", 30000) != UP_OK) {
                return SW_SECURITY_NOT_SATISFIED;
            }
            factory_reset();
            return SW_OK;
        }
        store_erase_ns(NS_PGP);
        load();
        s_pw1_81 = s_pw1_82 = s_pw3 = false;
        vault_close();
        return SW_OK;
    }

    switch (a->ins) {
    case INS_VERIFY:        return do_verify(a);
    case INS_CHANGE_REF:    return do_change_ref(a);
    case INS_RESET_RETRY:   return do_reset_retry(a);
    case INS_GET_DATA:      return do_get_data(a, r);
    case INS_PUT_DATA:
    case INS_PUT_DATA_ODD:  return do_put_data(a);
    case INS_GENERATE:      return do_generate(a, r);
    case INS_PSO:           return do_pso(a, r);
    case INS_INTERNAL_AUTH:
        if (!s_pw1_82) return SW_SECURITY_NOT_SATISFIED;
        if (!uif_confirm(KEY_AUT)) return SW_SECURITY_NOT_SATISFIED;
        return sign_with(KEY_AUT, a->data, a->lc, r);
    case INS_GET_CHALLENGE: {
        size_t n = a->le ? a->le : 0;
        if (n == 0 || n > 0xFF) return SW_WRONG_LENGTH;
        uint8_t buf[0xFF];
        crypto_random(buf, n);
        rb_put(r, buf, n);
        return SW_OK;
    }
    case INS_SELECT_DATA:
        if (a->p1 > 2) return SW_INCORRECT_P1P2;
        s_cert_sel = a->p1;
        return SW_OK;
    case INS_TERMINATE:
        if (!s_pw3 && devpin_tries(DEVPIN_ADMIN) != 0) return SW_SECURITY_NOT_SATISFIED;
        // With PW3 blocked the host needs no PIN at all: ask the user.
        if (!s_pw3 && up_wait("Reset OpenPGP?", "OpenPGP keys erased", 30000) != UP_OK) {
            return SW_SECURITY_NOT_SATISFIED;
        }
        store_erase_ns(NS_PGP);
        s_pw1_81 = s_pw1_82 = s_pw3 = false;
        vault_close();
        set_defaults();
        s_st.terminated = 1;
        save();
        return SW_OK;
    case INS_ACTIVATE:
        return SW_OK;
    default:
        return SW_INS_NOT_SUPPORTED;
    }
}

const app_t app_openpgp = {
    .name = "openpgp",
    .aid = s_aid_prefix,
    .aid_len = sizeof(s_aid_prefix),
    .select = pgp_select,
    .process = pgp_process,
    .deselect = pgp_deselect,
};

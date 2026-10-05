// Secrets app: TOTP/HOTP using the YubiKey OATH APDU protocol, plus two
// YubiKey-compatible HMAC-SHA1 challenge-response slots (KeePassXC over PC/SC).
#include "apps.h"
#include "core/crypto.h"
#include "core/store.h"
#include "core/up.h"
#include <stdio.h>
#include <string.h>
#include "esp_mac.h"

#define INS_PUT         0x01
#define INS_DELETE      0x02
#define INS_SET_CODE    0x03
#define INS_RESET       0x04
#define INS_LIST        0xA1
#define INS_CALCULATE   0xA2
#define INS_VALIDATE    0xA3
#define INS_CALC_ALL    0xA4
#define INS_HMAC_SET    0xB1    // own extension: P1 = slot, data = secret (empty deletes)

// YubiKey OTP API requests share INS 01 with PUT and are told apart by P1.
#define INS_API_REQ     0x01
#define CMD_GET_SERIAL  0x10
#define CMD_HMAC_1      0x30
#define CMD_HMAC_2      0x38

#define TAG_NAME        0x71
#define TAG_NAME_LIST   0x72
#define TAG_KEY         0x73
#define TAG_CHALLENGE   0x74
#define TAG_RESPONSE    0x75
#define TAG_TRUNCATED   0x76
#define TAG_HOTP        0x77
#define TAG_PROPERTY    0x78
#define TAG_VERSION     0x79
#define TAG_IMF         0x7A
#define TAG_ALGORITHM   0x7B
#define TAG_TOUCH       0x7C

#define TYPE_HOTP       0x10
#define TYPE_TOTP       0x20
#define TYPE_MASK       0xF0
#define ALG_MASK        0x0F
#define PROP_TOUCH      0x02

#define MAX_CREDS       50
#define MAX_NAME        64
#define MAX_KEY         64
#define MAX_HMAC_KEY    64

typedef struct {
    uint8_t name_len;
    char name[MAX_NAME];
    uint8_t type_alg;
    uint8_t digits;
    uint8_t key_len;
    uint8_t key[MAX_KEY];
    uint8_t prop;
    uint32_t counter;
} oath_cred_t;

typedef struct {
    uint8_t set;
    uint8_t alg;
    uint8_t key[16];
} oath_auth_t;

static const uint8_t s_aid[] = {0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01};
static const uint8_t s_version[] = {0x04, 0x04, 0x00};

static uint8_t s_salt[8];
static oath_auth_t s_auth;
static uint8_t s_challenge[8];
static bool s_authenticated;
static oath_cred_t s_cred;

static void cred_key(int i, char *k)
{
    snprintf(k, 8, "c%02d", i);
}

static bool cred_load(int i, oath_cred_t *c)
{
    char k[8];
    cred_key(i, k);
    return store_read(NS_OATH, k, c, sizeof(*c));
}

// Finds a credential by name; returns slot or -1. *free_slot gets the first empty slot.
static int cred_find(const uint8_t *name, size_t len, int *free_slot)
{
    if (free_slot) *free_slot = -1;
    for (int i = 0; i < MAX_CREDS; i++) {
        if (!cred_load(i, &s_cred)) {
            if (free_slot && *free_slot < 0) *free_slot = i;
            continue;
        }
        if (s_cred.name_len == len && memcmp(s_cred.name, name, len) == 0) return i;
    }
    return -1;
}

static void load_state(void)
{
    if (!store_read(NS_OATH, "salt", s_salt, sizeof(s_salt))) {
        crypto_random(s_salt, sizeof(s_salt));
        store_set(NS_OATH, "salt", s_salt, sizeof(s_salt));
    }
    if (!store_read(NS_OATH, "auth", &s_auth, sizeof(s_auth))) memset(&s_auth, 0, sizeof(s_auth));
}

static size_t hmac_md(uint8_t type_alg, const uint8_t *key, size_t klen, const uint8_t *msg, size_t mlen,
                      uint8_t *out)
{
    int md = type_alg & ALG_MASK;
    if (md < 1 || md > 3) md = 1;
    return hmac_any(md, key, klen, msg, mlen, out);
}

static uint32_t truncate(const uint8_t *mac, size_t len)
{
    uint8_t off = mac[len - 1] & 0x0F;
    return ((uint32_t)(mac[off] & 0x7F) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
}

// Computes the response for s_cred; HOTP uses and advances the stored counter.
// Returns 0 if the advanced counter can't be stored: the same code must not
// come out again after a reboot.
static size_t calculate(int slot, const uint8_t *chal, size_t chal_len, uint8_t *mac)
{
    uint8_t msg[8] = {0};
    if ((s_cred.type_alg & TYPE_MASK) == TYPE_HOTP) {
        uint32_t c = s_cred.counter;
        msg[4] = c >> 24;
        msg[5] = c >> 16;
        msg[6] = c >> 8;
        msg[7] = c;
        s_cred.counter++;
        char k[8];
        cred_key(slot, k);
        if (store_set(NS_OATH, k, &s_cred, sizeof(s_cred)) != ESP_OK) return 0;
    } else {
        if (chal_len > 8) chal_len = 8;
        memcpy(msg + 8 - chal_len, chal, chal_len);
    }
    return hmac_md(s_cred.type_alg, s_cred.key, s_cred.key_len, msg, 8, mac);
}

static void put_truncated(rbuf_t *r, const uint8_t *mac, size_t len)
{
    uint32_t t = truncate(mac, len);
    uint8_t v[5] = {s_cred.digits, t >> 24, t >> 16, t >> 8, t};
    rb_tlv(r, TAG_TRUNCATED, v, 5);
}

static void oath_deselect(void)
{
    s_authenticated = false;
}

static uint16_t oath_select(const apdu_t *a, rbuf_t *r)
{
    load_state();
    s_authenticated = !s_auth.set;
    rb_tlv(r, TAG_VERSION, s_version, sizeof(s_version));
    rb_tlv(r, TAG_NAME, s_salt, sizeof(s_salt));
    if (s_auth.set) {
        crypto_random(s_challenge, sizeof(s_challenge));
        rb_tlv(r, TAG_CHALLENGE, s_challenge, sizeof(s_challenge));
        rb_tlv(r, TAG_ALGORITHM, &s_auth.alg, 1);
    }
    return SW_OK;
}

static uint16_t do_put(const apdu_t *a)
{
    const uint8_t *p = a->data, *end = a->data + a->lc;
    const uint8_t *name = NULL, *key = NULL;
    size_t name_len = 0, key_len = 0;
    uint8_t prop = 0;
    uint32_t imf = 0;

    while (p < end) {
        uint8_t tag = *p++;
        if (tag == TAG_PROPERTY) {      // YubiKey quirk: value byte without length
            if (p >= end) return SW_WRONG_DATA;
            prop = *p++;
            continue;
        }
        if (p >= end) return SW_WRONG_DATA;
        size_t len = *p++;
        if (p + len > end) return SW_WRONG_DATA;
        if (tag == TAG_NAME) {
            name = p;
            name_len = len;
        } else if (tag == TAG_KEY) {
            key = p;
            key_len = len;
        } else if (tag == TAG_IMF && len == 4) {
            imf = ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
        }
        p += len;
    }
    if (!name || !key || name_len == 0 || name_len > MAX_NAME || key_len < 2 || key_len - 2 > MAX_KEY) {
        return SW_WRONG_DATA;
    }
    uint8_t type = key[0] & TYPE_MASK, alg = key[0] & ALG_MASK;
    if ((type != TYPE_HOTP && type != TYPE_TOTP) || alg < 1 || alg > 3) return SW_WRONG_DATA;
    if (key[1] < 6 || key[1] > 10) return SW_WRONG_DATA;

    int free_slot;
    int slot = cred_find(name, name_len, &free_slot);
    if (slot < 0) slot = free_slot;
    if (slot < 0) return SW_NOT_ENOUGH_SPACE;

    memset(&s_cred, 0, sizeof(s_cred));
    s_cred.name_len = name_len;
    memcpy(s_cred.name, name, name_len);
    s_cred.type_alg = key[0];
    s_cred.digits = key[1];
    s_cred.key_len = key_len - 2;
    memcpy(s_cred.key, key + 2, key_len - 2);
    s_cred.prop = prop;
    s_cred.counter = imf;
    char k[8];
    cred_key(slot, k);
    return store_set(NS_OATH, k, &s_cred, sizeof(s_cred)) == ESP_OK ? SW_OK : SW_NOT_ENOUGH_SPACE;
}

static uint16_t do_delete(const apdu_t *a)
{
    size_t len;
    const uint8_t *name = tlv_find(a->data, a->lc, TAG_NAME, &len);
    if (!name) return SW_WRONG_DATA;
    int slot = cred_find(name, len, NULL);
    if (slot < 0) return 0x6984;
    char k[8];
    cred_key(slot, k);
    store_del(NS_OATH, k);
    return SW_OK;
}

static uint16_t do_set_code(const apdu_t *a)
{
    size_t klen, clen, rlen;
    const uint8_t *key = tlv_find(a->data, a->lc, TAG_KEY, &klen);
    if (!key) return SW_WRONG_DATA;
    if (klen == 0) {                    // remove access code
        memset(&s_auth, 0, sizeof(s_auth));
        store_del(NS_OATH, "auth");
        return SW_OK;
    }
    const uint8_t *chal = tlv_find(a->data, a->lc, TAG_CHALLENGE, &clen);
    const uint8_t *resp = tlv_find(a->data, a->lc, TAG_RESPONSE, &rlen);
    if (!chal || !resp || klen != 17) return SW_WRONG_DATA;
    // The client proves it holds the key by answering its own challenge.
    uint8_t mac[64];
    size_t mlen = hmac_md(key[0], key + 1, 16, chal, clen, mac);
    if (rlen != mlen || !ct_equal(mac, resp, mlen)) return SW_WRONG_DATA;
    s_auth.set = 1;
    s_auth.alg = key[0] & ALG_MASK;
    memcpy(s_auth.key, key + 1, 16);
    store_set(NS_OATH, "auth", &s_auth, sizeof(s_auth));
    return SW_OK;
}

static uint16_t do_validate(const apdu_t *a, rbuf_t *r)
{
    size_t clen, rlen;
    const uint8_t *chal = tlv_find(a->data, a->lc, TAG_CHALLENGE, &clen);
    const uint8_t *resp = tlv_find(a->data, a->lc, TAG_RESPONSE, &rlen);
    if (!s_auth.set || !chal || !resp) return SW_WRONG_DATA;
    uint8_t mac[64];
    size_t mlen = hmac_md(s_auth.alg, s_auth.key, 16, s_challenge, sizeof(s_challenge), mac);
    crypto_random(s_challenge, sizeof(s_challenge));    // single use
    if (rlen != mlen || !ct_equal(mac, resp, mlen)) return SW_WRONG_DATA;
    s_authenticated = true;
    mlen = hmac_md(s_auth.alg, s_auth.key, 16, chal, clen, mac);
    rb_tlv(r, TAG_RESPONSE, mac, mlen);
    return SW_OK;
}

static uint16_t do_list(rbuf_t *r)
{
    for (int i = 0; i < MAX_CREDS; i++) {
        if (!cred_load(i, &s_cred)) continue;
        uint8_t v[1 + MAX_NAME];
        v[0] = s_cred.type_alg;
        memcpy(v + 1, s_cred.name, s_cred.name_len);
        if (!rb_tlv(r, TAG_NAME_LIST, v, 1 + s_cred.name_len)) return SW_UNKNOWN;
    }
    return SW_OK;
}

static uint16_t do_calculate(const apdu_t *a, rbuf_t *r)
{
    size_t nlen, clen = 0;
    const uint8_t *name = tlv_find(a->data, a->lc, TAG_NAME, &nlen);
    const uint8_t *chal = tlv_find(a->data, a->lc, TAG_CHALLENGE, &clen);
    if (!name) return SW_WRONG_DATA;
    int slot = cred_find(name, nlen, NULL);
    if (slot < 0) return 0x6984;
    if ((s_cred.type_alg & TYPE_MASK) == TYPE_TOTP && !chal) return SW_WRONG_DATA;

    if (s_cred.prop & PROP_TOUCH) {
        char label[MAX_NAME + 1];
        snprintf(label, sizeof(label), "%.*s", s_cred.name_len, s_cred.name);
        if (up_wait("OTP", label, 30000) != UP_OK) return SW_SECURITY_NOT_SATISFIED;
    }
    uint8_t mac[64];
    size_t mlen = calculate(slot, chal, clen, mac);
    if (!mlen) return SW_NOT_ENOUGH_SPACE;
    if (a->p2 == 0x01) {
        put_truncated(r, mac, mlen);
    } else {
        uint8_t v[1 + 64];
        v[0] = s_cred.digits;
        memcpy(v + 1, mac, mlen);
        rb_tlv(r, TAG_RESPONSE, v, 1 + mlen);
    }
    return SW_OK;
}

static uint16_t do_calc_all(const apdu_t *a, rbuf_t *r)
{
    size_t clen;
    const uint8_t *chal = tlv_find(a->data, a->lc, TAG_CHALLENGE, &clen);
    if (!chal) return SW_WRONG_DATA;
    for (int i = 0; i < MAX_CREDS; i++) {
        if (!cred_load(i, &s_cred)) continue;
        rb_tlv(r, TAG_NAME, s_cred.name, s_cred.name_len);
        if ((s_cred.type_alg & TYPE_MASK) == TYPE_HOTP) {
            rb_tlv(r, TAG_HOTP, &s_cred.digits, 1);
        } else if (s_cred.prop & PROP_TOUCH) {
            rb_tlv(r, TAG_TOUCH, &s_cred.digits, 1);
        } else {
            uint8_t mac[64];
            size_t mlen = calculate(i, chal, clen, mac);
            put_truncated(r, mac, mlen);
        }
    }
    return SW_OK;
}

static void hmac_key_name(int slot, char *k)
{
    snprintf(k, 8, "h%d", slot);
}

// Challenge-response slots answer without the OATH access code, like the
// YubiKey OTP application they imitate.
static uint16_t do_api_req(const apdu_t *a, rbuf_t *r)
{
    if (a->p1 == CMD_GET_SERIAL) {
        uint8_t mac[6];
        esp_efuse_mac_get_default(mac);
        rb_put(r, mac + 2, 4);
        return SW_OK;
    }
    if (a->p1 != CMD_HMAC_1 && a->p1 != CMD_HMAC_2) return SW_INCORRECT_P1P2;
    char k[8];
    uint8_t key[MAX_HMAC_KEY], mac[20];
    size_t klen = sizeof(key), n = a->lc;
    hmac_key_name(a->p1 == CMD_HMAC_1 ? 1 : 2, k);
    if (store_get(NS_OATH, k, key, &klen) != ESP_OK) return SW_FILE_NOT_FOUND;
    if (n == 0 || n > 64) return SW_WRONG_LENGTH;
    // As on a YubiKey: a 64-byte challenge ends in padding, the last byte and
    // all equal bytes before it.
    if (n == 64) {
        while (n > 0 && a->data[n - 1] == a->data[63]) n--;
    }
    hmac_any(1, key, klen, a->data, n, mac);
    memset(key, 0, sizeof(key));
    rb_put(r, mac, sizeof(mac));
    return SW_OK;
}

static uint16_t do_hmac_set(const apdu_t *a)
{
    if (a->p1 != 1 && a->p1 != 2) return SW_INCORRECT_P1P2;
    if (a->lc > MAX_HMAC_KEY) return SW_WRONG_LENGTH;
    char k[8], label[12];
    hmac_key_name(a->p1, k);
    snprintf(label, sizeof(label), "Slot %d", a->p1);
    if (up_wait(a->lc ? "Set HMAC?" : "Delete HMAC?", label, 30000) != UP_OK) return SW_SECURITY_NOT_SATISFIED;
    if (a->lc == 0) {
        store_del(NS_OATH, k);
        return SW_OK;
    }
    return store_set(NS_OATH, k, a->data, a->lc) == ESP_OK ? SW_OK : SW_NOT_ENOUGH_SPACE;
}

static uint16_t oath_process(const apdu_t *a, rbuf_t *r)
{
    if (a->ins == INS_RESET) {
        if (a->p1 != 0xDE || a->p2 != 0xAD) return SW_INCORRECT_P1P2;
        if (up_wait("Reset OTP?", "OTP and HMAC secrets erased", 30000) != UP_OK) {
            return SW_SECURITY_NOT_SATISFIED;
        }
        store_erase_ns(NS_OATH);
        load_state();
        s_authenticated = true;
        return SW_OK;
    }
    if (a->ins == INS_VALIDATE) return do_validate(a, r);
    if (a->ins == INS_API_REQ && a->p1 != 0x00) return do_api_req(a, r);
    if (!s_authenticated) return SW_SECURITY_NOT_SATISFIED;

    switch (a->ins) {
    case INS_PUT:       return do_put(a);
    case INS_DELETE:    return do_delete(a);
    case INS_SET_CODE:  return do_set_code(a);
    case INS_LIST:      return do_list(r);
    case INS_CALCULATE: return do_calculate(a, r);
    case INS_CALC_ALL:  return do_calc_all(a, r);
    case INS_HMAC_SET:  return do_hmac_set(a);
    default:            return SW_INS_NOT_SUPPORTED;
    }
}

const app_t app_oath = {
    .name = "oath",
    .aid = s_aid,
    .aid_len = sizeof(s_aid),
    .select = oath_select,
    .process = oath_process,
    .deselect = oath_deselect,
};

// Password manager app: records encrypted with a data key that is sealed to the
// device vault and opened with the device PIN (core/devpin).
#include "apps.h"
#include "pwd_rec.h"
#include "core/crypto.h"
#include "core/devpin.h"
#include "core/vault.h"
#include "core/store.h"
#include "core/up.h"
#include <stdio.h>
#include <string.h>

#define INS_RESET       0x04
#define INS_VERIFY      0x20
#define INS_LIST        0xA1
#define INS_GET         0xA2
#define INS_PUT         0xA3
#define INS_DELETE      0xA4
#define INS_GENERATE    0xA5

#define TAG_ID          0x08
#define TAG_STATUS      0x09
#define TAG_ENTRY       0x20

#define GET_WITH_PASS   0x01    // GET P1: include the password

#define APP_VERSION     2

// "dek" holds the data key sealed to the device vault.
#define DEK_BLOB_LEN    (32 + VAULT_OVERHEAD)

static const uint8_t s_aid[] = {0xF0, 0x51, 0x4B, 0x50, 0x57, 0x44};   // proprietary "QKPWD"

static uint8_t s_dek[32];
static bool s_unlocked;
static uint32_t s_vault_gen;        // devpin_vault_generation() of s_dek
static pwd_rec_t s_rec;
static uint8_t s_plain[PWD_REC_MAX_ENC];
static uint8_t s_blob[PWD_REC_MAX_ENC + SEAL_OVERHEAD];

static void lock(void)
{
    memset(s_dek, 0, sizeof(s_dek));
    s_unlocked = false;
}

static void rec_key(int i, char *k)
{
    snprintf(k, 8, "p%03d", i);
}

static bool rec_exists(int i)
{
    char k[8];
    size_t n = 0;
    rec_key(i, k);
    return store_get(NS_PWD, k, NULL, &n) == ESP_OK;     // size only, no read
}

static bool rec_load(int i)
{
    char k[8];
    size_t n = sizeof(s_blob), pl;
    rec_key(i, k);
    if (store_get(NS_PWD, k, s_blob, &n) != ESP_OK) return false;
    bool ok = aead_open(s_dek, s_blob, n, s_plain, &pl) && pwd_rec_decode(s_plain, pl, &s_rec);
    memset(s_plain, 0, sizeof(s_plain));
    return ok;
}

static uint16_t rec_save(int i)
{
    char k[8];
    size_t pl = pwd_rec_encode(&s_rec, true, s_plain, sizeof(s_plain));
    size_t n = pl ? aead_seal(s_dek, s_plain, pl, s_blob) : 0;
    memset(s_plain, 0, sizeof(s_plain));
    if (!n) return SW_UNKNOWN;
    rec_key(i, k);
    return store_set(NS_PWD, k, s_blob, n) == ESP_OK ? SW_OK : SW_NOT_ENOUGH_SPACE;
}

// A missing data key (fresh device, reset, or the own PIN of older firmware
// in "key") means the records can't be read: start from an empty store.
static void ensure_dek(void)
{
    uint8_t blob[DEK_BLOB_LEN], dek[32];
    if (store_read(NS_PWD, "dek", blob, sizeof(blob))) return;
    store_erase_ns(NS_PWD);
    crypto_random(dek, sizeof(dek));
    size_t n = vault_seal(devpin_vpub(), dek, sizeof(dek), blob);
    memset(dek, 0, sizeof(dek));
    if (n) store_set(NS_PWD, "dek", blob, n);
}

static uint16_t unlock(const uint8_t *pin, size_t len)
{
    uint8_t blob[DEK_BLOB_LEN], vpriv[32];
    size_t n;
    lock();
    ensure_dek();           // a new vault key (devpin_set) drops it
    switch (devpin_verify(DEVPIN_USER, pin, len, vpriv)) {
    case DEVPIN_OK:      break;
    case DEVPIN_WRONG:   return SW_VERIFY_FAIL(devpin_tries(DEVPIN_USER));
    case DEVPIN_BLOCKED: return SW_AUTH_BLOCKED;
    default:             return SW_UNKNOWN;
    }
    s_unlocked = store_read(NS_PWD, "dek", blob, sizeof(blob)) &&
                 vault_open(vpriv, blob, sizeof(blob), s_dek, &n) && n == sizeof(s_dek);
    memset(vpriv, 0, sizeof(vpriv));
    s_vault_gen = devpin_vault_generation();
    if (!s_unlocked) {
        lock();
        return SW_UNKNOWN;
    }
    return SW_OK;
}

static uint16_t pwd_select(const apdu_t *a, rbuf_t *r)
{
    (void)a;
    lock();
    ensure_dek();
    uint8_t count = 0;
    for (int i = 0; i < PWD_MAX_RECORDS; i++) count += rec_exists(i);
    // Version, PIN set (always: the device PIN), PIN tries, records, capacity.
    uint8_t st[] = {APP_VERSION, 1, devpin_tries(DEVPIN_USER), count, PWD_MAX_RECORDS};
    rb_tlv(r, TAG_STATUS, st, sizeof(st));
    return SW_OK;
}

static uint16_t do_verify(const apdu_t *a)
{
    if (a->lc) return unlock(a->data, a->lc);
    // Empty VERIFY: report the state.
    if (s_unlocked) return SW_OK;
    uint8_t t = devpin_tries(DEVPIN_USER);
    return t ? SW_VERIFY_FAIL(t) : SW_AUTH_BLOCKED;
}

static int parse_id(const apdu_t *a)
{
    size_t len;
    const uint8_t *v = tlv_find(a->data, a->lc, TAG_ID, &len);
    if (!v || len != 1 || v[0] >= PWD_MAX_RECORDS) return -1;
    return v[0];
}

// Entries without password and note, starting at id P1. The client continues
// from the last returned id + 1 until the response is empty.
static uint16_t do_list(const apdu_t *a, rbuf_t *r)
{
    uint8_t entry[PWD_REC_MAX_ENC + 3];
    for (int i = a->p1; i < PWD_MAX_RECORDS; i++) {
        if (!rec_load(i)) continue;
        s_rec.len[PWD_F_NOTE] = 0;
        entry[0] = TAG_ID;
        entry[1] = 1;
        entry[2] = i;
        size_t n = pwd_rec_encode(&s_rec, false, entry + 3, sizeof(entry) - 3);
        memset(&s_rec, 0, sizeof(s_rec));
        if (r->len + n + 3 + 4 > r->cap) break;     // page full
        rb_tlv(r, TAG_ENTRY, entry, n + 3);
    }
    memset(entry, 0, sizeof(entry));
    return SW_OK;
}

static uint16_t do_get(const apdu_t *a, rbuf_t *r)
{
    int id = parse_id(a);
    if (id < 0) return SW_WRONG_DATA;
    if (!rec_load(id)) return SW_REF_NOT_FOUND;
    bool with_pass = a->p1 & GET_WITH_PASS;
    uint16_t sw = SW_OK;
    if (with_pass && (s_rec.flags & PWD_FLAG_TOUCH)) {
        char label[PWD_MAX_NAME + 1];
        snprintf(label, sizeof(label), "%.*s", s_rec.len[PWD_F_NAME], s_rec.name);
        if (up_wait("Password?", label, 30000) != UP_OK) sw = SW_SECURITY_NOT_SATISFIED;
    }
    if (sw == SW_OK) {
        uint8_t id8 = id;
        rb_tlv(r, TAG_ID, &id8, 1);
        size_t n = pwd_rec_encode(&s_rec, with_pass, r->data + r->len, r->cap - r->len);
        if (n) r->len += n;
        else sw = SW_UNKNOWN;
    }
    memset(&s_rec, 0, sizeof(s_rec));
    return sw;
}

// With an id: updates fields present in the data. Without: adds a new record.
static uint16_t do_put(const apdu_t *a, rbuf_t *r)
{
    size_t len;
    int id;
    if (devpin_any_default()) return SW_CONDITIONS_NOT_SATISFIED;
    if (tlv_find(a->data, a->lc, TAG_ID, &len)) {
        id = parse_id(a);
        if (id < 0) return SW_WRONG_DATA;
        if (!rec_load(id)) return SW_REF_NOT_FOUND;
        // A touch-protected record changes only with a press: otherwise its
        // flag could be cleared and the password read without one.
        if (s_rec.flags & PWD_FLAG_TOUCH) {
            char label[PWD_MAX_NAME + 1];
            snprintf(label, sizeof(label), "%.*s", s_rec.len[PWD_F_NAME], s_rec.name);
            if (up_wait("Change record?", label, 30000) != UP_OK) {
                memset(&s_rec, 0, sizeof(s_rec));
                return SW_SECURITY_NOT_SATISFIED;
            }
        }
    } else {
        for (id = 0; id < PWD_MAX_RECORDS && rec_exists(id); id++) {}
        if (id == PWD_MAX_RECORDS) return SW_NOT_ENOUGH_SPACE;
        memset(&s_rec, 0, sizeof(s_rec));
    }
    uint16_t sw = SW_WRONG_DATA;
    if (pwd_rec_merge(&s_rec, a->data, a->lc) && s_rec.len[PWD_F_NAME] > 0) sw = rec_save(id);
    memset(&s_rec, 0, sizeof(s_rec));
    if (sw == SW_OK) {
        uint8_t id8 = id;
        rb_tlv(r, TAG_ID, &id8, 1);
    }
    return sw;
}

static uint16_t do_delete(const apdu_t *a)
{
    int id = parse_id(a);
    if (id < 0) return SW_WRONG_DATA;
    if (!rec_exists(id)) return SW_REF_NOT_FOUND;
    char k[8];
    rec_key(id, k);
    return store_del(NS_PWD, k) == ESP_OK ? SW_OK : SW_UNKNOWN;
}

static uint16_t do_generate(const apdu_t *a, rbuf_t *r)
{
    char pw[PWD_MAX_PASS];
    if (!pwd_generate(a->p1, a->p2, pw)) return SW_INCORRECT_P1P2;
    rb_put(r, pw, a->p1);
    memset(pw, 0, sizeof(pw));
    return SW_OK;
}

static uint16_t pwd_process(const apdu_t *a, rbuf_t *r)
{
    // A PIN change elsewhere replaced the vault key and dropped the data key.
    if (s_unlocked && s_vault_gen != devpin_vault_generation()) lock();
    switch (a->ins) {
    case INS_RESET:
        if (a->p1 != 0xDE || a->p2 != 0xAD) return SW_INCORRECT_P1P2;
        if (up_wait("Reset PWD?", "All passwords erased", 30000) != UP_OK) {
            return SW_SECURITY_NOT_SATISFIED;
        }
        lock();
        store_erase_ns(NS_PWD);
        ensure_dek();
        return SW_OK;
    case INS_VERIFY:     return do_verify(a);
    case INS_GENERATE:   return do_generate(a, r);
    }
    if (!s_unlocked) return SW_SECURITY_NOT_SATISFIED;
    switch (a->ins) {
    case INS_LIST:   return do_list(a, r);
    case INS_GET:    return do_get(a, r);
    case INS_PUT:    return do_put(a, r);
    case INS_DELETE: return do_delete(a);
    default:         return SW_INS_NOT_SUPPORTED;
    }
}

const app_t app_pwd = {
    .name = "pwd",
    .aid = s_aid,
    .aid_len = sizeof(s_aid),
    .select = pwd_select,
    .process = pwd_process,
    .deselect = lock,
};

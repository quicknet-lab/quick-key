// Host tests for platform-independent modules: CBOR codec, APDU layer,
// vault (secrets at rest), device PIN and its flash records, password
// manager records.
// Build and run: make -C test/host
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "fido/cbor.h"
#include "apdu/apdu.h"
#include "apps/apps.h"
#include "apps/pwd_rec.h"
#include "core/crypto.h"
#include "core/pinstore.h"
#include "core/vault.h"
#include "core/devpin.h"
#include "core/store.h"

// ---- stub applications for the APDU dispatcher ----

static size_t g_last_lc;
static uint8_t g_big[600];

static uint16_t stub_select(const apdu_t *a, rbuf_t *r) { (void)a; (void)r; return SW_OK; }
static int g_deselects;
static void stub_deselect(void) { g_deselects++; }

static uint16_t stub_process(const apdu_t *a, rbuf_t *r)
{
    g_last_lc = a->lc;
    if (a->ins == 0x01) {           // echo data
        rb_put(r, a->data, a->lc);
        return SW_OK;
    }
    if (a->ins == 0x02) {           // 600-byte response
        rb_put(r, g_big, sizeof(g_big));
        return SW_OK;
    }
    return SW_INS_NOT_SUPPORTED;
}

static const uint8_t aid_pgp[] = {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
static const uint8_t aid_x[] = {0xF0, 0x00, 0x00, 0x00, 0x01};
static const uint8_t aid_oath[] = {0xF0, 0x00, 0x00, 0x00, 0x02};
const app_t app_openpgp = {"pgp", aid_pgp, sizeof(aid_pgp), stub_select, stub_process, stub_deselect};
const app_t app_piv = {"x1", aid_x, sizeof(aid_x), stub_select, stub_process, NULL};
const app_t app_oath = {"x2", aid_oath, sizeof(aid_oath), stub_select, stub_process, NULL};
const app_t app_pwd = {"x5", aid_x, sizeof(aid_x), stub_select, stub_process, NULL};
const app_t app_admin = {"x3", aid_x, sizeof(aid_x), stub_select, stub_process, NULL};
const app_t app_fido = {"x4", aid_x, sizeof(aid_x), stub_select, stub_process, NULL};

static uint8_t out[5000];
extern bool g_store_fail;
extern uint8_t g_flash[0x2000];
extern int g_flash_cut;
void flash_power_on(void);

static uint16_t sw_of(size_t n) { return (out[n - 2] << 8) | out[n - 1]; }

static void test_cbor(void)
{
    uint8_t buf[256];
    cbor_w w;
    cbor_w_init(&w, buf, sizeof(buf));
    cbor_put_map(&w, 3);
    cbor_put_uint(&w, 1);
    cbor_put_bytes(&w, "abc", 3);
    cbor_put_int(&w, -7);
    cbor_put_text(&w, "public-key");
    cbor_put_uint(&w, 1000);
    cbor_put_bool(&w, true);
    assert(!w.err);
    // a3 01 43 616263 26 6a "public-key" 19 03e8 f5
    assert(buf[0] == 0xA3 && buf[1] == 0x01 && buf[2] == 0x43 && buf[6] == 0x26 && buf[7] == 0x6A);
    assert(buf[18] == 0x19 && buf[19] == 0x03 && buf[20] == 0xE8 && buf[21] == 0xF5);

    cbor_r r;
    size_t n, l;
    uint64_t u;
    int64_t i;
    const uint8_t *d;
    bool b;
    cbor_r_init(&r, buf, w.len);
    assert(cbor_get_map(&r, &n) && n == 3);
    assert(cbor_get_uint(&r, &u) && u == 1);
    assert(cbor_get_bytes(&r, &d, &l) && l == 3 && memcmp(d, "abc", 3) == 0);
    assert(cbor_get_int(&r, &i) && i == -7);
    assert(cbor_text_eq(&r, "public-key"));
    assert(cbor_get_uint(&r, &u) && u == 1000);
    assert(cbor_get_bool(&r, &b) && b);
    assert(!r.err && r.p == r.end);

    // skip over nested structure, reject truncated input
    cbor_r_init(&r, buf, w.len);
    assert(cbor_skip(&r) && r.p == r.end);
    cbor_r_init(&r, buf, w.len - 3);
    assert(!cbor_skip(&r));
    // indefinite length is rejected
    uint8_t indef[] = {0x9F, 0x01, 0xFF};
    cbor_r_init(&r, indef, sizeof(indef));
    assert(!cbor_skip(&r));
    printf("cbor ok\n");
}

static void test_apdu(void)
{
    size_t n;
    for (size_t i = 0; i < sizeof(g_big); i++) g_big[i] = (uint8_t)i;

    // no app selected
    uint8_t c0[] = {0x00, 0x01, 0x00, 0x00};
    n = apdu_process(c0, sizeof(c0), out, sizeof(out));
    assert(n == 2 && sw_of(n) == SW_CONDITIONS_NOT_SATISFIED);

    // unknown AID
    uint8_t sel_bad[] = {0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x11, 0x22, 0x33, 0x44};
    n = apdu_process(sel_bad, sizeof(sel_bad), out, sizeof(out));
    assert(sw_of(n) == SW_FILE_NOT_FOUND);

    // select OpenPGP by full AID (longer than registered prefix)
    uint8_t sel[] = {0x00, 0xA4, 0x04, 0x00, 0x08, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00};
    n = apdu_process(sel, sizeof(sel), out, sizeof(out));
    assert(n == 2 && sw_of(n) == SW_OK);

    // short case 4 echo
    uint8_t echo[] = {0x00, 0x01, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC, 0x00};
    n = apdu_process(echo, sizeof(echo), out, sizeof(out));
    assert(n == 5 && out[0] == 0xAA && out[2] == 0xCC && sw_of(n) == SW_OK);

    // malformed length
    uint8_t bad[] = {0x00, 0x01, 0x00, 0x00, 0x05, 0xAA};
    n = apdu_process(bad, sizeof(bad), out, sizeof(out));
    assert(sw_of(n) == SW_WRONG_LENGTH);
    // extended marker without the length bytes (must not read past the end)
    uint8_t bad_ext[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x05};
    n = apdu_process(bad_ext, sizeof(bad_ext), out, sizeof(out));
    assert(sw_of(n) == SW_WRONG_LENGTH);

    // command chaining: 2 + 3 bytes
    uint8_t ch1[] = {0x10, 0x01, 0x00, 0x00, 0x02, 0x01, 0x02};
    uint8_t ch2[] = {0x00, 0x01, 0x00, 0x00, 0x03, 0x03, 0x04, 0x05};
    n = apdu_process(ch1, sizeof(ch1), out, sizeof(out));
    assert(n == 2 && sw_of(n) == SW_OK);
    n = apdu_process(ch2, sizeof(ch2), out, sizeof(out));
    assert(g_last_lc == 5 && n == 7 && out[0] == 1 && out[4] == 5);
    // a different command in the middle of a chain breaks it, nothing is glued
    n = apdu_process(ch1, sizeof(ch1), out, sizeof(out));
    assert(sw_of(n) == SW_OK);
    uint8_t other[] = {0x00, 0x02, 0x00, 0x00, 0x01, 0x09};
    n = apdu_process(other, sizeof(other), out, sizeof(out));
    assert(n == 2 && sw_of(n) == SW_LAST_CMD_EXPECTED);
    n = apdu_process(ch2, sizeof(ch2), out, sizeof(out));
    assert(g_last_lc == 3 && n == 5);

    // short Le: 600 bytes -> 256 + 61xx, GET RESPONSE x2
    uint8_t big[] = {0x00, 0x02, 0x00, 0x00, 0x00};
    n = apdu_process(big, sizeof(big), out, sizeof(out));
    assert(n == 258 && sw_of(n) == 0x6100 && out[255] == 255);
    uint8_t gr[] = {0x00, 0xC0, 0x00, 0x00, 0x00};
    n = apdu_process(gr, sizeof(gr), out, sizeof(out));
    assert(n == 258 && sw_of(n) == (0x6100 | 88) && out[0] == (uint8_t)256);
    n = apdu_process(gr, sizeof(gr), out, sizeof(out));
    assert(n == 90 && sw_of(n) == SW_OK && out[87] == (uint8_t)599);

    // A5 with data pending: a command of its own outside OATH...
    n = apdu_process(big, sizeof(big), out, sizeof(out));
    assert(sw_of(n) == 0x6100);
    uint8_t a5[] = {0x00, 0xA5, 0x02, 0x04, 0x00};
    n = apdu_process(a5, sizeof(a5), out, sizeof(out));
    assert(n == 2 && sw_of(n) == SW_INS_NOT_SUPPORTED);
    // ...and SEND REMAINING in OATH. Leaving OpenPGP calls its deselect.
    uint8_t sel_oath[] = {0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x00, 0x00, 0x00, 0x02};
    int d0 = g_deselects;
    n = apdu_process(sel_oath, sizeof(sel_oath), out, sizeof(out));
    assert(sw_of(n) == SW_OK && g_deselects == d0 + 1);
    n = apdu_process(big, sizeof(big), out, sizeof(out));
    assert(sw_of(n) == 0x6100);
    n = apdu_process(a5, sizeof(a5), out, sizeof(out));
    assert(n == 258 && sw_of(n) == (0x6100 | 88) && out[0] == (uint8_t)256);
    n = apdu_process(sel, sizeof(sel), out, sizeof(out));
    assert(sw_of(n) == SW_OK);

    // extended Le: everything at once
    uint8_t bigx[] = {0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
    n = apdu_process(bigx, sizeof(bigx), out, sizeof(out));
    assert(n == 602 && sw_of(n) == SW_OK);

    // extended Lc echo
    uint8_t ext[7 + 300 + 2] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x2C};
    for (int i = 0; i < 300; i++) ext[7 + i] = (uint8_t)i;
    n = apdu_process(ext, sizeof(ext), out, sizeof(out));
    assert(g_last_lc == 300 && n == 302 && out[299] == (uint8_t)299);

    // TLV helpers
    uint8_t tb[400];
    rbuf_t r = {tb, 0, sizeof(tb)};
    rb_tlv(&r, 0x7F49, g_big, 300);
    rb_tlv(&r, 0x86, g_big, 2);
    size_t vl;
    const uint8_t *v = tlv_find(tb, r.len, 0x86, &vl);
    assert(v && vl == 2 && tb[2] == 0x82 && tb[3] == 0x01 && tb[4] == 0x2C);
    assert(tlv_find(tb, r.len, 0x7F49, &vl) && vl == 300);
    printf("apdu ok\n");
}

static void test_vault(void)
{
    // PBKDF2-HMAC-SHA256("password", "salt", 1 and 4096 iterations)
    static const uint8_t pb1[32] = {
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
        0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b};
    static const uint8_t pb4096[32] = {
        0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
        0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a};
    uint8_t k[32], k2[32];
    pbkdf2_sha256((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 1, k, 32);
    assert(memcmp(k, pb1, 32) == 0);
    pbkdf2_sha256((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 4096, k, 32);
    assert(memcmp(k, pb4096, 32) == 0);

    uint8_t salt[KDF_SALT_LEN] = {1, 2, 3};
    pin_kek((const uint8_t *)"123456", 6, salt, k);
    pin_kek((const uint8_t *)"123457", 6, salt, k2);
    assert(memcmp(k, k2, 32) != 0);
    salt[0] = 9;
    pin_kek((const uint8_t *)"123456", 6, salt, k2);
    assert(memcmp(k, k2, 32) != 0);

    // seal / open
    uint8_t msg[300], blob[300 + VAULT_OVERHEAD], plain[300];
    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)i;
    size_t n = sizeof(msg), bl = aead_seal(k, msg, n, blob), pl;
    assert(bl == n + SEAL_OVERHEAD);
    assert(aead_open(k, blob, bl, plain, &pl) && pl == n && memcmp(plain, msg, n) == 0);
    assert(!aead_open(k2, blob, bl, plain, &pl));           // wrong key
    blob[bl - 1] ^= 1;
    assert(!aead_open(k, blob, bl, plain, &pl));            // tampered ciphertext
    blob[bl - 1] ^= 1;
    blob[0] = 2;
    assert(!aead_open(k, blob, bl, plain, &pl));            // unknown version
    assert(!aead_open(k, blob, SEAL_OVERHEAD - 1, plain, &pl));
    uint8_t blob2[sizeof(blob)];
    aead_seal(k, msg, n, blob2);
    assert(memcmp(blob + 1, blob2 + 1, 12) != 0);           // fresh IV

    // key wrapped under a PIN
    uint8_t w[PIN_WRAP_LEN], w2[PIN_WRAP_LEN], key[32];
    pin_wrap((const uint8_t *)"123456", 6, k, w);
    assert(pin_unwrap((const uint8_t *)"123456", 6, w, key) && memcmp(key, k, 32) == 0);
    assert(!pin_unwrap((const uint8_t *)"123457", 6, w, key));
    assert(!pin_unwrap((const uint8_t *)"12345", 5, w, key));
    pin_wrap((const uint8_t *)"123456", 6, k, w2);
    assert(memcmp(w, w2, KDF_SALT_LEN) != 0);               // fresh salt

    // vault: seal to the public key, open with the private key
    uint8_t priv[32], pub[64], priv2[32], pub2[64];
    assert(vault_create(priv, pub) && vault_create(priv2, pub2));
    bl = vault_seal(pub, msg, n, blob);
    assert(bl == n + VAULT_OVERHEAD);
    assert(vault_open(priv, blob, bl, plain, &pl) && pl == n && memcmp(plain, msg, n) == 0);
    assert(!vault_open(priv2, blob, bl, plain, &pl));       // other vault
    blob[70] ^= 1;
    assert(!vault_open(priv, blob, bl, plain, &pl));        // tampered
    blob[70] ^= 1;
    blob[5] ^= 1;
    assert(!vault_open(priv, blob, bl, plain, &pl));        // tampered ephemeral key
    assert(!vault_open(priv, blob, VAULT_OVERHEAD - 1, plain, &pl));
    printf("vault ok\n");
}

static void unhex(const char *h, uint8_t *out)
{
    for (size_t i = 0; h[2 * i]; i++) sscanf(h + 2 * i, "%2hhx", &out[i]);
}

static void test_25519(void)
{
    uint8_t seed[32], pub[32], exp_pub[32], sig[64], exp_sig[64];
    unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed);
    unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", exp_pub);
    unhex("80d724b01e7ca260f4cc7f8de7c95f73cfac615bab1f762b6435b6ec26c8cf6d"
          "2c758dae2f87399a8eeda1cbcd2835ac5ba66d6ecaa3aba5e567a751053dc207", exp_sig);
    ed25519_pubkey(seed, pub);
    assert(memcmp(pub, exp_pub, 32) == 0);
    ed25519_sign(seed, (const uint8_t *)"abc", 3, sig);
    assert(memcmp(sig, exp_sig, 64) == 0);
    assert(seed[0] == 0x9d);                                // seed not wiped

    uint8_t a[32], b[32], pa[32], pb[32], exp[32], s1[32], s2[32];
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a);
    unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b);
    unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", exp);
    x25519_pubkey(a, pa);
    assert(memcmp(pa, exp, 32) == 0);
    x25519_pubkey(b, pb);
    unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", exp);
    assert(x25519(a, pb, s1) && x25519(b, pa, s2));
    assert(memcmp(s1, exp, 32) == 0 && memcmp(s2, exp, 32) == 0);
    uint8_t zero[32] = {0};
    assert(!x25519(a, zero, s1));                           // low-order point rejected
    printf("25519 ok\n");
}

static void set_field(pwd_rec_t *rec, int f, const char *v)
{
    size_t max;
    char *dst = pwd_field(rec, f, &max);
    rec->len[f] = strlen(v);
    memcpy(dst, v, rec->len[f]);
}

static void test_pwd(void)
{
    // record round trip, all fields at maximum length
    static pwd_rec_t rec, back;
    memset(&rec, 0, sizeof(rec));
    for (int f = 0; f < PWD_FIELDS; f++) {
        size_t max;
        char *v = pwd_field(&rec, f, &max);
        memset(v, 'a' + f, max);
        rec.len[f] = max;
    }
    rec.flags = PWD_FLAG_TOUCH;
    uint8_t enc[PWD_REC_MAX_ENC];
    size_t n = pwd_rec_encode(&rec, true, enc, sizeof(enc));
    assert(n > 0 && n <= PWD_REC_MAX_ENC);
    assert(pwd_rec_decode(enc, n, &back));
    assert(memcmp(&rec, &back, sizeof(rec)) == 0);
    assert(pwd_rec_encode(&rec, true, enc, n - 1) == 0);   // buffer too small

    // without password; empty fields are omitted
    memset(&rec, 0, sizeof(rec));
    set_field(&rec, PWD_F_NAME, "mail");
    set_field(&rec, PWD_F_PASS, "secret");
    n = pwd_rec_encode(&rec, false, enc, sizeof(enc));
    assert(n == 6 + 3);
    assert(pwd_rec_decode(enc, n, &back) && back.len[PWD_F_PASS] == 0 && back.flags == 0);

    // rejects: no name, oversized field, bad flags length
    uint8_t noname[] = {0x02, 0x01, 'x'};
    assert(!pwd_rec_decode(noname, sizeof(noname), &back));
    uint8_t big[2 + 2 + 65] = {0x01, 0x81, 65};
    assert(!pwd_rec_decode(big, 3 + 65, &back));
    uint8_t badflags[] = {0x01, 0x01, 'x', 0x07, 0x02, 0, 0};
    assert(!pwd_rec_decode(badflags, sizeof(badflags), &back));

    // merge: absent fields kept, empty value clears, name can't be oversized
    uint8_t upd[] = {0x03, 0x02, 'm', 'e', 0x02, 0x00, 0x07, 0x01, PWD_FLAG_TOUCH};
    assert(pwd_rec_decode(enc, n, &back));
    set_field(&back, PWD_F_URL, "a.b");
    assert(pwd_rec_merge(&back, upd, sizeof(upd)));
    assert(back.len[PWD_F_NAME] == 4 && back.len[PWD_F_URL] == 0 && back.len[PWD_F_LOGIN] == 2);
    assert(back.flags == PWD_FLAG_TOUCH);
    big[0] = 0x01;
    assert(!pwd_rec_merge(&back, big, 3 + 65));

    // generator
    char pw[PWD_MAX_PASS];
    assert(!pwd_generate(PWD_GEN_MIN - 1, PWD_GEN_LOWER, pw));
    assert(!pwd_generate(PWD_MAX_PASS + 1, PWD_GEN_LOWER, pw));
    assert(!pwd_generate(16, 0, pw));
    for (int i = 0; i < 200; i++) {
        assert(pwd_generate(PWD_GEN_MIN, 0x0F, pw));
        int lo = 0, up = 0, dg = 0, sy = 0;
        for (int j = 0; j < PWD_GEN_MIN; j++) {
            char c = pw[j];
            if (c >= 'a' && c <= 'z') lo++;
            else if (c >= 'A' && c <= 'Z') up++;
            else if (c >= '0' && c <= '9') dg++;
            else if (c > ' ' && c < 0x7F) sy++;
            else assert(0);
        }
        assert(lo && up && dg && sy);
    }
    assert(pwd_generate(PWD_MAX_PASS, PWD_GEN_DIGITS, pw));
    for (int j = 0; j < PWD_MAX_PASS; j++) assert(pw[j] >= '0' && pw[j] <= '9');
    printf("pwd ok\n");
}

static bool in_flash(const uint8_t *rec, size_t len)
{
    return memmem(g_flash, sizeof(g_flash), rec, len) != NULL;
}

static void test_pinstore(void)
{
    uint8_t a[300], b[300], c[300], r[300];
    memset(a, 0xA1, sizeof(a));
    memset(b, 0xB2, sizeof(b));
    memset(c, 0xC3, sizeof(c));

    // First start: zeroed (never erased) flash holds nothing and is cleaned.
    memset(g_flash, 0, sizeof(g_flash));
    assert(pinstore_read(r, sizeof(r)) == 0);
    for (size_t i = 0; i < sizeof(g_flash); i++) assert(g_flash[i] == 0xFF);
    assert(pinstore_write(a, sizeof(a)) && pinstore_read(r, sizeof(r)) == 1 && !memcmp(r, a, sizeof(r)));
    // A change leaves exactly one copy: the old one is erased whole.
    assert(pinstore_write(b, sizeof(b)) && pinstore_read(r, sizeof(r)) == 1 && !memcmp(r, b, sizeof(r)));
    assert(!in_flash(a, 32) && in_flash(b, sizeof(b)));
    // A read of another size fails and keeps the record.
    assert(pinstore_read(r, 100) == -1 && pinstore_read(r, sizeof(r)) == 1 && !memcmp(r, b, sizeof(r)));

    // Power cut at every step of a write (erase, write, erase old): after the
    // restart the old or the new record is there, never none and never both.
    for (int cut = 1;; cut++) {
        g_flash_cut = cut;
        bool done = pinstore_write(c, sizeof(c));
        flash_power_on();
        if (done) {
            assert(pinstore_read(r, sizeof(r)) == 1 && !memcmp(r, c, sizeof(r)) && !in_flash(b, 32));
            break;
        }
        assert(pinstore_read(r, sizeof(r)) == 1);
        assert(!memcmp(r, b, sizeof(r)) || !memcmp(r, c, sizeof(r)));
        assert(!(in_flash(b, 32) && in_flash(c, 32)));
        if (!memcmp(r, c, sizeof(r))) memcpy(b, c, sizeof(b));     // the cut came after the new copy was whole
        else assert(pinstore_write(b, sizeof(b)));                  // back to a known state
    }

    // Both copies valid (power lost before the old one was erased): the newer
    // wins and the older one goes.
    static uint8_t old[0x1000];
    assert(pinstore_write(a, sizeof(a)));
    int cur = g_flash[0] == 0xFF;
    memcpy(old, g_flash + cur * 0x1000, sizeof(old));
    assert(pinstore_write(b, sizeof(b)));
    memcpy(g_flash + cur * 0x1000, old, sizeof(old));
    assert(in_flash(a, 32) && in_flash(b, 32));
    assert(pinstore_read(r, sizeof(r)) == 1 && !memcmp(r, b, sizeof(r)) && !in_flash(a, 32));

    // A broken copy is never used, and is erased.
    cur = g_flash[0] == 0xFF;
    g_flash[cur * 0x1000 + 40] ^= 1;
    assert(pinstore_read(r, sizeof(r)) == 0);
    for (size_t i = 0; i < sizeof(g_flash); i++) assert(g_flash[i] == 0xFF);

    // Erase (factory reset) leaves nothing.
    assert(pinstore_write(a, sizeof(a)) && pinstore_erase() && pinstore_read(r, sizeof(r)) == 0);
    printf("pinstore ok\n");
}

static devpin_res_t verify_str(int who, const char *pin, uint8_t vpriv[32])
{
    return devpin_verify(who, (const uint8_t *)pin, strlen(pin), vpriv);
}

static void test_devpin(void)
{
    uint8_t vpriv[32], v2[32], blob[8 + VAULT_OVERHEAD], out[8], h[32];
    size_t n;
    store_init();
    assert(devpin_init());
    assert(devpin_tries(DEVPIN_USER) == DEVPIN_USER_TRIES && devpin_tries(DEVPIN_ADMIN) == DEVPIN_ADMIN_TRIES);
    assert(devpin_len(DEVPIN_USER) == 6 && devpin_len(DEVPIN_ADMIN) == 8);
    assert(devpin_is_default(DEVPIN_USER) && devpin_is_default(DEVPIN_ADMIN) && devpin_any_default());

    // The default PIN opens what is sealed to the vault; FIDO's PIN hash does too.
    assert(vault_seal(devpin_vpub(), (const uint8_t *)"secret!!", 8, blob));
    assert(verify_str(DEVPIN_USER, "123456", vpriv) == DEVPIN_OK);
    assert(vault_open(vpriv, blob, sizeof(blob), out, &n) && n == 8 && !memcmp(out, "secret!!", 8));
    sha256((const uint8_t *)"123456", 6, h);
    assert(devpin_verify_hash(DEVPIN_USER, h, v2) == DEVPIN_OK && !memcmp(vpriv, v2, 32));
    assert(verify_str(DEVPIN_ADMIN, "12345678", v2) == DEVPIN_OK && !memcmp(vpriv, v2, 32));

    // A wrong PIN costs a try, a right one restores them.
    assert(verify_str(DEVPIN_USER, "654321", v2) == DEVPIN_WRONG);
    assert(devpin_tries(DEVPIN_USER) == DEVPIN_USER_TRIES - 1);
    assert(verify_str(DEVPIN_USER, "123456", v2) == DEVPIN_OK);
    assert(devpin_tries(DEVPIN_USER) == DEVPIN_USER_TRIES);

    // Length limits: user 6-8, admin exactly 8.
    assert(!devpin_set(DEVPIN_USER, vpriv, (const uint8_t *)"12345", 5));
    assert(!devpin_set(DEVPIN_USER, vpriv, (const uint8_t *)"123456789", 9));
    assert(!devpin_set(DEVPIN_ADMIN, vpriv, (const uint8_t *)"1234567", 7));

    // While a factory PIN is set, a change replaces the vault key (the old one
    // may linger in flash under a PIN everybody knows); the factory value
    // itself can't be chosen.
    uint8_t vpub0[64];
    memcpy(vpub0, devpin_vpub(), 64);
    uint32_t vg = devpin_vault_generation(), g = devpin_generation();
    assert(!devpin_set(DEVPIN_USER, vpriv, (const uint8_t *)"123456", 6));
    assert(devpin_set(DEVPIN_USER, vpriv, (const uint8_t *)"pässw0", 7));    // any characters, UTF-8
    assert(devpin_vault_generation() == vg + 1 && devpin_generation() == g + 1);
    assert(memcmp(vpub0, devpin_vpub(), 64) != 0);
    assert(devpin_len(DEVPIN_USER) == 7);
    assert(!devpin_is_default(DEVPIN_USER) && devpin_is_default(DEVPIN_ADMIN) && devpin_any_default());
    assert(verify_str(DEVPIN_USER, "123456", v2) == DEVPIN_WRONG);
    assert(verify_str(DEVPIN_USER, "pässw0", vpriv) == DEVPIN_OK);
    assert(!vault_open(vpriv, blob, sizeof(blob), out, &n));                 // sealed to the old key
    // The admin PIN, not typed in for the change, opens the new key too.
    assert(verify_str(DEVPIN_ADMIN, "12345678", v2) == DEVPIN_OK && !memcmp(vpriv, v2, 32));

    // State survives a restart.
    devpin_init();
    assert(devpin_len(DEVPIN_USER) == 7 && verify_str(DEVPIN_USER, "pässw0", v2) == DEVPIN_OK);
    assert(!memcmp(vpriv, v2, 32));
    assert(!devpin_is_default(DEVPIN_USER) && devpin_is_default(DEVPIN_ADMIN));

    // A try that can't be stored (full flash) is not checked at all: no free
    // guesses after a reboot. A PIN change that can't be stored fails.
    g_store_fail = true;
    g_flash_cut = 1;
    assert(verify_str(DEVPIN_USER, "000000", v2) == DEVPIN_ERROR);
    assert(verify_str(DEVPIN_USER, "pässw0", v2) == DEVPIN_ERROR);
    assert(!devpin_set(DEVPIN_USER, vpriv, (const uint8_t *)"222222", 6));
    g_store_fail = false;
    flash_power_on();
    devpin_init();
    assert(devpin_tries(DEVPIN_USER) == DEVPIN_USER_TRIES && devpin_len(DEVPIN_USER) == 7);
    assert(verify_str(DEVPIN_USER, "pässw0", v2) == DEVPIN_OK && !memcmp(vpriv, v2, 32));

    // Blocked user PIN: even the right one fails; the admin PIN sets a new one.
    for (int i = 0; i < DEVPIN_USER_TRIES - 1; i++) assert(verify_str(DEVPIN_USER, "000000", v2) == DEVPIN_WRONG);
    assert(verify_str(DEVPIN_USER, "000000", v2) == DEVPIN_BLOCKED);
    assert(verify_str(DEVPIN_USER, "pässw0", v2) == DEVPIN_BLOCKED && devpin_tries(DEVPIN_USER) == 0);
    assert(verify_str(DEVPIN_ADMIN, "12345678", v2) == DEVPIN_OK);
    assert(devpin_set(DEVPIN_USER, v2, (const uint8_t *)"111111", 6));
    assert(devpin_tries(DEVPIN_USER) == DEVPIN_USER_TRIES);
    assert(verify_str(DEVPIN_USER, "111111", vpriv) == DEVPIN_OK);

    // The last factory PIN goes: one more new vault key, then changes keep it.
    vg = devpin_vault_generation();
    assert(verify_str(DEVPIN_ADMIN, "12345678", v2) == DEVPIN_OK && !memcmp(vpriv, v2, 32));
    assert(!devpin_set(DEVPIN_ADMIN, v2, (const uint8_t *)"12345678", 8));
    assert(devpin_set(DEVPIN_ADMIN, v2, (const uint8_t *)"87654321", 8) && !devpin_any_default());
    assert(devpin_vault_generation() == vg + 1);
    assert(verify_str(DEVPIN_USER, "111111", vpriv) == DEVPIN_OK);
    assert(verify_str(DEVPIN_ADMIN, "87654321", v2) == DEVPIN_OK && !memcmp(vpriv, v2, 32));
    assert(vault_seal(devpin_vpub(), (const uint8_t *)"secret!!", 8, blob));
    assert(devpin_set(DEVPIN_USER, vpriv, (const uint8_t *)"222222", 6) && devpin_vault_generation() == vg + 1);
    devpin_init();
    assert(verify_str(DEVPIN_USER, "222222", v2) == DEVPIN_OK);
    assert(vault_open(v2, blob, sizeof(blob), out, &n) && n == 8 && !memcmp(out, "secret!!", 8));

    // Power cut at any step of a PIN change: after the restart the old PIN
    // or the new one works, never neither (no silent factory PINs).
    for (int cut = 1;; cut++) {
        g_flash_cut = cut;
        bool done = devpin_set(DEVPIN_USER, v2, (const uint8_t *)"333333", 6);
        flash_power_on();
        assert(devpin_init() && !devpin_any_default());
        devpin_res_t r3 = verify_str(DEVPIN_USER, "333333", vpriv);
        if (done) assert(r3 == DEVPIN_OK);
        if (r3 == DEVPIN_OK) break;
        assert(verify_str(DEVPIN_USER, "222222", vpriv) == DEVPIN_OK);
    }
    assert(!memcmp(vpriv, v2, 32) && verify_str(DEVPIN_USER, "222222", v2) == DEVPIN_WRONG);

    // A record that can't be read (here: of another size) is not taken for a
    // first start: no new vault, nothing erased; the key must stop.
    uint8_t other[300];
    memset(other, 0x5A, sizeof(other));
    static uint8_t saved[0x2000];
    memcpy(saved, g_flash, sizeof(saved));
    assert(pinstore_write(other, sizeof(other)) && !devpin_init());
    assert(pinstore_read(other, sizeof(other)) == 1 && other[0] == 0x5A);
    memcpy(g_flash, saved, sizeof(saved));
    assert(devpin_init() && verify_str(DEVPIN_USER, "333333", v2) == DEVPIN_OK);

    // Admin PIN: 3 tries.
    for (int i = 0; i < DEVPIN_ADMIN_TRIES - 1; i++) assert(verify_str(DEVPIN_ADMIN, "00000000", v2) == DEVPIN_WRONG);
    assert(verify_str(DEVPIN_ADMIN, "00000000", v2) == DEVPIN_BLOCKED);
    assert(verify_str(DEVPIN_ADMIN, "87654321", v2) == DEVPIN_BLOCKED);
    printf("devpin ok\n");
}

int main(void)
{
    test_cbor();
    test_apdu();
    test_vault();
    test_25519();
    test_pwd();
    test_pinstore();
    test_devpin();
    printf("all tests passed\n");
    return 0;
}

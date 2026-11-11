// Host tests for the OTP application (apps/oath.c): the device PIN opens the
// accounts, they are sealed at rest, the plain accounts and the access code of
// firmware before 2.0.0 are taken over, HMAC slots answer without the PIN.
// Build and run: make -C test/host
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "apdu/apdu.h"
#include "apps/apps.h"
#include "core/devpin.h"
#include "core/store.h"
#include "core/up.h"
#include "core/vault.h"
#include "esp_mac.h"

// ---- what oath.c needs from the rest of the firmware ----

static const uint8_t aid_x[] = {0xF0, 0x00, 0x00, 0x00, 0x01};
static uint16_t stub(const apdu_t *a, rbuf_t *r) { (void)a; (void)r; return SW_OK; }
const app_t app_openpgp = {"x0", aid_x, sizeof(aid_x), stub, stub, NULL};
const app_t app_piv = {"x1", aid_x, sizeof(aid_x), stub, stub, NULL};
const app_t app_pwd = {"x2", aid_x, sizeof(aid_x), stub, stub, NULL};
const app_t app_admin = {"x3", aid_x, sizeof(aid_x), stub, stub, NULL};
const app_t app_fido = {"x4", aid_x, sizeof(aid_x), stub, stub, NULL};

static int g_presses;
up_result_t up_wait(const char *title, const char *detail, uint32_t timeout_ms)
{
    (void)title;
    (void)detail;
    (void)timeout_ms;
    g_presses++;
    return UP_OK;
}

esp_err_t esp_efuse_mac_get_default(uint8_t *mac)
{
    memset(mac, 0x5A, 6);
    return ESP_OK;
}

// ---- helpers ----

// An account as firmware before 2.0.0 stored it, in plain text.
typedef struct {
    uint8_t name_len;
    char name[64];
    uint8_t type_alg;
    uint8_t digits;
    uint8_t key_len;
    uint8_t key[64];
    uint8_t prop;
    uint32_t counter;
} legacy_cred_t;

static const char RFC_KEY[] = "12345678901234567890";      // RFC 4226 / 6238 SHA-1 secret
static uint8_t g_out[4096];
static rbuf_t g_r;

static uint16_t cmd(uint8_t ins, uint8_t p1, uint8_t p2, const void *data, size_t lc)
{
    apdu_t a = {0x00, ins, p1, p2, data, lc, 0, false};
    g_r = (rbuf_t){g_out, 0, sizeof(g_out)};
    return app_oath.process(&a, &g_r);
}

static void select_oath(void)
{
    apdu_t a = {0};
    g_r = (rbuf_t){g_out, 0, sizeof(g_out)};
    assert(app_oath.select(&a, &g_r) == SW_OK);
}

static uint16_t verify(const char *pin)
{
    return cmd(0x20, 0, 0, pin, strlen(pin));
}

static size_t put_tlv(uint8_t *p, uint8_t tag, const void *v, size_t n)
{
    p[0] = tag;
    p[1] = n;
    memcpy(p + 2, v, n);
    return n + 2;
}

// The code for an account, -1 on an error.
static long code(const char *name, uint64_t t)
{
    uint8_t d[100], chal[8];
    for (int i = 0; i < 8; i++) chal[i] = t >> (56 - 8 * i);
    size_t n = put_tlv(d, 0x71, name, strlen(name));
    n += put_tlv(d + n, 0x74, chal, 8);
    if (cmd(0xA2, 0, 1, d, n) != SW_OK) return -1;
    size_t vl;
    const uint8_t *v = tlv_find(g_out, g_r.len, 0x76, &vl);
    assert(v && vl == 5);
    long m = 1;
    for (int i = 0; i < v[0]; i++) m *= 10;
    return (long)(((uint32_t)v[1] << 24 | v[2] << 16 | v[3] << 8 | v[4]) % m);
}

static uint16_t put(const char *name, uint8_t type_alg, uint8_t digits, const char *key)
{
    uint8_t d[200], k[66] = {type_alg, digits};
    memcpy(k + 2, key, strlen(key));
    size_t n = put_tlv(d, 0x71, name, strlen(name));
    n += put_tlv(d + n, 0x73, k, 2 + strlen(key));
    return cmd(0x01, 0, 0, d, n);
}

static int listed(void)
{
    assert(cmd(0xA1, 0, 0, NULL, 0) == SW_OK);
    int count = 0;
    for (size_t i = 0; i + 2 <= g_r.len; i += 2 + g_out[i + 1]) count += g_out[i] == 0x72;
    return count;
}

static size_t stored_size(const char *key)
{
    size_t n = 0;
    return store_get(NS_OATH, key, NULL, &n) == ESP_OK ? n : 0;
}

static void write_legacy(int slot, const char *name, uint8_t type_alg, uint8_t digits, uint32_t counter)
{
    legacy_cred_t c = {0};
    char k[8];
    c.name_len = strlen(name);
    memcpy(c.name, name, c.name_len);
    c.type_alg = type_alg;
    c.digits = digits;
    c.key_len = strlen(RFC_KEY);
    memcpy(c.key, RFC_KEY, c.key_len);
    c.counter = counter;
    snprintf(k, sizeof(k), "c%02d", slot);
    assert(store_set(NS_OATH, k, &c, sizeof(c)) == ESP_OK);
}

static void change_pin(int who, const char *old, const char *new)
{
    uint8_t vpriv[32];
    assert(devpin_verify(who, (const uint8_t *)old, strlen(old), vpriv) == DEVPIN_OK);
    assert(devpin_set(who, vpriv, (const uint8_t *)new, strlen(new)));
}

int main(void)
{
    store_init();
    assert(devpin_init());

    // Factory PINs: the accounts stay closed, VERIFY doesn't spend a try.
    // An account of older firmware waits in plain text, with its access code.
    write_legacy(0, "hotp", 0x11, 6, 0);
    uint8_t auth[18] = {1, 1};
    assert(store_set(NS_OATH, "auth", auth, sizeof(auth)) == ESP_OK);
    select_oath();
    assert(cmd(0xA1, 0, 0, NULL, 0) == SW_SECURITY_NOT_SATISFIED);
    assert(verify("123456") == SW_CONDITIONS_NOT_SATISFIED && devpin_tries(DEVPIN_USER) == DEVPIN_USER_TRIES);
    assert(cmd(0x20, 0, 0, NULL, 0) == SW_CONDITIONS_NOT_SATISFIED);
    assert(stored_size("dek") == 0 && stored_size("c00") == sizeof(legacy_cred_t));
    printf("oath: closed while a factory PIN is set\n");

    // Both PINs changed: the next SELECT makes the data key and seals the old
    // account; the access code is gone.
    change_pin(DEVPIN_USER, "123456", "314159");
    change_pin(DEVPIN_ADMIN, "12345678", "27182818");
    select_oath();
    assert(stored_size("dek") == 32 + VAULT_OVERHEAD);
    assert(stored_size("c00") == sizeof(legacy_cred_t) + SEAL_OVERHEAD && stored_size("auth") == 0);
    size_t n = stored_size("c00");
    uint8_t blob[300];
    assert(store_get(NS_OATH, "c00", blob, &n) == ESP_OK && !memmem(blob, n, RFC_KEY, 8) && !memmem(blob, n, "hotp", 4));
    printf("oath: old plain accounts sealed, access code dropped\n");

    // Nothing without the PIN; a wrong one costs a try.
    assert(cmd(0xA1, 0, 0, NULL, 0) == SW_SECURITY_NOT_SATISFIED && code("hotp", 0) == -1);
    assert(put("new", 0x21, 6, RFC_KEY) == SW_SECURITY_NOT_SATISFIED);
    assert(cmd(0x20, 0, 0, NULL, 0) == SW_VERIFY_FAIL(DEVPIN_USER_TRIES));
    assert(verify("000000") == SW_VERIFY_FAIL(DEVPIN_USER_TRIES - 1));
    assert(cmd(0xA1, 0, 0, NULL, 0) == SW_SECURITY_NOT_SATISFIED);
    // The access code commands of older firmware are gone.
    assert(cmd(0xA3, 0, 0, NULL, 0) == SW_SECURITY_NOT_SATISFIED);
    printf("oath: PIN needed, wrong PIN counted\n");

    // The PIN opens them: RFC 4226 HOTP codes, the counter kept sealed.
    assert(verify("314159") == SW_OK && devpin_tries(DEVPIN_USER) == DEVPIN_USER_TRIES);
    assert(cmd(0x20, 0, 0, NULL, 0) == SW_OK);
    assert(listed() == 1);
    assert(code("hotp", 0) == 755224 && code("hotp", 0) == 287082);
    assert(cmd(0x03, 0, 0, NULL, 0) == SW_INS_NOT_SUPPORTED);
    // RFC 6238 SHA-1, T = 59 s.
    assert(put("totp", 0x21, 8, RFC_KEY) == SW_OK && code("totp", 59 / 30) == 94287082);
    assert(stored_size("c01") == sizeof(legacy_cred_t) + SEAL_OVERHEAD);
    assert(listed() == 2);
    printf("oath: HOTP/TOTP vectors, new account sealed\n");

    // Leaving the application locks it; the HOTP counter survived.
    app_oath.deselect();
    select_oath();
    assert(cmd(0xA1, 0, 0, NULL, 0) == SW_SECURITY_NOT_SATISFIED);
    assert(verify("314159") == SW_OK && code("hotp", 0) == 359152);
    printf("oath: deselect locks, counter kept\n");

    // A plain account left by a power cut during the takeover is sealed at the next unlock.
    write_legacy(2, "late", 0x11, 6, 0);
    app_oath.deselect();
    select_oath();
    assert(stored_size("c02") == sizeof(legacy_cred_t));
    assert(verify("314159") == SW_OK && stored_size("c02") == sizeof(legacy_cred_t) + SEAL_OVERHEAD);
    assert(listed() == 3 && code("late", 0) == 755224);
    // Delete.
    uint8_t d[20];
    n = put_tlv(d, 0x71, "late", 4);
    assert(cmd(0x02, 0, 0, d, n) == SW_OK && listed() == 2 && stored_size("c02") == 0);
    printf("oath: leftover plain account sealed at unlock, delete\n");

    // HMAC slots: written with the PIN and a press, answered without the PIN.
    app_oath.deselect();
    select_oath();
    uint8_t secret[20], chal[64] = {0};
    memset(secret, 0x0B, sizeof(secret));
    assert(cmd(0xB1, 1, 0, secret, sizeof(secret)) == SW_SECURITY_NOT_SATISFIED);
    assert(verify("314159") == SW_OK);
    int presses = g_presses;
    assert(cmd(0xB1, 1, 0, secret, sizeof(secret)) == SW_OK && g_presses == presses + 1);
    app_oath.deselect();
    select_oath();
    memcpy(chal, "Hi There", 8);
    memset(chal + 8, 56, 56);                       // KeePassXC padding
    assert(cmd(0x01, 0x30, 0, chal, 64) == SW_OK && g_r.len == 20);
    assert(g_out[0] == 0xB6 && g_out[19] == 0x00);  // RFC 2202 test case 1: b617...be00
    printf("oath: HMAC slot written with the PIN, answers without it\n");

    // Reset: a press, no PIN; everything erased, a fresh data key, still locked.
    presses = g_presses;
    assert(cmd(0x04, 0xDE, 0xAD, NULL, 0) == SW_OK && g_presses == presses + 1);
    assert(stored_size("c00") == 0 && stored_size("c01") == 0 && stored_size("h1") == 0);
    assert(stored_size("dek") == 32 + VAULT_OVERHEAD);
    assert(cmd(0xA1, 0, 0, NULL, 0) == SW_SECURITY_NOT_SATISFIED);
    assert(verify("314159") == SW_OK && listed() == 0);
    assert(put("again", 0x21, 6, RFC_KEY) == SW_OK && listed() == 1);
    printf("oath: reset\n");

    // A blocked PIN keeps them closed.
    app_oath.deselect();
    select_oath();
    for (int i = DEVPIN_USER_TRIES - 1; i > 0; i--) assert(verify("000000") == SW_VERIFY_FAIL(i));
    assert(verify("000000") == SW_AUTH_BLOCKED && verify("314159") == SW_AUTH_BLOCKED);
    assert(cmd(0xA1, 0, 0, NULL, 0) == SW_SECURITY_NOT_SATISFIED);
    printf("oath: blocked PIN\n");

    printf("all oath tests passed\n");
    return 0;
}

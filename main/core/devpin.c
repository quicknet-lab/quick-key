#include "devpin.h"
#include "chipkey.h"
#include "crypto.h"
#include "pinstore.h"
#include "store.h"
#include "vault.h"
#include <string.h>

typedef struct {
    uint8_t tries[2];
    uint8_t len[2];             // copy of pin_rec_t.len (kept for the storage format)
} pin_state_t;

// Each PIN has a P-256 key pair of its own: the private half is wrapped under
// the PIN (run through `rounds` chip-bound HMACs, chipkey), the vault key is
// sealed to the public half. So a new vault key can be sealed to a PIN that
// nobody has just typed in, which lets devpin_set() replace the vault key.
typedef struct {
    uint32_t rounds;
    uint8_t len;
    uint8_t wrap[PIN_WRAP_LEN];
    uint8_t pub[64];
    uint8_t vault[32 + VAULT_OVERHEAD];
} pin_rec_t;

// Both records, the vault public key and the factory-PIN flags are one
// pinstore record, so a power cut can't leave them out of step. Not in NVS:
// a replaced NVS value lingers in flash, and with it a wrap under an old PIN.
typedef struct {
    pin_rec_t rec[2];
    uint8_t vpub[64];
    uint8_t is_default;         // bit per PIN: still the factory value
} pin_keys_t;

static const char *s_default[2] = {"123456", "12345678"};
static const uint8_t s_max_tries[2] = {DEVPIN_USER_TRIES, DEVPIN_ADMIN_TRIES};
static pin_state_t s_st;
static pin_keys_t s_keys, s_next;
static uint32_t s_generation, s_vault_generation;

static bool save(void)
{
    return store_set(NS_PIN, "state", &s_st, sizeof(s_st)) == ESP_OK;
}

static void pin_hash(const uint8_t *pin, size_t len, uint8_t h[DEVPIN_HASH_LEN])
{
    uint8_t d[32];
    sha256(pin, len, d);
    memcpy(h, d, DEVPIN_HASH_LEN);
    memset(d, 0, sizeof(d));
}

static bool is_factory(int who, const uint8_t *pin, size_t len)
{
    return len == strlen(s_default[who]) && memcmp(pin, s_default[who], len) == 0;
}

// A new key pair for the PIN, the vault key sealed to it.
static bool make_rec(pin_rec_t *rec, const uint8_t *pin, size_t len, const uint8_t vpriv[32])
{
    uint8_t h[DEVPIN_HASH_LEN], k[32], priv[32];
    memset(rec, 0, sizeof(*rec));
    rec->len = len;
    rec->rounds = chipkey_rounds();
    pin_hash(pin, len, h);
    bool ok = p256_keygen(priv, rec->pub) && chipkey_stretch(h, sizeof(h), rec->rounds, k);
    if (ok) {
        pin_wrap(k, sizeof(k), priv, rec->wrap);
        ok = vault_seal(rec->pub, vpriv, 32, rec->vault) != 0;
    }
    memset(h, 0, sizeof(h));
    memset(k, 0, sizeof(k));
    memset(priv, 0, sizeof(priv));
    return ok;
}

bool devpin_init(void)
{
    // A record that can't be read is never taken for a first start: that
    // would replace the vault and lose every key and password.
    int rec = pinstore_read(&s_keys, sizeof(s_keys));
    if (rec < 0) return false;
    if (rec && store_read(NS_PIN, "state", &s_st, sizeof(s_st))) {
        s_st.len[DEVPIN_USER] = s_keys.rec[DEVPIN_USER].len;      // the records hold the authoritative lengths
        s_st.len[DEVPIN_ADMIN] = s_keys.rec[DEVPIN_ADMIN].len;
        return true;
    }
    uint8_t vpriv[32];
    bool ok;
    store_erase_ns(NS_PIN);
    pinstore_erase();
    memset(&s_keys, 0, sizeof(s_keys));
    // A record that failed to come out whole is never stored: the PINs
    // would never open it.
    ok = vault_create(vpriv, s_keys.vpub);
    for (int who = 0; who < 2; who++) {
        ok = ok && make_rec(&s_keys.rec[who], (const uint8_t *)s_default[who], strlen(s_default[who]), vpriv);
        s_st.len[who] = strlen(s_default[who]);
        s_st.tries[who] = s_max_tries[who];
    }
    memset(vpriv, 0, sizeof(vpriv));
    s_keys.is_default = 3;
    return ok && pinstore_write(&s_keys, sizeof(s_keys)) && save();
}

const uint8_t *devpin_vpub(void)
{
    return s_keys.vpub;
}

uint8_t devpin_tries(int who)
{
    return s_st.tries[who];
}

uint32_t devpin_generation(void)
{
    return s_generation;
}

uint32_t devpin_vault_generation(void)
{
    return s_vault_generation;
}

bool devpin_is_default(int who)
{
    return s_keys.is_default & (1 << who);
}

bool devpin_any_default(void)
{
    return s_keys.is_default != 0;
}

size_t devpin_len(int who)
{
    return s_st.len[who];
}

bool devpin_len_ok(int who, size_t len)
{
    return len >= (who == DEVPIN_USER ? DEVPIN_USER_MIN : DEVPIN_ADMIN_MIN) && len <= DEVPIN_MAX;
}

devpin_res_t devpin_verify_hash(int who, const uint8_t hash[DEVPIN_HASH_LEN], uint8_t vpriv[32])
{
    const pin_rec_t *rec = &s_keys.rec[who];
    uint8_t k[32], priv[32];
    size_t n;
    if (s_st.tries[who] == 0) return DEVPIN_BLOCKED;
    // Count the attempt first so that cutting power can't give free tries; if
    // the counter can't be stored (e.g. full flash), don't check the PIN at all.
    s_st.tries[who]--;
    if (!save()) {
        s_st.tries[who]++;
        return DEVPIN_ERROR;
    }
    if (!chipkey_stretch(hash, DEVPIN_HASH_LEN, rec->rounds, k)) return DEVPIN_ERROR;
    // A wrong PIN fails the GCM tag of the wrap.
    if (!pin_unwrap(k, sizeof(k), rec->wrap, priv)) {
        memset(k, 0, sizeof(k));
        return s_st.tries[who] ? DEVPIN_WRONG : DEVPIN_BLOCKED;
    }
    bool ok = vault_open(priv, rec->vault, sizeof(rec->vault), vpriv, &n) && n == 32;
    memset(k, 0, sizeof(k));
    memset(priv, 0, sizeof(priv));
    // The PIN was right either way: it gets its tries back.
    s_st.tries[who] = s_max_tries[who];
    save();
    return ok ? DEVPIN_OK : DEVPIN_ERROR;
}

devpin_res_t devpin_verify(int who, const uint8_t *pin, size_t len, uint8_t vpriv[32])
{
    uint8_t h[DEVPIN_HASH_LEN];
    pin_hash(pin, len, h);
    devpin_res_t res = devpin_verify_hash(who, h, vpriv);
    memset(h, 0, sizeof(h));
    return res;
}

bool devpin_set(int who, const uint8_t vpriv[32], const uint8_t *pin, size_t len)
{
    if (!devpin_len_ok(who, len) || is_factory(who, pin, len)) return false;
    // While a PIN is still the factory one, the vault key is replaced with
    // every change. Nothing is sealed to it then but the password manager's
    // still empty data key, and anyone could have taken the old one with a
    // PIN everybody knows.
    bool rotate = s_keys.is_default != 0;
    uint8_t nv[32];
    bool ok = true;
    s_next = s_keys;
    if (rotate) {
        ok = vault_create(nv, s_next.vpub) &&
             vault_seal(s_next.rec[!who].pub, nv, 32, s_next.rec[!who].vault) != 0;
        vpriv = nv;
    }
    ok = ok && make_rec(&s_next.rec[who], pin, len, vpriv);
    s_next.is_default &= ~(1 << who);
    // Dropped first: a power cut afterwards leaves it to be made again for
    // whichever vault key is in place.
    if (ok && rotate) ok = store_del(NS_PWD, "dek") == ESP_OK;
    ok = ok && pinstore_write(&s_next, sizeof(s_next));
    memset(nv, 0, sizeof(nv));
    if (ok) s_keys = s_next;
    memset(&s_next, 0, sizeof(s_next));
    if (!ok) return false;
    s_st.len[who] = len;
    s_st.tries[who] = s_max_tries[who];
    save();
    s_generation++;
    if (rotate) s_vault_generation++;
    return true;
}

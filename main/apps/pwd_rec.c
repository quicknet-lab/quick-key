#include "pwd_rec.h"
#include "apdu/apdu.h"
#include "core/crypto.h"
#include <string.h>

char *pwd_field(pwd_rec_t *rec, int f, size_t *max)
{
    switch (f) {
    case PWD_F_NAME:  *max = PWD_MAX_NAME;  return rec->name;
    case PWD_F_URL:   *max = PWD_MAX_URL;   return rec->url;
    case PWD_F_LOGIN: *max = PWD_MAX_LOGIN; return rec->login;
    case PWD_F_PASS:  *max = PWD_MAX_PASS;  return rec->pass;
    case PWD_F_NOTE:  *max = PWD_MAX_NOTE;  return rec->note;
    default:          *max = PWD_MAX_OTP;   return rec->otp;
    }
}

size_t pwd_rec_encode(const pwd_rec_t *rec, bool with_pass, uint8_t *out, size_t cap)
{
    rbuf_t r = {out, 0, cap};
    for (int f = 0; f < PWD_FIELDS; f++) {
        size_t max;
        const char *v = pwd_field((pwd_rec_t *)rec, f, &max);
        if (rec->len[f] == 0 || (f == PWD_F_PASS && !with_pass)) continue;
        if (!rb_tlv(&r, PWD_TAG_FIELD(f), v, rec->len[f])) return 0;
    }
    if (!rb_tlv(&r, PWD_TAG_FLAGS, &rec->flags, 1)) return 0;
    return r.len;
}

bool pwd_rec_merge(pwd_rec_t *rec, const uint8_t *in, size_t len)
{
    for (int f = 0; f < PWD_FIELDS; f++) {
        size_t max, vl;
        char *dst = pwd_field(rec, f, &max);
        const uint8_t *v = tlv_find(in, len, PWD_TAG_FIELD(f), &vl);
        if (!v) continue;
        if (vl > max) return false;
        memcpy(dst, v, vl);
        rec->len[f] = vl;
    }
    size_t vl;
    const uint8_t *v = tlv_find(in, len, PWD_TAG_FLAGS, &vl);
    if (v) {
        if (vl != 1) return false;
        rec->flags = v[0];
    }
    return true;
}

bool pwd_rec_decode(const uint8_t *in, size_t len, pwd_rec_t *rec)
{
    memset(rec, 0, sizeof(*rec));
    return pwd_rec_merge(rec, in, len) && rec->len[PWD_F_NAME] > 0;
}

static const char *const s_sets[] = {
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
    "!#$%&()*+,-./:;<=>?@[]^_{|}~",
};

// Uniform index below n (n <= 256) by rejection sampling.
static size_t rand_below(size_t n)
{
    uint8_t b;
    do {
        crypto_random(&b, 1);
    } while (b >= 256 - 256 % n);
    return b % n;
}

bool pwd_generate(size_t len, uint8_t sets, char *out)
{
    sets &= 0x0F;
    if (len < PWD_GEN_MIN || len > PWD_MAX_PASS || !sets) return false;
    char alphabet[128];
    size_t n = 0;
    for (int i = 0; i < 4; i++) {
        if (!(sets & (1 << i))) continue;
        size_t l = strlen(s_sets[i]);
        memcpy(alphabet + n, s_sets[i], l);
        n += l;
    }
    // Regenerate until every selected set is present: keeps the distribution uniform
    // over all valid passwords.
    uint8_t seen;
    do {
        seen = 0;
        for (size_t i = 0; i < len; i++) {
            out[i] = alphabet[rand_below(n)];
            for (int s = 0; s < 4; s++) {
                if ((sets & (1 << s)) && strchr(s_sets[s], out[i])) seen |= 1 << s;
            }
        }
    } while (seen != sets);
    return true;
}

#include "u2f.h"
#include "fido.h"
#include "ctap2.h"
#include "core/crypto.h"
#include "core/up.h"
#include "apdu/apdu.h"
#include <string.h>

#define U2F_REGISTER     0x01
#define U2F_AUTHENTICATE 0x02
#define U2F_VERSION      0x03

#define U2F_AUTH_CHECK_ONLY   0x07
#define U2F_AUTH_ENFORCE      0x03
#define U2F_AUTH_DONT_ENFORCE 0x08

static size_t sw(uint8_t *r, size_t n, uint16_t s)
{
    r[n] = s >> 8;
    r[n + 1] = s & 0xFF;
    return n + 2;
}

static size_t do_register(const uint8_t *d, size_t lc, uint8_t *r, size_t cap)
{
    if (lc != 64) return sw(r, 0, SW_WRONG_LENGTH);
    const uint8_t *chal = d, *app = d + 32;
    uint8_t req[33] = {U2F_REGISTER};
    memcpy(req + 1, app, 32);
    if (!up_poll_u2f("Register U2F", req)) return sw(r, 0, SW_CONDITIONS_NOT_SATISFIED);

    uint8_t kh[CRED_ID_LEN], priv[32], pub[64];
    fido_new_cred(app, CRED_ID_VER, kh, priv);
    p256_pubkey(priv, pub);
    memset(priv, 0, sizeof(priv));

    size_t cert_len;
    const uint8_t *cert = fido_att_cert(&cert_len);
    if (cap < 1 + 65 + 1 + CRED_ID_LEN + cert_len + 72 + 2) return sw(r, 0, SW_UNKNOWN);

    size_t n = 0;
    r[n++] = 0x05;
    r[n++] = 0x04;
    memcpy(r + n, pub, 64);
    n += 64;
    r[n++] = CRED_ID_LEN;
    memcpy(r + n, kh, CRED_ID_LEN);
    n += CRED_ID_LEN;
    memcpy(r + n, cert, cert_len);
    n += cert_len;

    // Signed: 0x00 || appId || challenge || keyHandle || publicKey
    uint8_t msg[1 + 32 + 32 + CRED_ID_LEN + 65], hash[32], rs[64];
    msg[0] = 0x00;
    memcpy(msg + 1, app, 32);
    memcpy(msg + 33, chal, 32);
    memcpy(msg + 65, kh, CRED_ID_LEN);
    msg[65 + CRED_ID_LEN] = 0x04;
    memcpy(msg + 66 + CRED_ID_LEN, pub, 64);
    sha256(msg, sizeof(msg), hash);
    if (!p256_sign(fido_att_priv(), hash, 32, rs)) return sw(r, 0, SW_UNKNOWN);
    n += ecdsa_sig_to_der(rs, r + n);
    return sw(r, n, SW_OK);
}

static size_t do_authenticate(uint8_t p1, const uint8_t *d, size_t lc, uint8_t *r)
{
    if (lc < 65 || lc != 65 + (size_t)d[64]) return sw(r, 0, SW_WRONG_LENGTH);
    const uint8_t *chal = d, *app = d + 32, *kh = d + 65;
    uint8_t priv[32];
    // Discoverable credentials are CTAP2-only (they must honour deletion).
    if (d[64] != CRED_ID_LEN || kh[0] != CRED_ID_VER || !fido_open_cred(app, kh, d[64], priv)) {
        return sw(r, 0, SW_WRONG_DATA);
    }

    if (p1 == U2F_AUTH_CHECK_ONLY) {
        memset(priv, 0, sizeof(priv));
        return sw(r, 0, SW_CONDITIONS_NOT_SATISFIED);
    }
    uint8_t flags = 0;
    if (p1 == U2F_AUTH_ENFORCE) {
        uint8_t req[33] = {U2F_AUTHENTICATE};
        memcpy(req + 1, app, 32);
        if (!up_poll_u2f("Sign in U2F", req)) {
            memset(priv, 0, sizeof(priv));
            return sw(r, 0, SW_CONDITIONS_NOT_SATISFIED);
        }
        flags = 0x01;
    } else if (p1 != U2F_AUTH_DONT_ENFORCE) {
        memset(priv, 0, sizeof(priv));
        return sw(r, 0, SW_WRONG_P1P2);
    }

    uint32_t ctr;
    if (!fido_next_counter(&ctr)) {
        memset(priv, 0, sizeof(priv));
        return sw(r, 0, SW_UNKNOWN);
    }
    uint8_t msg[32 + 1 + 4 + 32], hash[32], rs[64];
    memcpy(msg, app, 32);
    msg[32] = flags;
    msg[33] = ctr >> 24;
    msg[34] = ctr >> 16;
    msg[35] = ctr >> 8;
    msg[36] = ctr;
    memcpy(msg + 37, chal, 32);
    sha256(msg, sizeof(msg), hash);
    bool ok = p256_sign(priv, hash, 32, rs);
    memset(priv, 0, sizeof(priv));
    if (!ok) return sw(r, 0, SW_UNKNOWN);

    size_t n = 0;
    memcpy(r, msg + 32, 5);
    n = 5;
    n += ecdsa_sig_to_der(rs, r + n);
    return sw(r, n, SW_OK);
}

size_t u2f_process(const uint8_t *req, size_t len, uint8_t *resp, size_t cap)
{
    if (len < 4) return sw(resp, 0, SW_WRONG_LENGTH);
    if (req[0] != 0x00) return sw(resp, 0, SW_CLA_NOT_SUPPORTED);
    if (ctap2_always_uv()) return sw(resp, 0, SW_INS_NOT_SUPPORTED);   // CTAP 2.1: no U2F with alwaysUv

    // U2F uses extended length encoding; accept short encoding too.
    const uint8_t *data = NULL;
    size_t lc = 0;
    if (len > 4) {
        if (req[4] == 0 && len >= 7) {
            lc = (req[5] << 8) | req[6];
            data = req + 7;
            if (7 + lc > len) return sw(resp, 0, SW_WRONG_LENGTH);
        } else if (len > 5) {
            lc = req[4];
            data = req + 5;
            if (5 + lc > len) return sw(resp, 0, SW_WRONG_LENGTH);
        }
    }

    switch (req[1]) {
    case U2F_REGISTER:
        return do_register(data, lc, resp, cap);
    case U2F_AUTHENTICATE:
        return do_authenticate(req[2], data, lc, resp);
    case U2F_VERSION:
        if (lc != 0) return sw(resp, 0, SW_WRONG_LENGTH);
        memcpy(resp, "U2F_V2", 6);
        return sw(resp, 6, SW_OK);
    default:
        return sw(resp, 0, SW_INS_NOT_SUPPORTED);
    }
}

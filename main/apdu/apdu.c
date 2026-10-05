#include "apdu.h"
#include "apps/apps.h"
#include <string.h>

static const app_t *s_selected;

// Command chaining (CLA bit 0x10) accumulation.
static uint8_t s_chain[APDU_MAX_DATA];
static size_t s_chain_len;
static bool s_chaining;
static uint8_t s_chain_hdr[4];     // CLA (without the chaining bit), INS, P1, P2 of the chain

// Pending response data for GET RESPONSE.
static uint8_t s_pending[APDU_MAX_DATA];
static size_t s_pending_len, s_pending_off;

static const app_t *const s_apps[] = {
    &app_openpgp,
    &app_piv,
    &app_oath,
    &app_pwd,
    &app_admin,
    &app_fido,
};

static void deselect(void)
{
    if (s_selected && s_selected->deselect) s_selected->deselect();
    s_selected = NULL;
}

void apdu_reset(void)
{
    deselect();
    s_chaining = false;
    s_chain_len = 0;
    s_pending_len = s_pending_off = 0;
}

static bool parse(const uint8_t *in, size_t len, apdu_t *a)
{
    if (len < 4) return false;
    memset(a, 0, sizeof(*a));
    a->cla = in[0];
    a->ins = in[1];
    a->p1 = in[2];
    a->p2 = in[3];
    const uint8_t *b = in + 4;
    size_t n = len - 4;
    if (n == 0) return true;
    if (n == 1) {                                   // case 2 short
        a->le = b[0] ? b[0] : 256;
        return true;
    }
    if (b[0] != 0) {                                // short Lc
        a->lc = b[0];
        if (n == 1 + a->lc) {
            a->data = b + 1;
            return true;
        }
        if (n == 2 + a->lc) {
            a->data = b + 1;
            a->le = b[1 + a->lc] ? b[1 + a->lc] : 256;
            return true;
        }
        return false;
    }
    a->ext = true;
    if (n < 3) return false;
    if (n == 3) {                                   // case 2 extended
        size_t le = (b[1] << 8) | b[2];
        a->le = le ? le : 65536;
        return true;
    }
    a->lc = (b[1] << 8) | b[2];
    if (a->lc == 0) return false;
    if (n == 3 + a->lc) {
        a->data = b + 3;
        return true;
    }
    if (n == 5 + a->lc) {
        a->data = b + 3;
        size_t le = (b[3 + a->lc] << 8) | b[4 + a->lc];
        a->le = le ? le : 65536;
        return true;
    }
    return false;
}

static size_t finish(uint8_t *out, size_t datalen, uint16_t sw)
{
    out[datalen] = sw >> 8;
    out[datalen + 1] = sw & 0xFF;
    return datalen + 2;
}

// Returns as much pending data as the host asked for, with 61xx if more remains.
static size_t emit_pending(const apdu_t *a, uint8_t *out, size_t cap)
{
    size_t remaining = s_pending_len - s_pending_off;
    size_t max = a->ext ? (a->le ? a->le : 65536) : (a->le ? a->le : 256);
    if (max > cap - 2) max = cap - 2;
    size_t n = remaining < max ? remaining : max;
    memcpy(out, s_pending + s_pending_off, n);
    s_pending_off += n;
    remaining -= n;
    if (remaining == 0) {
        s_pending_len = s_pending_off = 0;
        return finish(out, n, SW_OK);
    }
    return finish(out, n, SW_BYTES_REMAINING | (remaining > 255 ? 0 : remaining));
}

static const app_t *find_app(const uint8_t *aid, size_t len)
{
    for (size_t i = 0; i < sizeof(s_apps) / sizeof(s_apps[0]); i++) {
        const app_t *app = s_apps[i];
        // Partial (prefix) AID selection as allowed by ISO 7816-4.
        if (len >= 5 && len <= app->aid_len && memcmp(aid, app->aid, len) == 0) return app;
        if (len > app->aid_len && memcmp(aid, app->aid, app->aid_len) == 0) return app;
    }
    return NULL;
}

size_t apdu_process(const uint8_t *in, size_t len, uint8_t *out, size_t cap)
{
    apdu_t a;
    if (!parse(in, len, &a)) return finish(out, 0, SW_WRONG_LENGTH);

    // GET RESPONSE, or OATH SEND REMAINING (A5) while data is pending. In the
    // other applications A5 is a command of its own (OpenPGP SELECT DATA,
    // password GENERATE).
    bool send_remaining = a.ins == 0xA5 && s_pending_len && s_selected == &app_oath;
    if ((a.ins == 0xC0 || send_remaining) && (a.cla & 0x10) == 0) {
        if (s_pending_len == 0) return finish(out, 0, SW_CONDITIONS_NOT_SATISFIED);
        return emit_pending(&a, out, cap);
    }
    s_pending_len = s_pending_off = 0;

    // A chain continues only with the same command: anything else (e.g. from
    // another program on the host) must not be glued to its data.
    uint8_t hdr[4] = {a.cla & ~0x10, a.ins, a.p1, a.p2};
    if (s_chaining && memcmp(hdr, s_chain_hdr, 4) != 0) {
        s_chaining = false;
        return finish(out, 0, SW_LAST_CMD_EXPECTED);
    }
    if (a.cla & 0x10) {                             // chained, more to come
        if (!s_chaining) {
            s_chain_len = 0;
            memcpy(s_chain_hdr, hdr, 4);
        }
        if (s_chain_len + a.lc > sizeof(s_chain)) {
            s_chaining = false;
            return finish(out, 0, SW_WRONG_LENGTH);
        }
        memcpy(s_chain + s_chain_len, a.data, a.lc);
        s_chain_len += a.lc;
        s_chaining = true;
        return finish(out, 0, SW_OK);
    }
    if (s_chaining) {
        if (s_chain_len + a.lc > sizeof(s_chain)) {
            s_chaining = false;
            return finish(out, 0, SW_WRONG_LENGTH);
        }
        memcpy(s_chain + s_chain_len, a.data, a.lc);
        s_chain_len += a.lc;
        a.data = s_chain;
        a.lc = s_chain_len;
        s_chaining = false;
    }

    rbuf_t r = {.data = s_pending, .len = 0, .cap = sizeof(s_pending)};
    uint16_t sw;
    if (a.ins == 0xA4 && a.p1 == 0x04) {            // SELECT by AID
        const app_t *app = find_app(a.data, a.lc);
        if (!app) return finish(out, 0, SW_FILE_NOT_FOUND);
        deselect();
        s_selected = app;
        sw = app->select(&a, &r);
        // 6285: application is terminated but stays selected for ACTIVATE FILE.
        if (sw != SW_OK && sw != 0x6285) s_selected = NULL;
    } else if (!s_selected) {
        return finish(out, 0, SW_CONDITIONS_NOT_SATISFIED);
    } else {
        sw = s_selected->process(&a, &r);
    }

    if (r.len == 0 || sw != SW_OK) return finish(out, 0, sw);
    s_pending_len = r.len;
    s_pending_off = 0;
    return emit_pending(&a, out, cap);
}

bool rb_put(rbuf_t *r, const void *d, size_t n)
{
    if (r->len + n > r->cap) return false;
    memcpy(r->data + r->len, d, n);
    r->len += n;
    return true;
}

bool rb_byte(rbuf_t *r, uint8_t b)
{
    return rb_put(r, &b, 1);
}

bool rb_tlv(rbuf_t *r, uint16_t tag, const void *v, size_t n)
{
    uint8_t h[6];
    size_t k = 0;
    if (tag > 0xFF) h[k++] = tag >> 8;
    h[k++] = tag & 0xFF;
    if (n < 0x80) {
        h[k++] = n;
    } else if (n < 0x100) {
        h[k++] = 0x81;
        h[k++] = n;
    } else {
        h[k++] = 0x82;
        h[k++] = n >> 8;
        h[k++] = n & 0xFF;
    }
    return rb_put(r, h, k) && (n == 0 || rb_put(r, v, n));
}

const uint8_t *tlv_find(const uint8_t *p, size_t len, uint16_t tag, size_t *vlen)
{
    const uint8_t *end = p + len;
    while (p < end) {
        uint16_t t = *p++;
        if ((t & 0x1F) == 0x1F) {
            if (p >= end) return NULL;
            t = (t << 8) | *p++;
        }
        if (p >= end) return NULL;
        size_t l = *p++;
        if (l == 0x81) {
            if (p >= end) return NULL;
            l = *p++;
        } else if (l == 0x82) {
            if (p + 1 >= end) return NULL;
            l = (p[0] << 8) | p[1];
            p += 2;
        } else if (l > 0x82) {
            return NULL;
        }
        if (p + l > end) return NULL;
        if (t == tag) {
            *vlen = l;
            return p;
        }
        p += l;
    }
    return NULL;
}

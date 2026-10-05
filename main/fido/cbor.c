#include "cbor.h"
#include <string.h>

void cbor_w_init(cbor_w *w, uint8_t *buf, size_t cap)
{
    w->p = buf;
    w->len = 0;
    w->cap = cap;
    w->err = false;
}

static void put(cbor_w *w, const void *d, size_t n)
{
    if (w->err || w->len + n > w->cap) {
        w->err = true;
        return;
    }
    memcpy(w->p + w->len, d, n);
    w->len += n;
}

static void head(cbor_w *w, uint8_t major, uint64_t v)
{
    uint8_t b[9];
    size_t n;
    major <<= 5;
    if (v < 24) {
        b[0] = major | v;
        n = 1;
    } else if (v <= 0xFF) {
        b[0] = major | 24;
        b[1] = v;
        n = 2;
    } else if (v <= 0xFFFF) {
        b[0] = major | 25;
        b[1] = v >> 8;
        b[2] = v;
        n = 3;
    } else if (v <= 0xFFFFFFFFu) {
        b[0] = major | 26;
        for (int i = 0; i < 4; i++) b[1 + i] = v >> (24 - 8 * i);
        n = 5;
    } else {
        b[0] = major | 27;
        for (int i = 0; i < 8; i++) b[1 + i] = v >> (56 - 8 * i);
        n = 9;
    }
    put(w, b, n);
}

void cbor_put_uint(cbor_w *w, uint64_t v) { head(w, CBOR_UINT, v); }

void cbor_put_int(cbor_w *w, int64_t v)
{
    if (v >= 0) head(w, CBOR_UINT, (uint64_t)v);
    else head(w, CBOR_NEGINT, (uint64_t)(-1 - v));
}

void cbor_put_bytes(cbor_w *w, const void *d, size_t n)
{
    head(w, CBOR_BYTES, n);
    put(w, d, n);
}

void cbor_put_textn(cbor_w *w, const char *s, size_t n)
{
    head(w, CBOR_TEXT, n);
    put(w, s, n);
}

void cbor_put_text(cbor_w *w, const char *s) { cbor_put_textn(w, s, strlen(s)); }
void cbor_put_map(cbor_w *w, size_t n) { head(w, CBOR_MAP, n); }
void cbor_put_array(cbor_w *w, size_t n) { head(w, CBOR_ARRAY, n); }

void cbor_put_bool(cbor_w *w, bool b)
{
    uint8_t v = b ? 0xF5 : 0xF4;
    put(w, &v, 1);
}

void cbor_r_init(cbor_r *r, const uint8_t *buf, size_t len)
{
    r->p = buf;
    r->end = buf + len;
    r->err = false;
}

int cbor_peek(const cbor_r *r)
{
    if (r->err || r->p >= r->end) return -1;
    return r->p[0] >> 5;
}

// Reads an item head; returns major type, value in *v.
static int rd_head(cbor_r *r, uint64_t *v)
{
    if (r->err || r->p >= r->end) goto fail;
    uint8_t ib = *r->p++;
    uint8_t ai = ib & 0x1F;
    if (ai < 24) {
        *v = ai;
    } else if (ai <= 27) {
        size_t n = 1u << (ai - 24);
        if ((size_t)(r->end - r->p) < n) goto fail;
        *v = 0;
        for (size_t i = 0; i < n; i++) *v = (*v << 8) | *r->p++;
    } else {
        goto fail;      // indefinite lengths are not allowed in CTAP2
    }
    return ib >> 5;
fail:
    r->err = true;
    return -1;
}

static bool expect(cbor_r *r, int major, uint64_t *v)
{
    const uint8_t *save = r->p;
    int m = rd_head(r, v);
    if (m != major) {
        r->p = save;
        if (m >= 0) r->err = true;
        return false;
    }
    return true;
}

bool cbor_get_uint(cbor_r *r, uint64_t *v) { return expect(r, CBOR_UINT, v); }

bool cbor_get_int(cbor_r *r, int64_t *v)
{
    uint64_t u;
    int m = rd_head(r, &u);
    if (m == CBOR_UINT) *v = (int64_t)u;
    else if (m == CBOR_NEGINT) *v = -1 - (int64_t)u;
    else {
        r->err = true;
        return false;
    }
    return true;
}

static bool get_str(cbor_r *r, int major, const uint8_t **d, size_t *n)
{
    uint64_t len;
    if (!expect(r, major, &len)) return false;
    if ((uint64_t)(r->end - r->p) < len) {
        r->err = true;
        return false;
    }
    *d = r->p;
    *n = len;
    r->p += len;
    return true;
}

bool cbor_get_bytes(cbor_r *r, const uint8_t **d, size_t *n) { return get_str(r, CBOR_BYTES, d, n); }

bool cbor_get_text(cbor_r *r, const char **s, size_t *n)
{
    return get_str(r, CBOR_TEXT, (const uint8_t **)s, n);
}

bool cbor_get_map(cbor_r *r, size_t *n)
{
    uint64_t v;
    if (!expect(r, CBOR_MAP, &v)) return false;
    *n = v;
    return true;
}

bool cbor_get_array(cbor_r *r, size_t *n)
{
    uint64_t v;
    if (!expect(r, CBOR_ARRAY, &v)) return false;
    *n = v;
    return true;
}

bool cbor_get_bool(cbor_r *r, bool *b)
{
    if (r->err || r->p >= r->end || (*r->p != 0xF4 && *r->p != 0xF5)) {
        r->err = true;
        return false;
    }
    *b = *r->p++ == 0xF5;
    return true;
}

static bool skip_depth(cbor_r *r, int depth)
{
    if (depth > 8) {
        r->err = true;
        return false;
    }
    uint64_t v;
    int m = rd_head(r, &v);
    switch (m) {
    case CBOR_UINT:
    case CBOR_NEGINT:
    case CBOR_SIMPLE:
        return true;
    case CBOR_BYTES:
    case CBOR_TEXT:
        if ((uint64_t)(r->end - r->p) < v) {
            r->err = true;
            return false;
        }
        r->p += v;
        return true;
    case CBOR_ARRAY:
        for (uint64_t i = 0; i < v; i++) if (!skip_depth(r, depth + 1)) return false;
        return true;
    case CBOR_MAP:
        for (uint64_t i = 0; i < 2 * v; i++) if (!skip_depth(r, depth + 1)) return false;
        return true;
    case CBOR_TAG:
        return skip_depth(r, depth + 1);
    default:
        return false;
    }
}

bool cbor_skip(cbor_r *r) { return skip_depth(r, 0); }

bool cbor_text_eq(cbor_r *r, const char *s)
{
    cbor_r save = *r;
    const char *t;
    size_t n;
    if (cbor_peek(r) != CBOR_TEXT || !cbor_get_text(r, &t, &n)) {
        *r = save;
        return false;
    }
    if (n == strlen(s) && memcmp(t, s, n) == 0) return true;
    *r = save;
    return false;
}

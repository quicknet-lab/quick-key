#pragma once
// Minimal CBOR encoder/decoder for CTAP2 (definite lengths only).
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define CBOR_UINT   0
#define CBOR_NEGINT 1
#define CBOR_BYTES  2
#define CBOR_TEXT   3
#define CBOR_ARRAY  4
#define CBOR_MAP    5
#define CBOR_TAG    6
#define CBOR_SIMPLE 7

typedef struct {
    uint8_t *p;
    size_t len, cap;
    bool err;
} cbor_w;

void cbor_w_init(cbor_w *w, uint8_t *buf, size_t cap);
void cbor_put_uint(cbor_w *w, uint64_t v);
void cbor_put_int(cbor_w *w, int64_t v);
void cbor_put_bytes(cbor_w *w, const void *d, size_t n);
void cbor_put_text(cbor_w *w, const char *s);
void cbor_put_textn(cbor_w *w, const char *s, size_t n);
void cbor_put_map(cbor_w *w, size_t n);
void cbor_put_array(cbor_w *w, size_t n);
void cbor_put_bool(cbor_w *w, bool b);

typedef struct {
    const uint8_t *p, *end;
    bool err;
} cbor_r;

void cbor_r_init(cbor_r *r, const uint8_t *buf, size_t len);
int cbor_peek(const cbor_r *r);     // major type or -1
bool cbor_get_uint(cbor_r *r, uint64_t *v);
bool cbor_get_int(cbor_r *r, int64_t *v);
bool cbor_get_bytes(cbor_r *r, const uint8_t **d, size_t *n);
bool cbor_get_text(cbor_r *r, const char **s, size_t *n);
bool cbor_get_map(cbor_r *r, size_t *n);
bool cbor_get_array(cbor_r *r, size_t *n);
bool cbor_get_bool(cbor_r *r, bool *b);
bool cbor_skip(cbor_r *r);
// True if the next item is text equal to s (consumes it when equal).
bool cbor_text_eq(cbor_r *r, const char *s);

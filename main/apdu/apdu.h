#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SW_OK                   0x9000
#define SW_BYTES_REMAINING      0x6100
#define SW_WRONG_LENGTH         0x6700
#define SW_SECURITY_NOT_SATISFIED 0x6982
#define SW_AUTH_BLOCKED         0x6983
#define SW_LAST_CMD_EXPECTED    0x6883
#define SW_CONDITIONS_NOT_SATISFIED 0x6985
#define SW_WRONG_DATA           0x6A80
#define SW_FUNC_NOT_SUPPORTED   0x6A81
#define SW_FILE_NOT_FOUND       0x6A82
#define SW_NOT_ENOUGH_SPACE     0x6A84
#define SW_INCORRECT_P1P2       0x6A86
#define SW_REF_NOT_FOUND        0x6A88
#define SW_WRONG_P1P2           0x6B00
#define SW_INS_NOT_SUPPORTED    0x6D00
#define SW_CLA_NOT_SUPPORTED    0x6E00
#define SW_UNKNOWN              0x6F00
#define SW_VERIFY_FAIL(n)       (0x63C0 | ((n) & 0x0F))

#define APDU_MAX_DATA 4096

typedef struct {
    uint8_t cla, ins, p1, p2;
    const uint8_t *data;
    size_t lc;
    size_t le;          // 0 when absent; 256/65536 for "max"
    bool ext;
} apdu_t;

// Response buffer the applications append to.
typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} rbuf_t;

typedef struct {
    const char *name;
    const uint8_t *aid;
    size_t aid_len;
    // SELECT with this AID; may append FCI/select data.
    uint16_t (*select)(const apdu_t *a, rbuf_t *r);
    uint16_t (*process)(const apdu_t *a, rbuf_t *r);
    // Optional: another application gets selected or the card is reset;
    // drops PIN state and wipes keys held in RAM.
    void (*deselect)(void);
} app_t;

void apdu_reset(void);
// Full command APDU in, response APDU (data + SW) out. Returns response length.
size_t apdu_process(const uint8_t *in, size_t len, uint8_t *out, size_t cap);

// Helpers for applications.
bool rb_put(rbuf_t *r, const void *d, size_t n);
bool rb_byte(rbuf_t *r, uint8_t b);
// Appends tag (1 or 2 bytes) + BER length + value.
bool rb_tlv(rbuf_t *r, uint16_t tag, const void *v, size_t n);
// Finds a tag in a BER-TLV list (top level only). Tags up to 2 bytes.
const uint8_t *tlv_find(const uint8_t *p, size_t len, uint16_t tag, size_t *vlen);

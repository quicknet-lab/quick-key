#pragma once
// Password manager: record format and password generator.
// Platform-independent (host-tested); storage and APDU live in pwd.c.
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define PWD_MAX_RECORDS 250

// Record fields. The same TLV tags are used in storage and in the APDU protocol.
enum { PWD_F_NAME, PWD_F_URL, PWD_F_LOGIN, PWD_F_PASS, PWD_F_NOTE, PWD_F_OTP, PWD_FIELDS };
#define PWD_TAG_FIELD(f) ((uint8_t)(0x01 + (f)))  // 0x01 name ... 0x06 otp
#define PWD_TAG_FLAGS   0x07

#define PWD_MAX_NAME    64
#define PWD_MAX_URL     128
#define PWD_MAX_LOGIN   64
#define PWD_MAX_PASS    128
#define PWD_MAX_NOTE    256
#define PWD_MAX_OTP     64      // name of a linked OATH credential

#define PWD_FLAG_TOUCH  0x01    // reading the password needs a button press

typedef struct {
    uint8_t flags;
    uint16_t len[PWD_FIELDS];
    char name[PWD_MAX_NAME];
    char url[PWD_MAX_URL];
    char login[PWD_MAX_LOGIN];
    char pass[PWD_MAX_PASS];
    char note[PWD_MAX_NOTE];
    char otp[PWD_MAX_OTP];
} pwd_rec_t;

// Largest encoded record: field values + flags + 4 bytes of tag/length each.
#define PWD_REC_MAX_ENC (PWD_MAX_NAME + PWD_MAX_URL + PWD_MAX_LOGIN + PWD_MAX_PASS + \
                         PWD_MAX_NOTE + PWD_MAX_OTP + 1 + 4 * (PWD_FIELDS + 1))

// Pointer to a field's buffer and its capacity.
char *pwd_field(pwd_rec_t *rec, int f, size_t *max);

// Record <-> TLV list. Encoding skips empty fields (and the password when
// with_pass is false). Decoding needs a non-empty name; missing fields are empty.
size_t pwd_rec_encode(const pwd_rec_t *rec, bool with_pass, uint8_t *out, size_t cap);
bool pwd_rec_decode(const uint8_t *in, size_t len, pwd_rec_t *rec);
// Overwrites only the fields present in the TLV list; an empty value clears a field.
bool pwd_rec_merge(pwd_rec_t *rec, const uint8_t *in, size_t len);

// Password generator on the hardware RNG. Every selected set occurs at least once.
#define PWD_GEN_LOWER   0x01
#define PWD_GEN_UPPER   0x02
#define PWD_GEN_DIGITS  0x04
#define PWD_GEN_SYMBOLS 0x08
#define PWD_GEN_MIN     4
// out gets len characters (no terminator). False on a bad length or empty set mask.
bool pwd_generate(size_t len, uint8_t sets, char *out);

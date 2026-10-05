#pragma once
// One user PIN for all applications (FIDO PIN, OpenPGP PW1, PIV PIN, password
// manager) and one admin PIN for recovery (OpenPGP PW3, PIV PUK). Both wrap
// the device vault key: a verified PIN gives the key that opens secrets
// sealed to devpin_vpub(). PINs are handled as LEFT(SHA-256(PIN), 16), the
// form in which FIDO clients send them.
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define DEVPIN_USER         0
#define DEVPIN_ADMIN        1
#define DEVPIN_USER_MIN     6
#define DEVPIN_ADMIN_MIN    8
#define DEVPIN_MAX          8       // PIV limits PIN and PUK to 8 bytes
#define DEVPIN_USER_TRIES   8
#define DEVPIN_ADMIN_TRIES  3
#define DEVPIN_HASH_LEN     16

typedef enum { DEVPIN_OK, DEVPIN_WRONG, DEVPIN_BLOCKED, DEVPIN_ERROR } devpin_res_t;

// Loads the PIN state, creating the vault and default PINs (123456 /
// 12345678) if there is none. False if they can't be stored (e.g. no "pins"
// partition): the key must not run with PINs that reset on every start.
bool devpin_init(void);
const uint8_t *devpin_vpub(void);
uint8_t devpin_tries(int who);
// Changes with every successful PIN change (in RAM): lets FIDO drop a
// pinUvAuthToken issued for the old PIN, whichever application changed it.
uint32_t devpin_generation(void);
// Changes when a PIN change replaces the vault key (only while a factory PIN
// is set): applications drop a vault key or data key they hold.
uint32_t devpin_vault_generation(void);
// True while the PIN is the factory default (PIV metadata reports it).
bool devpin_is_default(int who);
// True while either PIN is the factory default. Then anyone can open the
// vault, so the applications refuse to store keys and passwords.
bool devpin_any_default(void);
// Length of the current PIN (OpenPGP needs it to split old and new PIN).
size_t devpin_len(int who);
bool devpin_len_ok(int who, size_t len);
devpin_res_t devpin_verify(int who, const uint8_t *pin, size_t len, uint8_t vpriv[32]);
devpin_res_t devpin_verify_hash(int who, const uint8_t hash[DEVPIN_HASH_LEN], uint8_t vpriv[32]);
// Sets a new PIN and restores its tries; vpriv comes from a successful verify.
// The factory value of that PIN is refused.
bool devpin_set(int who, const uint8_t vpriv[32], const uint8_t *pin, size_t len);

#pragma once
// One record (devpin's PIN records) in the "pins" partition rather than in
// NVS. NVS only marks a replaced value erased and leaves it in flash until it
// reuses the page; here a write goes to the other of two sectors and the old
// sector is erased whole, so after a PIN change no wrap under the old PIN is
// left. A power cut at any step leaves either the old or the new record.
#include <stddef.h>
#include <stdbool.h>

#define PINSTORE_MAX    2000

// Reads exactly len bytes: 1 read, 0 no record (blank or broken flash),
// -1 the partition is missing, can't be read or holds a record of another
// size — the caller must not take that for "no PINs yet". Also erases a
// leftover older or broken copy.
int pinstore_read(void *buf, size_t len);
bool pinstore_write(const void *buf, size_t len);
// Erases both sectors (factory reset).
bool pinstore_erase(void);

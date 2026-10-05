#pragma once
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

// Persistent key/value storage on the dedicated "store" NVS partition.
// Each application uses its own namespace so it can be reset independently.
#define NS_SYS   "sys"
#define NS_FIDO  "fido"
#define NS_OATH  "oath"
#define NS_PGP   "pgp"
#define NS_PIV   "piv"
#define NS_PWD   "pwd"
#define NS_PIN   "pin"

// ESP_ERR_NVS_NO_FREE_PAGES / ESP_ERR_NVS_NEW_VERSION_FOUND: the partition
// can't be used as it is; the data stays until store_format().
esp_err_t store_init(void);
// Erases every application's data and the device PIN.
esp_err_t store_format(void);
// On entry *len is the buffer size, on success it is the stored size. With
// buf NULL only the size is returned (an existence check without a read).
esp_err_t store_get(const char *ns, const char *key, void *buf, size_t *len);
esp_err_t store_set(const char *ns, const char *key, const void *buf, size_t len);
esp_err_t store_del(const char *ns, const char *key);
esp_err_t store_erase_ns(const char *ns);
// Reads exactly len bytes, false if missing or of a different size.
bool store_read(const char *ns, const char *key, void *buf, size_t len);

// Host stand-in for core/store.c: key/value pairs in RAM.
#include "core/store.h"
#include <stdint.h>
#include <string.h>

#define MAX_ITEMS 32
#define MAX_VALUE 1024

static struct {
    char ns[16], key[16];
    size_t len;
    uint8_t val[MAX_VALUE];
    bool used;
} s_items[MAX_ITEMS];

bool g_store_fail;      // tests: every write fails, as on a full flash

static int find(const char *ns, const char *key)
{
    for (int i = 0; i < MAX_ITEMS; i++) {
        if (s_items[i].used && !strcmp(s_items[i].ns, ns) && !strcmp(s_items[i].key, key)) return i;
    }
    return -1;
}

esp_err_t store_init(void)
{
    memset(s_items, 0, sizeof(s_items));
    return ESP_OK;
}

esp_err_t store_get(const char *ns, const char *key, void *buf, size_t *len)
{
    int i = find(ns, key);
    if (i < 0) return ESP_ERR_NOT_FOUND;
    if (buf && s_items[i].len > *len) return ESP_ERR_INVALID_SIZE;
    if (buf) memcpy(buf, s_items[i].val, s_items[i].len);
    *len = s_items[i].len;
    return ESP_OK;
}

bool store_read(const char *ns, const char *key, void *buf, size_t len)
{
    size_t n = len;
    return store_get(ns, key, buf, &n) == ESP_OK && n == len;
}

esp_err_t store_set(const char *ns, const char *key, const void *buf, size_t len)
{
    if (g_store_fail) return ESP_FAIL;
    int i = find(ns, key);
    for (int j = 0; i < 0 && j < MAX_ITEMS; j++) if (!s_items[j].used) i = j;
    if (i < 0 || len > MAX_VALUE) return ESP_FAIL;
    strcpy(s_items[i].ns, ns);
    strcpy(s_items[i].key, key);
    memcpy(s_items[i].val, buf, len);
    s_items[i].len = len;
    s_items[i].used = true;
    return ESP_OK;
}

esp_err_t store_del(const char *ns, const char *key)
{
    int i = find(ns, key);
    if (i >= 0) s_items[i].used = false;
    return ESP_OK;
}

esp_err_t store_erase_ns(const char *ns)
{
    for (int i = 0; i < MAX_ITEMS; i++) if (s_items[i].used && !strcmp(s_items[i].ns, ns)) s_items[i].used = false;
    return ESP_OK;
}

#include "store.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_flash_encrypt.h"
#include "esp_log.h"
#include "esp_partition.h"

#define STORE_PART "store"

static const char *TAG = "store";

// With flash encryption on (the secure build), the store is an encrypted
// NVS: flash encryption alone leaves NVS partitions in plain text. Its keys
// live in the nvs_keys partition, which flash encryption does protect; they
// are generated on the first start. A development key without flash
// encryption keeps a plain NVS: keys in a readable partition would protect
// nothing.
static nvs_sec_cfg_t s_cfg;
static bool s_secure;

static esp_err_t open_store(void)
{
    return s_secure ? nvs_flash_secure_init_partition(STORE_PART, &s_cfg) : nvs_flash_init_partition(STORE_PART);
}

esp_err_t store_init(void)
{
    if (esp_flash_encryption_enabled()) {
        const esp_partition_t *keys = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                                               ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS, NULL);
        if (keys == NULL) {
            ESP_LOGE(TAG, "nvs_keys partition not found");
            return ESP_ERR_NOT_FOUND;
        }
        esp_err_t err = nvs_flash_read_security_cfg(keys, &s_cfg);
        if (err == ESP_ERR_NVS_KEYS_NOT_INITIALIZED) {
            ESP_LOGW(TAG, "generating the store encryption keys (first start)");
            err = nvs_flash_generate_keys(keys, &s_cfg);
        }
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "store encryption keys: %s", esp_err_to_name(err));
            return err;
        }
        s_secure = true;
    }
    return open_store();
}

esp_err_t store_format(void)
{
    ESP_LOGW(TAG, "store partition erased");
    esp_err_t err = nvs_flash_erase_partition(STORE_PART);
    return err == ESP_OK ? open_store() : err;
}

esp_err_t store_get(const char *ns, const char *key, void *buf, size_t *len)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open_from_partition(STORE_PART, ns, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    err = nvs_get_blob(h, key, buf, len);
    nvs_close(h);
    return err;
}

bool store_read(const char *ns, const char *key, void *buf, size_t len)
{
    size_t n = len;
    return store_get(ns, key, buf, &n) == ESP_OK && n == len;
}

esp_err_t store_set(const char *ns, const char *key, const void *buf, size_t len)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open_from_partition(STORE_PART, ns, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, key, buf, len);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t store_del(const char *ns, const char *key)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open_from_partition(STORE_PART, ns, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_erase_key(h, key);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err == ESP_ERR_NVS_NOT_FOUND ? ESP_OK : err;
}

esp_err_t store_erase_ns(const char *ns)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open_from_partition(STORE_PART, ns, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_erase_all(h);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

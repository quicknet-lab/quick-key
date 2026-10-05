#include "chipkey.h"
#include "crypto.h"
#include <string.h>
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_flash_encrypt.h"
#include "esp_hmac.h"
#include "esp_log.h"
#include "esp_timer.h"

#define TARGET_US       250000
#define CAL_ROUNDS      256
#define MIN_ROUNDS      1000
#define MAX_ROUNDS      (1u << 20)

static const char *TAG = "chipkey";
static bool s_hw;
static hmac_key_id_t s_key;
static uint32_t s_rounds;

bool chipkey_init(void)
{
    if (!esp_flash_encryption_enabled()) return true;
    esp_efuse_block_t blk;
    if (!esp_efuse_find_purpose(ESP_EFUSE_KEY_PURPOSE_HMAC_UP, &blk)) {
        // First start. The key must be read-protected in the same burn.
        if (esp_efuse_read_field_bit(ESP_EFUSE_WR_DIS_RD_DIS)) {
            ESP_LOGE(TAG, "eFuse read protection is locked: no PIN key can be added");
            return false;
        }
        blk = esp_efuse_find_unused_key_block();
        if (blk == EFUSE_BLK_KEY_MAX) {
            ESP_LOGE(TAG, "no free eFuse key block");
            return false;
        }
        uint8_t key[32];
        crypto_random(key, sizeof(key));
        esp_err_t err = esp_efuse_write_key(blk, ESP_EFUSE_KEY_PURPOSE_HMAC_UP, key, sizeof(key));
        memset(key, 0, sizeof(key));
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "burning the PIN key: %s", esp_err_to_name(err));
            return false;
        }
        ESP_LOGW(TAG, "PIN key burned into eFuse BLOCK_KEY%d", blk - EFUSE_BLK_KEY0);
    }
    if (!esp_efuse_get_key_dis_read(blk)) {
        ESP_LOGE(TAG, "the PIN key is readable");
        return false;
    }
    // Done after the key (also after a power cut right after it), so that
    // nobody can read-protect anything else, e.g. the Secure Boot digest.
    if (!esp_efuse_read_field_bit(ESP_EFUSE_WR_DIS_RD_DIS) &&
        esp_efuse_write_field_bit(ESP_EFUSE_WR_DIS_RD_DIS) != ESP_OK) {
        ESP_LOGE(TAG, "locking eFuse read protection failed");
        return false;
    }
    s_key = (hmac_key_id_t)(blk - EFUSE_BLK_KEY0);
    s_hw = true;
    return true;
}

static bool step(const uint8_t *in, size_t len, uint8_t out[32])
{
    static const char soft_key[] = "quick-key development";
    if (s_hw) return esp_hmac_calculate(s_key, in, len, out) == ESP_OK;
    hmac_sha256((const uint8_t *)soft_key, sizeof(soft_key) - 1, in, len, out);
    return true;
}

bool chipkey_stretch(const uint8_t *in, size_t len, uint32_t rounds, uint8_t out[32])
{
    uint8_t x[32];
    bool ok = step(in, len, x);
    for (uint32_t i = 1; ok && i < rounds; i++) ok = step(x, sizeof(x), x);
    memcpy(out, x, sizeof(x));
    memset(x, 0, sizeof(x));
    return ok;
}

uint32_t chipkey_rounds(void)
{
    if (!s_rounds) {
        uint8_t x[32] = {0};
        int64_t t = esp_timer_get_time();
        chipkey_stretch(x, sizeof(x), CAL_ROUNDS, x);
        int64_t dt = esp_timer_get_time() - t;
        uint64_t r = (uint64_t)CAL_ROUNDS * TARGET_US / (dt > 0 ? dt : 1);
        s_rounds = r < MIN_ROUNDS ? MIN_ROUNDS : r > MAX_ROUNDS ? MAX_ROUNDS : (uint32_t)r;
        ESP_LOGI(TAG, "%u HMAC rounds per PIN check", (unsigned)s_rounds);
    }
    return s_rounds;
}

// Device management: version, UUID, reboot, RNG, factory reset.
// Reachable as CTAPHID vendor commands and as an APDU application.
#include "admin.h"
#include "apps.h"
#include "core/crypto.h"
#include "core/pinstore.h"
#include "core/store.h"
#include "core/up.h"
#include "fido/fido.h"
#include <string.h>
#include "esp_app_desc.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "soc/rtc_cntl_reg.h"
#include "esp_rom_sys.h"
#include "tinyusb.h"

static const uint8_t s_aid[] = {0xF0, 0x51, 0x4B, 0x41, 0x44, 0x4D};   // proprietary "QKADM"

static void reboot_cb(void *arg)
{
    esp_restart();
}

// Hand the USB PHY back to USB-Serial-JTAG and restart into the ROM download mode.
static void bootloader_cb(void *arg)
{
    // Detach first so the host notices the device change and re-enumerates.
    tud_disconnect();
    esp_rom_delay_us(300 * 1000);
    CLEAR_PERI_REG_MASK(RTC_CNTL_USB_CONF_REG,
                        RTC_CNTL_SW_HW_USB_PHY_SEL | RTC_CNTL_SW_USB_PHY_SEL | RTC_CNTL_USB_PAD_ENABLE);
    REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
    esp_restart();
}

static void reboot_later_cb(esp_timer_cb_t cb)
{
    static esp_timer_handle_t t;
    const esp_timer_create_args_t args = {.callback = cb, .name = "reboot"};
    if (t) esp_timer_delete(t);
    esp_timer_create(&args, &t);
    esp_timer_start_once(t, 200 * 1000);
}

static void reboot_later(void)
{
    reboot_later_cb(reboot_cb);
}

void factory_reset(void)
{
    store_erase_ns(NS_FIDO);
    store_erase_ns(NS_OATH);
    store_erase_ns(NS_PGP);
    store_erase_ns(NS_PIV);
    store_erase_ns(NS_PWD);
    store_erase_ns(NS_PIN);
    pinstore_erase();
    reboot_later();
}

// PROJECT_VER "major.minor.patch"
static void parse_version(const char *v, uint8_t out[3])
{
    int maj = 0, min = 0, pat = 0, i = 0;
    int *f[3] = {&maj, &min, &pat};
    for (const char *p = v; *p && i < 3; p++) {
        if (*p == '.') i++;
        else if (*p >= '0' && *p <= '9') *f[i] = *f[i] * 10 + (*p - '0');
        else break;
    }
    out[0] = maj;
    out[1] = min;
    out[2] = pat;
}

int fw_version(uint8_t out[3])
{
    parse_version(esp_app_get_description()->version, out);
    return 3;
}

static const char *TAG = "admin";

static esp_ota_handle_t s_ota;
static const esp_partition_t *s_ota_part;
static uint32_t s_ota_size, s_ota_written;

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void ota_abort(void)
{
    if (s_ota_part) esp_ota_abort(s_ota);
    s_ota_part = NULL;
}

static uint8_t ota_begin(const uint8_t *req, size_t len)
{
    if (len != 4) return OTA_BAD_STATE;
    ota_abort();
    uint32_t size = rd32(req);
    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (!part || size == 0 || size > part->size) return OTA_BAD_STATE;
    if (up_wait("Update?", "Install new firmware", 30000) != UP_OK) return OTA_NOT_CONFIRMED;
    if (esp_ota_begin(part, size, &s_ota) != ESP_OK) return OTA_FLASH_ERROR;
    s_ota_part = part;
    s_ota_size = size;
    s_ota_written = 0;
    ESP_LOGI(TAG, "OTA to %s, %u bytes", part->label, (unsigned)size);
    return OTA_OK;
}

static uint8_t ota_write(const uint8_t *req, size_t len)
{
    if (!s_ota_part || len < 4 || rd32(req) != s_ota_written || s_ota_written + len - 4 > s_ota_size) {
        return OTA_BAD_STATE;
    }
    if (esp_ota_write(s_ota, req + 4, len - 4) != ESP_OK) {
        ota_abort();
        return OTA_FLASH_ERROR;
    }
    s_ota_written += len - 4;
    return OTA_OK;
}

static uint8_t ota_end(void)
{
    if (!s_ota_part || s_ota_written != s_ota_size) return OTA_BAD_STATE;
    const esp_partition_t *part = s_ota_part;
    s_ota_part = NULL;
    // esp_ota_end validates the image, including its signature.
    esp_err_t err = esp_ota_end(s_ota);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "OTA image rejected: %s", esp_err_to_name(err));
        return err == ESP_ERR_OTA_VALIDATE_FAILED ? OTA_VERIFY_FAILED : OTA_FLASH_ERROR;
    }
    // No downgrades: an older signed image could bring back fixed bugs. The
    // same version may be installed again (development builds); going back
    // is possible only through the ROM bootloader.
    esp_app_desc_t desc;
    uint8_t cur[3], img[3];
    if (esp_ota_get_partition_description(part, &desc) != ESP_OK) return OTA_VERIFY_FAILED;
    parse_version(desc.version, img);
    fw_version(cur);
    if (memcmp(img, cur, sizeof(cur)) < 0) {
        ESP_LOGE(TAG, "OTA image %s is older than the running firmware", desc.version);
        return OTA_DOWNGRADE;
    }
    if (esp_ota_set_boot_partition(part) != ESP_OK) return OTA_FLASH_ERROR;
    reboot_later();
    return OTA_OK;
}

static int run(uint8_t cmd, uint8_t *out, size_t cap)
{
    switch (cmd) {
    case ADMIN_VERSION:
        return fw_version(out);
    case ADMIN_UUID:
        if (cap < 16) return -1;
        esp_efuse_read_field_blob(ESP_EFUSE_OPTIONAL_UNIQUE_ID, out, 128);
        return 16;
    case ADMIN_REBOOT:
        reboot_later();
        return 0;
    case ADMIN_RNG: {
        size_t n = cap < 57 ? cap : 57;
        crypto_random(out, n);
        return n;
    }
    case ADMIN_FACTORY_RESET:
        if (up_wait("FACTORY RESET", "Erase ALL keys and data", 30000) != UP_OK) {
            out[0] = 0x01;
            return 1;
        }
        factory_reset();
        out[0] = 0x00;
        return 1;
    case ADMIN_BOOTLOADER:
        // Download mode can read the flash, so require a physical confirmation.
        if (up_wait("Bootloader?", "Reboot to firmware update mode", 30000) != UP_OK) {
            out[0] = 0x01;
            return 1;
        }
        reboot_later_cb(bootloader_cb);
        out[0] = 0x00;
        return 1;
    default:
        return -1;
    }
}

int admin_hid(uint8_t cmd, const uint8_t *req, size_t len, uint8_t *resp, size_t cap)
{
    switch (cmd) {
    case ADMIN_OTA_BEGIN: resp[0] = ota_begin(req, len); return 1;
    case ADMIN_OTA_WRITE: resp[0] = ota_write(req, len); return 1;
    case ADMIN_OTA_END:   resp[0] = ota_end(); return 1;
    default:              return run(cmd, resp, cap);
    }
}

static uint16_t admin_select(const apdu_t *a, rbuf_t *r)
{
    uint8_t v[3];
    fw_version(v);
    rb_put(r, v, 3);
    return SW_OK;
}

static uint16_t admin_process(const apdu_t *a, rbuf_t *r)
{
    uint8_t buf[64];
    int n = run(a->ins, buf, sizeof(buf));
    if (n < 0) return SW_INS_NOT_SUPPORTED;
    rb_put(r, buf, n);
    return SW_OK;
}

const app_t app_admin = {
    .name = "admin",
    .aid = s_aid,
    .aid_len = sizeof(s_aid),
    .select = admin_select,
    .process = admin_process,
};

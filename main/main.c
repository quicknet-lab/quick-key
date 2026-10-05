#include "board.h"
#include "core/chipkey.h"
#include "core/crypto.h"
#include "core/devpin.h"
#include "core/store.h"
#include "core/up.h"
#include "core/worker.h"
#include "fido/fido.h"
#include "ui/lcd.h"
#include "ui/led.h"
#include "usb/usb.h"
#include "esp_app_desc.h"
#include "esp_flash_encrypt.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_secure_boot.h"
#include "nvs.h"
#include "tinyusb.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "main";

// The secure build's bootloader leaves flash encryption in Development mode,
// with the ROM download path still able to write and read the flash. Close it
// for good once this image has proved it works: the store opened (with its
// encryption) and a host enumerated the USB device, so signed OTA can reach
// the key. On a factory-fresh key that is the first start, right after the
// bootloader burned Secure Boot and flash encryption. Release mode also
// switches the ROM to Secure Download mode. A no-op once done; without a
// host it is retried on the next start.
static void lock_down(void)
{
#if CONFIG_SECURE_FLASH_ENC_ENABLED
    if (!esp_secure_boot_enabled() || esp_get_flash_encryption_mode() != ESP_FLASH_ENC_MODE_DEVELOPMENT) {
        return;
    }
    for (int i = 0; i < 300 && !tud_mounted(); i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (!tud_mounted()) {
        ESP_LOGW(TAG, "no USB host: flash encryption stays in Development mode until the next start");
        return;
    }
    ESP_LOGW(TAG, "switching flash encryption to Release mode: USB flashing closes for good");
    esp_flash_encryption_set_release_mode();
    ESP_LOGW(TAG, "flash encryption is in Release mode; eFuse checklist %s",
             esp_flash_encryption_cfg_verify_release_mode() ? "complete" : "has warnings (see above)");
#endif
}

void app_main(void)
{
    ESP_LOGI(TAG, "Quick-Key %s", esp_app_get_description()->version);

    led_init();
    lcd_init();
    up_init();
    ui_show("Quick-Key", "Starting...", COLOR_GRAY);

    crypto_init();
    esp_err_t err = store_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // The storage can't be read as it is (e.g. a firmware with another
        // NVS format). Never erase it silently: the previous firmware may
        // still read it. Only a press on the device erases it.
        ESP_LOGE(TAG, "store unreadable: %s", esp_err_to_name(err));
        while (up_wait("Storage error", "Press: ERASE all keys", 60000) != UP_OK) {}
        err = store_format();
    }
    ESP_ERROR_CHECK(err);
    // Without the chip-bound PIN key the key does not start: no USB, so
    // lock_down() never runs and the ROM bootloader can still recover it.
    if (!chipkey_init()) {
        ui_show("Security error", "PIN key in eFuse", COLOR_RED);
        for (;;) vTaskDelay(portMAX_DELAY);
    }
    // PIN records that can't be read or stored (e.g. no "pins" partition)
    // stop the key: starting over with factory PINs would lose the vault.
    if (!devpin_init()) {
        ui_show("Storage error", "PIN partition", COLOR_RED);
        for (;;) vTaskDelay(portMAX_DELAY);
    }
    fido_init();

    worker_start();
    usb_init();
    // Reaching this point means the image works: cancel a pending rollback.
    esp_ota_mark_app_valid_cancel_rollback();
    ui_idle();
    lock_down();
}

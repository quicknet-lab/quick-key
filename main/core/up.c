#include "up.h"
#include <string.h>
#include "board.h"
#include "worker.h"
#include "ui/lcd.h"
#include "ui/led.h"
#include "driver/gpio.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define KEEPALIVE_MS     100
#define U2F_PROMPT_MS    10000

static int64_t s_u2f_prompt_until;
static uint8_t s_u2f_for[33];       // request the prompt belongs to
static bool s_u2f_armed;            // button seen released during the prompt

void up_init(void)
{
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << PIN_BUTTON,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
    };
    gpio_config(&io);
}

bool up_button_pressed(void)
{
    return gpio_get_level(PIN_BUTTON) == 0;
}

void ui_idle(void)
{
    led_set(0, 0, 0);
    ui_show("Quick-Key", "Ready", COLOR_GREEN);
}

up_result_t up_wait(const char *title, const char *detail, uint32_t timeout_ms)
{
    ui_show(title, detail, COLOR_YELLOW);
    up_result_t res = UP_TIMEOUT;
    // Require a fresh press: a held button must be released first. The
    // timeout and keepalives apply while waiting for that too.
    bool armed = false;
    int64_t start = esp_timer_get_time();
    int64_t last_ka = 0;
    for (;;) {
        int64_t now = esp_timer_get_time();
        if ((now - start) / 1000 >= timeout_ms) break;
        led_set(((now / 250000) & 1) ? 60 : 0, ((now / 250000) & 1) ? 40 : 0, 0);
        if (!up_button_pressed()) {
            armed = true;
        } else if (armed) {
            res = UP_OK;
            break;
        }
        if ((now - last_ka) / 1000 >= KEEPALIVE_MS) {
            last_ka = now;
            if (!worker_keepalive(KEEPALIVE_UPNEEDED)) {
                res = UP_CANCEL;
                break;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    ui_idle();
    return res;
}

bool up_poll_u2f(const char *detail, const uint8_t id[33])
{
    int64_t now = esp_timer_get_time();
    if (now < s_u2f_prompt_until && memcmp(id, s_u2f_for, sizeof(s_u2f_for)) == 0) {
        if (!up_button_pressed()) {
            s_u2f_armed = true;
        } else if (s_u2f_armed) {
            s_u2f_prompt_until = 0;
            ui_idle();
            return true;
        }
        return false;
    }
    // Start a new prompt; the host retries until the user presses the button.
    s_u2f_prompt_until = now + U2F_PROMPT_MS * 1000LL;
    memcpy(s_u2f_for, id, sizeof(s_u2f_for));
    s_u2f_armed = !up_button_pressed();
    ui_show("Touch", detail, COLOR_YELLOW);
    led_set(60, 40, 0);
    return false;
}

void up_wink(void)
{
    for (int i = 0; i < 3; i++) {
        led_set(0, 0, 80);
        vTaskDelay(pdMS_TO_TICKS(150));
        led_set(0, 0, 0);
        vTaskDelay(pdMS_TO_TICKS(150));
    }
}

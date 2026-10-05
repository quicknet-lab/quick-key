// APA102 RGB LED driven by bit-banging (one LED, rarely updated).
#include "led.h"
#include "board.h"
#include "driver/gpio.h"

static void led_byte(uint8_t v)
{
    for (int i = 7; i >= 0; i--) {
        gpio_set_level(PIN_LED_DI, (v >> i) & 1);
        gpio_set_level(PIN_LED_CI, 1);
        gpio_set_level(PIN_LED_CI, 0);
    }
}

void led_set(uint8_t r, uint8_t g, uint8_t b)
{
    for (int i = 0; i < 4; i++) led_byte(0x00);   // start frame
    led_byte(0xE0 | 4);                           // low global brightness
    led_byte(b);
    led_byte(g);
    led_byte(r);
    for (int i = 0; i < 4; i++) led_byte(0xFF);   // end frame
}

void led_init(void)
{
    gpio_config_t io = {
        .pin_bit_mask = (1ULL << PIN_LED_DI) | (1ULL << PIN_LED_CI),
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&io);
    gpio_set_level(PIN_LED_CI, 0);
    led_set(0, 0, 0);
}

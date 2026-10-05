// ST7735S 160x80 (0.96") over SPI with a full RAM framebuffer.
#include "lcd.h"
#include "board.h"
#include "font9x15.h"
#include <string.h>
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_lcd_panel_io.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

// Landscape: MV|MX, BGR. Panel RAM is 132x162, visible window is offset.
#define MADCTL_VAL  0x68
#define X_OFFSET    1
#define Y_OFFSET    26

static esp_lcd_panel_io_handle_t s_io;
static uint16_t s_fb[LCD_WIDTH * LCD_HEIGHT];
static SemaphoreHandle_t s_lock;

static void cmd(uint8_t c, const void *data, size_t len)
{
    esp_lcd_panel_io_tx_param(s_io, c, data, len);
}

void lcd_init(void)
{
    s_lock = xSemaphoreCreateMutex();

    gpio_config_t io = {
        .pin_bit_mask = (1ULL << PIN_LCD_BL) | (1ULL << PIN_LCD_RST),
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&io);
    gpio_set_level(PIN_LCD_BL, 1);

    spi_bus_config_t bus = {
        .mosi_io_num = PIN_LCD_MOSI,
        .miso_io_num = -1,
        .sclk_io_num = PIN_LCD_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = sizeof(s_fb),
    };
    ESP_ERROR_CHECK(spi_bus_initialize(SPI2_HOST, &bus, SPI_DMA_CH_AUTO));

    esp_lcd_panel_io_spi_config_t cfg = {
        .cs_gpio_num = PIN_LCD_CS,
        .dc_gpio_num = PIN_LCD_DC,
        .spi_mode = 0,
        .pclk_hz = 26 * 1000 * 1000,
        .trans_queue_depth = 4,
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)SPI2_HOST, &cfg, &s_io));

    gpio_set_level(PIN_LCD_RST, 0);
    vTaskDelay(pdMS_TO_TICKS(20));
    gpio_set_level(PIN_LCD_RST, 1);
    vTaskDelay(pdMS_TO_TICKS(120));

    cmd(0x11, NULL, 0);                         // SLPOUT
    vTaskDelay(pdMS_TO_TICKS(120));
    cmd(0x3A, (uint8_t[]){0x05}, 1);            // COLMOD 16 bit
    cmd(0x36, (uint8_t[]){MADCTL_VAL}, 1);      // MADCTL
    cmd(0x21, NULL, 0);                         // INVON
    cmd(0x13, NULL, 0);                         // NORON
    cmd(0x29, NULL, 0);                         // DISPON

    lcd_clear(COLOR_BLACK);
    lcd_flush();
    gpio_set_level(PIN_LCD_BL, 0);
}

void lcd_clear(uint16_t color)
{
    uint16_t c = (uint16_t)((color >> 8) | (color << 8));
    for (int i = 0; i < LCD_WIDTH * LCD_HEIGHT; i++) s_fb[i] = c;
}

static void put_char(int x, int y, bool bold, uint16_t c, char ch)
{
    if (ch < 0x20 || ch > 0x7E) ch = '?';
    const uint16_t *g = (bold ? font9x15b : font9x15)[ch - 0x20];
    for (int row = 0; row < FONT_H; row++) {
        for (int col = 0; col < FONT_W; col++) {
            if (!(g[row] & (0x100 >> col))) continue;
            int px = x + col, py = y + row;
            if (px >= 0 && px < LCD_WIDTH && py >= 0 && py < LCD_HEIGHT) {
                // Rotated 180 degrees to match how the dongle is held.
                s_fb[(LCD_HEIGHT - 1 - py) * LCD_WIDTH + (LCD_WIDTH - 1 - px)] = c;
            }
        }
    }
}

void lcd_text(int x, int y, bool bold, uint16_t color, const char *s)
{
    uint16_t c = (uint16_t)((color >> 8) | (color << 8));
    for (; *s; s++) {
        if ((*s & 0xC0) == 0x80) continue;      // UTF-8 continuation: one '?' per character
        put_char(x, y, bold, c, *s);
        x += FONT_W;
    }
}

void lcd_flush(void)
{
    uint8_t ca[4] = {0, X_OFFSET, 0, X_OFFSET + LCD_WIDTH - 1};
    uint8_t ra[4] = {0, Y_OFFSET, 0, Y_OFFSET + LCD_HEIGHT - 1};
    cmd(0x2A, ca, 4);
    cmd(0x2B, ra, 4);
    esp_lcd_panel_io_tx_color(s_io, 0x2C, s_fb, sizeof(s_fb));
    // tx_param drains queued color transfers, so s_fb is free again after it.
    cmd(0x00, NULL, 0);
}

void ui_show(const char *title, const char *detail, uint16_t color)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    lcd_clear(COLOR_BLACK);
    lcd_text(2, 0, true, color, title);
    if (detail) {
        // Wrap detail text over up to 4 lines of 17 chars.
        char line[18];
        size_t n = strlen(detail);
        for (int l = 0; l < 4 && n; l++) {
            size_t k = n > 17 ? 17 : n;
            memcpy(line, detail, k);
            line[k] = 0;
            lcd_text(2, 16 + l * FONT_H, false, COLOR_WHITE, line);
            detail += k;
            n -= k;
        }
    }
    lcd_flush();
    xSemaphoreGive(s_lock);
}

// ST7735S 160x80 (0.96") over SPI. What is drawn comes from ui_draw.c; this
// file brings the panel up and sends the frame.
#include "lcd.h"
#include "board.h"
#include "ui_draw.h"
#include <string.h>
#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_lcd_panel_io.h"
#include "esp_app_desc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

// Landscape: MV|MX, BGR. Panel RAM is 132x162, visible window is offset.
#define MADCTL_VAL  0x68
#define X_OFFSET    1
#define Y_OFFSET    26

static esp_lcd_panel_io_handle_t s_io;
// The frame as the panel takes it: rotated, bytes swapped.
static uint16_t s_tx[LCD_WIDTH * LCD_HEIGHT];
static SemaphoreHandle_t s_lock;

static void cmd(uint8_t c, const void *data, size_t len)
{
    esp_lcd_panel_io_tx_param(s_io, c, data, len);
}

static void send_frame(void)
{
    uint8_t ca[4] = {0, X_OFFSET, 0, X_OFFSET + LCD_WIDTH - 1};
    uint8_t ra[4] = {0, Y_OFFSET, 0, Y_OFFSET + LCD_HEIGHT - 1};
    cmd(0x2A, ca, 4);
    cmd(0x2B, ra, 4);
    esp_lcd_panel_io_tx_color(s_io, 0x2C, s_tx, sizeof(s_tx));
    // tx_param drains queued color transfers, so s_tx is free again after it.
    cmd(0x00, NULL, 0);
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
        .max_transfer_sz = sizeof(s_tx),
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

    memset(s_tx, 0, sizeof(s_tx));
    send_frame();
    gpio_set_level(PIN_LCD_BL, 0);
}

// Rotated 180 degrees to match how the dongle is held, bytes swapped for the
// panel. Call with s_lock held.
static void flush(void)
{
    const uint16_t *fb = ui_draw_frame();
    for (int i = 0; i < LCD_WIDTH * LCD_HEIGHT; i++) {
        uint16_t c = fb[LCD_WIDTH * LCD_HEIGHT - 1 - i];
        s_tx[i] = (uint16_t)((c >> 8) | (c << 8));
    }
    send_frame();
}

void ui_show(const char *title, const char *detail, uint16_t color)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    ui_draw_status(title, detail, color, esp_app_get_description()->version);
    flush();
    xSemaphoreGive(s_lock);
}

void ui_splash(void)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    ui_draw_splash(esp_app_get_description()->version);
    flush();
    xSemaphoreGive(s_lock);
}

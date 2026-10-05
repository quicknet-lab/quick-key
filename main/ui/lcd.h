#pragma once
#include <stdint.h>
#include <stdbool.h>

#define RGB565(r, g, b) ((uint16_t)((((r) & 0xF8) << 8) | (((g) & 0xFC) << 3) | ((b) >> 3)))
#define COLOR_BLACK  RGB565(0, 0, 0)
#define COLOR_WHITE  RGB565(255, 255, 255)
#define COLOR_RED    RGB565(255, 40, 40)
#define COLOR_GREEN  RGB565(40, 220, 80)
#define COLOR_YELLOW RGB565(255, 200, 0)
#define COLOR_GRAY   RGB565(120, 120, 120)

void lcd_init(void);
void lcd_clear(uint16_t color);
// 9x15 font; y is the top of the character cell.
void lcd_text(int x, int y, bool bold, uint16_t color, const char *s);
void lcd_flush(void);

// Two-line screen: title (large) and detail (small).
void ui_show(const char *title, const char *detail, uint16_t color);

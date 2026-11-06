#pragma once
#include <stdint.h>
#include "ui_draw.h"

void lcd_init(void);

// A status screen: title in a colored plate, detail under it. Colors are the
// COLOR_* of ui_draw.h.
void ui_show(const char *title, const char *detail, uint16_t color);
// The boot screen.
void ui_splash(void);

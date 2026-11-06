#pragma once
#include <stdint.h>

// What the 160x80 screen shows, drawn into a RAM frame. No hardware in here,
// so the same code builds on the host (test/host/ui_preview.c). The layout: a
// colored title plate across the top, the message centered under it, the
// version in the bottom-left corner.

#define UI_W 160
#define UI_H 80

#define RGB565(r, g, b) ((uint16_t)((((r) >> 3) << 11) | (((g) >> 2) << 5) | ((b) >> 3)))
#define COLOR_BLACK  RGB565(0x00, 0x00, 0x00)
#define COLOR_WHITE  RGB565(0xFF, 0xFF, 0xFF)
// Secondary text: the version.
#define COLOR_GRAY   RGB565(0x9A, 0x9A, 0x9A)
// Cyan: ordinary screens.
#define COLOR_ACCENT RGB565(0x6B, 0xD6, 0xC9)
// Worth a second look: the key asks for a button press.
#define COLOR_ORANGE RGB565(0xFF, 0xA0, 0x00)
// Critical: errors.
#define COLOR_RED    RGB565(0xFF, 0x40, 0x40)

// A status screen: title in a plate of `color`, detail under it (one short
// line large, longer text wrapped over up to three lines). With COLOR_ACCENT
// the detail is white, with any other color it takes that color. `version`
// (may be NULL) goes in the bottom-left corner when the detail is one short
// line.
void ui_draw_status(const char *title, const char *detail, uint16_t color, const char *version);

// The boot screen: QUICK-KEY and the version.
void ui_draw_splash(const char *version);

// The frame, UI_W x UI_H RGB565 values in native byte order, row-major,
// top-left first, as the screen is read.
const uint16_t *ui_draw_frame(void);

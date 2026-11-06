#include "ui_draw.h"
#include <stdbool.h>
#include <string.h>
#include "font_terminus.h"

// Terminus, printable ASCII: S 8x16 (20 columns here), S_BOLD for the title
// plate, M 12x24 bold (13 columns), L 16x32 bold (10 columns) for a single
// short word.
typedef struct {
    uint8_t w, h;
    const uint8_t *bits;
} font_t;

static const font_t FONT_S = {8, 16, display_font_s_bits};
static const font_t FONT_S_BOLD = {8, 16, display_font_s_bold_bits};
static const font_t FONT_M = {12, 24, display_font_m_bits};
static const font_t FONT_L = {16, 32, display_font_l_bits};

#define FONT_FIRST 0x20
#define FONT_LAST  0x7E

#define HEADER_H   18
#define COLS       (UI_W / 8)
#define MAX_LINES  3
#define FOOTER_Y   (UI_H - 16)

static uint16_t s_fb[UI_W * UI_H];

const uint16_t *ui_draw_frame(void)
{
    return s_fb;
}

static void fill(int x, int y, int w, int h, uint16_t color)
{
    for (int py = y < 0 ? 0 : y; py < y + h && py < UI_H; py++) {
        for (int px = x < 0 ? 0 : x; px < x + w && px < UI_W; px++) {
            s_fb[py * UI_W + px] = color;
        }
    }
}

static void text(int x, int y, const font_t *f, uint16_t color, const char *s)
{
    const int stride = (f->w + 7) / 8;
    for (; *s; s++, x += f->w) {
        unsigned char code = (unsigned char)*s;
        if (code < FONT_FIRST || code > FONT_LAST) code = '?';
        const uint8_t *glyph = &f->bits[(code - FONT_FIRST) * f->h * stride];
        for (int gy = 0; gy < f->h; gy++) {
            for (int gx = 0; gx < f->w; gx++) {
                int px = x + gx, py = y + gy;
                if ((glyph[gy * stride + (gx >> 3)] & (0x80 >> (gx & 7))) &&
                    px >= 0 && px < UI_W && py >= 0 && py < UI_H) {
                    s_fb[py * UI_W + px] = color;
                }
            }
        }
    }
}

static void text_centered(int y, const font_t *f, uint16_t color, const char *s)
{
    int w = (int)strlen(s) * f->w;
    text(w < UI_W ? (UI_W - w) / 2 : 0, y, f, color, s);
}

// One byte per character: a character outside printable ASCII becomes '?'
// (UTF-8 continuation bytes are dropped, so it is one '?', not several).
static size_t ascii(char *dst, size_t cap, const char *src)
{
    size_t n = 0;
    for (; src != NULL && *src && n + 1 < cap; src++) {
        unsigned char c = (unsigned char)*src;
        if ((c & 0xC0) == 0x80) continue;
        dst[n++] = (c >= FONT_FIRST && c <= FONT_LAST) ? (char)c : '?';
    }
    dst[n] = 0;
    return n;
}

// Splits s over up to MAX_LINES lines of COLS characters, breaking at
// spaces (inside a word only when the word is longer than a line). Text that
// does not fit ends in "...". Returns the number of lines.
static int wrap(const char *s, size_t len, char lines[MAX_LINES][COLS + 1])
{
    int k = 0;
    size_t pos = 0;
    while (k < MAX_LINES) {
        while (pos < len && s[pos] == ' ') pos++;
        if (pos >= len) break;
        size_t rest = len - pos, take = COLS;
        bool cut = false;
        if (rest <= COLS) {
            take = rest;
        } else if (k == MAX_LINES - 1) {
            take = COLS - 3;
            cut = true;
        } else {
            for (size_t i = COLS; i > 0; i--) {
                if (s[pos + i] == ' ') {
                    take = i;
                    break;
                }
            }
        }
        size_t end = take;
        while (end > 0 && s[pos + end - 1] == ' ') end--;
        memcpy(lines[k], &s[pos], end);
        if (cut) {
            memcpy(&lines[k][end], "...", 3);
            end += 3;
        }
        lines[k][end] = 0;
        pos += take;
        k++;
    }
    return k;
}

static void version_corner(const char *version)
{
    char v[24] = "v";
    ascii(v + 1, sizeof(v) - 1, version);
    text(4, FOOTER_Y, &FONT_S, COLOR_GRAY, v);
}

void ui_draw_status(const char *title, const char *detail, uint16_t color, const char *version)
{
    fill(0, 0, UI_W, UI_H, COLOR_BLACK);

    char buf[COLS + 1];
    ascii(buf, sizeof(buf), title);
    fill(0, 0, UI_W, HEADER_H, color);
    text_centered((HEADER_H - FONT_S_BOLD.h) / 2, &FONT_S_BOLD, COLOR_BLACK, buf);

    const uint16_t message_color = (color == COLOR_ACCENT) ? COLOR_WHITE : color;
    char msg[MAX_LINES * COLS + 8];
    size_t n = ascii(msg, sizeof(msg), detail);
    if (n == 0) return;

    // One short word reads at a glance in the large font; longer text is
    // wrapped in the small one.
    if (n <= UI_W / FONT_L.w || n <= UI_W / FONT_M.w) {
        const font_t *f = (n <= UI_W / FONT_L.w) ? &FONT_L : &FONT_M;
        int area = FOOTER_Y - HEADER_H;
        text_centered(HEADER_H + (area - f->h) / 2, f, message_color, msg);
        if (version != NULL) version_corner(version);
        return;
    }
    char lines[MAX_LINES][COLS + 1];
    int k = wrap(msg, n, lines);
    int y = HEADER_H + ((UI_H - HEADER_H) - k * FONT_S.h) / 2;
    for (int i = 0; i < k; i++) {
        text_centered(y + i * FONT_S.h, &FONT_S, message_color, lines[i]);
    }
}

void ui_draw_splash(const char *version)
{
    fill(0, 0, UI_W, UI_H, COLOR_BLACK);
    text_centered((FOOTER_Y - FONT_M.h) / 2, &FONT_M, COLOR_WHITE, "QUICK-KEY");
    if (version != NULL) version_corner(version);
}

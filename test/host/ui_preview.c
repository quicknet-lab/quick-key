// Draws every screen the key can show into PPM files, using the firmware's
// own layout code (main/ui/ui_draw.c), so the screens can be looked at without
// a key. Usage: ./ui_preview OUT_DIR
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ui/ui_draw.h"

static const struct {
    const char *name, *title, *detail;
    uint16_t color;
} screens[] = {
    {"ready",        "Quick-Key",       "Ready",                          COLOR_ACCENT},
    {"touch_short",  "Touch",           "Register U2F",                   COLOR_ORANGE},
    {"signin",       "Sign in",         "github.com / denis",             COLOR_ORANGE},
    {"select",       "Select",          "Press to use this key",          COLOR_ORANGE},
    {"update",       "Update?",         "Install new firmware",           COLOR_ORANGE},
    {"reset",        "FACTORY RESET",   "Erase ALL keys and data",        COLOR_ORANGE},
    {"piv_reset",    "Reset PIV?",      "PIV keys and certificates erased", COLOR_ORANGE},
    {"otp",          "OTP",             "GitHub:denis",                   COLOR_ORANGE},
    {"long_label",   "Password?",       "a-very-long-account-name-without-spaces-at-all-and-more-and-more", COLOR_ORANGE},
    {"utf8",         "Password?",       "\xD0\x9F\xD0\xB0\xD1\x80\xD0\xBE\xD0\xBB\xD1\x8C bank", COLOR_ORANGE},
    {"erase",        "Storage error",   "Press: ERASE all keys",          COLOR_ORANGE},
    {"sec_err",      "Security error",  "PIN key in eFuse",               COLOR_RED},
    {"stor_err",     "Storage error",   "PIN partition",                  COLOR_RED},
    {"title_only",   "Quick-Key",       NULL,                             COLOR_ACCENT},
};

static void write_ppm(const char *dir, const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.ppm", dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(1); }
    fprintf(f, "P6\n%d %d\n255\n", UI_W, UI_H);
    const uint16_t *fb = ui_draw_frame();
    for (int i = 0; i < UI_W * UI_H; i++) {
        uint16_t c = fb[i];
        unsigned r = (c >> 11) & 31, g = (c >> 5) & 63, b = c & 31;
        fputc(r << 3 | r >> 2, f);
        fputc(g << 2 | g >> 4, f);
        fputc(b << 3 | b >> 2, f);
    }
    fclose(f);
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s OUT_DIR\n", argv[0]); return 2; }
    ui_draw_splash("1.5.0");
    write_ppm(argv[1], "splash");
    for (size_t i = 0; i < sizeof(screens) / sizeof(screens[0]); i++) {
        ui_draw_status(screens[i].title, screens[i].detail, screens[i].color, "1.5.0");
        write_ppm(argv[1], screens[i].name);
    }
    return 0;
}

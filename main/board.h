#pragma once
// LilyGO T-Dongle S3 pinout (from official LilyGO examples)

#define PIN_BUTTON      0   // BOOT button, active low

#define PIN_LED_DI      40  // APA102 data
#define PIN_LED_CI      39  // APA102 clock

#define PIN_LCD_MOSI    3
#define PIN_LCD_SCLK    5
#define PIN_LCD_CS      4
#define PIN_LCD_DC      2
#define PIN_LCD_RST     1
#define PIN_LCD_BL      38  // active low

#define LCD_WIDTH       160
#define LCD_HEIGHT      80

// USB identity. 1209:0001 is the pid.codes test PID; replace before release.
#define QK_USB_VID      0x1209
#define QK_USB_PID      0x0001
#define QK_MANUFACTURER "Quick-Key"
#define QK_PRODUCT      "Quick-Key 3"

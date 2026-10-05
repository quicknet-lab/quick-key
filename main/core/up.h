#pragma once
#include <stdint.h>
#include <stdbool.h>

typedef enum { UP_OK, UP_TIMEOUT, UP_CANCEL } up_result_t;

void up_init(void);
bool up_button_pressed(void);
// Blocks until the button is pressed. Shows the request on the LCD and keeps
// the host informed via worker_keepalive() while waiting.
up_result_t up_wait(const char *title, const char *detail, uint32_t timeout_ms);
// Non-blocking check for U2F: true if the button was pressed during the
// prompt started by an earlier call for the same request (id: INS || appId
// hash). The first call starts the prompt. The button must be released and
// pressed again within the prompt, so one press approves one request.
bool up_poll_u2f(const char *detail, const uint8_t id[33]);
// Flash LED/LCD for a moment (CTAPHID WINK).
void up_wink(void);
void ui_idle(void);

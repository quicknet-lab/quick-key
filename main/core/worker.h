#pragma once
#include <stdint.h>
#include <stdbool.h>

// All authenticator requests run on a single worker task, one at a time.
typedef enum { REQ_HID, REQ_CCID } req_src_t;

#define KEEPALIVE_PROCESSING 1
#define KEEPALIVE_UPNEEDED   2

void worker_start(void);
// False if the request could not be queued; the caller rolls back its state.
bool worker_post(req_src_t src);
// Call periodically during long operations. Returns false if the host cancelled.
bool worker_keepalive(uint8_t status);

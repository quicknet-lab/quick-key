#include "worker.h"
#include "usb/ctaphid.h"
#include "usb/ccid.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

static QueueHandle_t s_queue;
static req_src_t s_current;

static void worker_task(void *arg)
{
    req_src_t src;
    for (;;) {
        if (xQueueReceive(s_queue, &src, portMAX_DELAY) != pdTRUE) continue;
        s_current = src;
        if (src == REQ_HID) {
            ctaphid_process();
        } else {
            ccid_process();
        }
    }
}

void worker_start(void)
{
    s_queue = xQueueCreate(4, sizeof(req_src_t));
    // RSA key generation and mbedTLS bignum code need a deep stack.
    xTaskCreatePinnedToCore(worker_task, "worker", 24 * 1024, NULL, 5, NULL, 1);
}

bool worker_post(req_src_t src)
{
    return xQueueSend(s_queue, &src, 0) == pdTRUE;
}

bool worker_keepalive(uint8_t status)
{
    if (!s_queue) return true;      // before USB is up (prompts at boot)
    // CCID time extensions are sent by a timer in the CCID driver.
    if (s_current == REQ_HID) return ctaphid_keepalive(status);
    return true;
}

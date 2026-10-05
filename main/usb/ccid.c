// Minimal CCID class driver for TinyUSB: one always-present T=1 card,
// short and extended APDU level exchange.
#include "ccid.h"
#include "core/worker.h"
#include "apdu/apdu.h"
#include <string.h>
#include "esp_timer.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#define PC_TO_RDR_ICC_POWER_ON      0x62
#define PC_TO_RDR_ICC_POWER_OFF     0x63
#define PC_TO_RDR_GET_SLOT_STATUS   0x65
#define PC_TO_RDR_XFR_BLOCK         0x6F
#define PC_TO_RDR_GET_PARAMETERS    0x6C
#define PC_TO_RDR_RESET_PARAMETERS  0x6D
#define PC_TO_RDR_SET_PARAMETERS    0x61
#define PC_TO_RDR_ESCAPE            0x6B
#define PC_TO_RDR_ICC_CLOCK         0x6E
#define PC_TO_RDR_ABORT             0x72

#define RDR_TO_PC_DATA_BLOCK        0x80
#define RDR_TO_PC_SLOT_STATUS       0x81
#define RDR_TO_PC_PARAMETERS        0x82
#define RDR_TO_PC_ESCAPE            0x83
#define RDR_TO_PC_NOTIFY_SLOT_CHANGE 0x50

#define STATUS_OK          0x00
#define STATUS_FAILED      0x40
#define STATUS_TIME_EXT    0x80
#define ERR_CMD_NOT_SUPPORTED 0x00
#define ERR_BAD_LENGTH     0x01    // offset of dwLength
#define ERR_CMD_SLOT_BUSY  0xE0

#define TIME_EXT_INTERVAL_US 1000000

static const char *TAG = "ccid";

// OpenPGP-style ATR: T=1, IFSC 254. TCK appended at init.
static uint8_t s_atr[] = {
    0x3B, 0xDA, 0x18, 0xFF, 0x81, 0xB1, 0xFE, 0x75, 0x1F, 0x03,
    0x00, 0x31, 0xF5, 0x73, 0xC0, 0x01, 0x60, 0x00, 0x90, 0x00,
    0x00, // TCK
};

// T=1 protocol data for RDR_to_PC_Parameters.
static const uint8_t s_t1_params[] = {0x11, 0x10, 0x00, 0x15, 0x00, 0xFE, 0x00};

static uint8_t s_ep_out, s_ep_in, s_ep_int;
// One packet of slack: OUT is armed for a full packet even when fewer bytes of
// the longest message remain.
static uint8_t s_rx[CCID_HDR + CCID_MAX_DATA + CCID_EP_SIZE];
static size_t s_rx_len;
static uint32_t s_rx_skip;     // bytes of a rejected (too long) message still to drop
static uint8_t s_tx[CCID_HDR + CCID_MAX_DATA + 2];
// The worker processes its own copy of the XfrBlock, and the USB task answers
// other messages from its own buffer: after a bus reset the USB task can take
// new messages while the worker is still busy with an old one.
static uint8_t s_cmd[CCID_HDR + CCID_MAX_DATA];
static uint8_t s_ctl[CCID_HDR + 32];
static uint8_t s_ext[CCID_HDR];
static uint8_t s_notify[2];
static size_t s_tx_last;
static volatile bool s_busy;           // the worker owns s_cmd/s_tx
static volatile bool s_out_held;       // OUT stays unarmed until the reply (flow control)
static bool s_out_armed;
static volatile uint32_t s_gen, s_req_gen;     // bus resets; the reset count when s_cmd was posted
static volatile bool s_apdu_reset_req; // ICC power on: the worker resets the APDU layer
static int64_t s_last_ext_us;
static SemaphoreHandle_t s_in_free;

static void arm_out(void)
{
    if (s_out_armed || !s_ep_out) return;
    s_out_armed = usbd_edpt_xfer(0, s_ep_out, s_rx + s_rx_len, CCID_EP_SIZE, false);
}

static void wr_hdr(uint8_t *b, uint8_t type, uint32_t len, uint8_t seq, uint8_t status, uint8_t err, uint8_t spec)
{
    b[0] = type;
    b[1] = len;
    b[2] = len >> 8;
    b[3] = len >> 16;
    b[4] = len >> 24;
    b[5] = 0;       // slot
    b[6] = seq;
    b[7] = status;
    b[8] = err;
    b[9] = spec;
}

// Queue a bulk IN transfer. Caller must own s_in_free.
static void send_in(const uint8_t *buf, size_t len)
{
    if (!s_ep_in) return;       // bus reset, not configured again yet
    s_tx_last = len;
    usbd_edpt_claim(0, s_ep_in);
    usbd_edpt_xfer(0, s_ep_in, (uint8_t *)buf, len, false);
    usbd_edpt_release(0, s_ep_in);
}

// Sends a reply built in s_ctl by the USB task. If the IN endpoint is taken
// (a time extension of a request still running), the reply is dropped and OUT
// re-armed: the host times out on that one message instead of a hang.
static void send_ctl(size_t n)
{
    if (xSemaphoreTake(s_in_free, pdMS_TO_TICKS(20)) != pdTRUE) {
        s_rx_len = 0;
        arm_out();
        return;
    }
    send_in(s_ctl, n);
}

static void reply_status(uint8_t seq, uint8_t err)
{
    wr_hdr(s_ctl, RDR_TO_PC_SLOT_STATUS, 0, seq, STATUS_FAILED, err, 0);
    send_ctl(CCID_HDR);
}

// Replies that the USB task produces directly (no APDU processing).
static void reply_now(void)
{
    uint8_t type = s_rx[0];
    uint8_t seq = s_rx[6];
    size_t n = 0;

    switch (type) {
    case PC_TO_RDR_ICC_POWER_ON:
        s_apdu_reset_req = true;    // done by the worker, which owns the APDU layer
        wr_hdr(s_ctl, RDR_TO_PC_DATA_BLOCK, sizeof(s_atr), seq, STATUS_OK, 0, 0);
        memcpy(s_ctl + CCID_HDR, s_atr, sizeof(s_atr));
        n = CCID_HDR + sizeof(s_atr);
        break;
    case PC_TO_RDR_ICC_POWER_OFF:
    case PC_TO_RDR_GET_SLOT_STATUS:
    case PC_TO_RDR_ICC_CLOCK:
    case PC_TO_RDR_ABORT:
        wr_hdr(s_ctl, RDR_TO_PC_SLOT_STATUS, 0, seq, STATUS_OK, 0, 0);
        n = CCID_HDR;
        break;
    case PC_TO_RDR_GET_PARAMETERS:
    case PC_TO_RDR_RESET_PARAMETERS:
    case PC_TO_RDR_SET_PARAMETERS:
        wr_hdr(s_ctl, RDR_TO_PC_PARAMETERS, sizeof(s_t1_params), seq, STATUS_OK, 0, 0x01);
        memcpy(s_ctl + CCID_HDR, s_t1_params, sizeof(s_t1_params));
        n = CCID_HDR + sizeof(s_t1_params);
        break;
    case PC_TO_RDR_ESCAPE:
        wr_hdr(s_ctl, RDR_TO_PC_ESCAPE, 0, seq, STATUS_FAILED, ERR_CMD_NOT_SUPPORTED, 0);
        n = CCID_HDR;
        break;
    default:
        wr_hdr(s_ctl, RDR_TO_PC_SLOT_STATUS, 0, seq, STATUS_FAILED, ERR_CMD_NOT_SUPPORTED, 0);
        n = CCID_HDR;
        break;
    }
    send_ctl(n);
}

static void handle_message(void)
{
    if (s_rx[0] != PC_TO_RDR_XFR_BLOCK) {
        reply_now();
        return;
    }
    // Only after a bus reset can a request arrive while the worker still
    // runs the one from before it.
    if (s_busy) {
        reply_status(s_rx[6], ERR_CMD_SLOT_BUSY);
        return;
    }
    uint32_t len = s_rx[1] | (s_rx[2] << 8) | (s_rx[3] << 16) | ((uint32_t)s_rx[4] << 24);
    memcpy(s_cmd, s_rx, CCID_HDR + len);
    s_req_gen = s_gen;
    s_last_ext_us = esp_timer_get_time();
    s_out_held = true;
    s_busy = true;
    if (!worker_post(REQ_CCID)) {
        s_busy = false;
        s_out_held = false;
        reply_status(s_cmd[6], ERR_CMD_SLOT_BUSY);
    }
}

void ccid_process(void)
{
    uint8_t seq = s_cmd[6];
    uint32_t len = s_cmd[1] | (s_cmd[2] << 8) | (s_cmd[3] << 16) | ((uint32_t)s_cmd[4] << 24);
    if (s_apdu_reset_req) {
        s_apdu_reset_req = false;
        apdu_reset();
    }
    size_t rlen = apdu_process(s_cmd + CCID_HDR, len, s_tx + CCID_HDR, CCID_MAX_DATA);

    xSemaphoreTake(s_in_free, portMAX_DELAY);
    if (s_req_gen != s_gen) {
        // The bus was reset meanwhile: nobody waits for this reply any more.
        s_busy = false;
        xSemaphoreGive(s_in_free);
        return;
    }
    wr_hdr(s_tx, RDR_TO_PC_DATA_BLOCK, rlen, seq, STATUS_OK, 0, 0);
    s_out_held = false;
    s_busy = false;
    send_in(s_tx, CCID_HDR + rlen);
}

// Periodic timer: while an APDU is being processed (which may block the worker
// for seconds, e.g. RSA key generation) ask the host for more time.
static void time_ext_cb(void *arg)
{
    if (!s_busy || s_req_gen != s_gen || esp_timer_get_time() - s_last_ext_us < TIME_EXT_INTERVAL_US) return;
    if (xSemaphoreTake(s_in_free, pdMS_TO_TICKS(50)) != pdTRUE) return;
    if (!s_busy) {
        // The final reply won the race; the IN endpoint is idle again.
        xSemaphoreGive(s_in_free);
        return;
    }
    s_last_ext_us = esp_timer_get_time();
    wr_hdr(s_ext, RDR_TO_PC_DATA_BLOCK, 0, s_cmd[6], STATUS_TIME_EXT, 0x01, 0);
    send_in(s_ext, CCID_HDR);
}

// ---- TinyUSB class driver ----

static void drv_init(void)
{
}

static bool drv_deinit(void)
{
    return true;
}

static void drv_reset(uint8_t rhport)
{
    s_ep_out = s_ep_in = s_ep_int = 0;
    s_rx_len = 0;
    s_rx_skip = 0;
    s_out_held = false;
    s_out_armed = false;
    s_gen++;                    // a request still in the worker is dropped when it ends
    xSemaphoreGive(s_in_free);
}

static uint16_t drv_open(uint8_t rhport, tusb_desc_interface_t const *itf, uint16_t max_len)
{
    if (itf->bInterfaceClass != 0x0B) return 0;

    uint16_t len = sizeof(tusb_desc_interface_t);
    uint8_t const *p = tu_desc_next(itf);
    uint8_t eps = 0;
    while (len < max_len && eps < itf->bNumEndpoints) {
        if (tu_desc_type(p) == TUSB_DESC_ENDPOINT) {
            tusb_desc_endpoint_t const *ep = (tusb_desc_endpoint_t const *)p;
            if (!usbd_edpt_open(rhport, ep)) return 0;
            if (ep->bmAttributes.xfer == TUSB_XFER_INTERRUPT) {
                s_ep_int = ep->bEndpointAddress;
            } else if (tu_edpt_dir(ep->bEndpointAddress) == TUSB_DIR_IN) {
                s_ep_in = ep->bEndpointAddress;
            } else {
                s_ep_out = ep->bEndpointAddress;
            }
            eps++;
        }
        len += tu_desc_len(p);
        p = tu_desc_next(p);
    }

    s_rx_len = 0;
    arm_out();
    // Card is always present.
    s_notify[0] = RDR_TO_PC_NOTIFY_SLOT_CHANGE;
    s_notify[1] = 0x03;
    usbd_edpt_xfer(rhport, s_ep_int, s_notify, sizeof(s_notify), false);
    return len;
}

static bool drv_control_xfer_cb(uint8_t rhport, uint8_t stage, tusb_control_request_t const *req)
{
    if (req->bmRequestType_bit.type != TUSB_REQ_TYPE_CLASS) return false;
    // ABORT (0x01) is acknowledged; clock/data rate queries are unsupported.
    if (req->bRequest == 0x01) {
        if (stage == CONTROL_STAGE_SETUP) tud_control_status(rhport, req);
        return true;
    }
    return false;
}

static bool drv_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result, uint32_t xferred)
{
    if (ep_addr == s_ep_out) {
        s_out_armed = false;
        bool short_pkt = xferred < CCID_EP_SIZE;   // ends the host's bulk transfer
        if (s_rx_skip) {
            s_rx_skip = short_pkt ? 0 : xferred < s_rx_skip ? s_rx_skip - xferred : 0;
            arm_out();
            return true;
        }
        s_rx_len += xferred;
        if (s_rx_len >= CCID_HDR) {
            uint32_t dlen = s_rx[1] | (s_rx[2] << 8) | (s_rx[3] << 16) | ((uint32_t)s_rx[4] << 24);
            if (dlen > CCID_MAX_DATA) {
                ESP_LOGW(TAG, "message too long: %u", (unsigned)dlen);
                // Answer with an error and drop the rest of it, so that its
                // data isn't read as headers.
                if (!short_pkt) s_rx_skip = s_rx_len - CCID_HDR < dlen ? dlen - (s_rx_len - CCID_HDR) : 0;
                s_rx_len = 0;
                arm_out();
                reply_status(s_rx[6], ERR_BAD_LENGTH);
                return true;
            }
            if (s_rx_len >= CCID_HDR + dlen) {
                // Do not re-arm OUT until the reply is sent (flow control).
                handle_message();
                return true;
            }
        }
        // A transfer that ended before the message did: start over.
        if (short_pkt || s_rx_len + CCID_EP_SIZE > sizeof(s_rx)) s_rx_len = 0;
        arm_out();
    } else if (ep_addr == s_ep_in) {
        if (s_tx_last && s_tx_last % CCID_EP_SIZE == 0) {
            s_tx_last = 0;
            usbd_edpt_xfer(rhport, s_ep_in, NULL, 0, false);    // ZLP
            return true;
        }
        xSemaphoreGive(s_in_free);
        // A time extension is not the final reply; keep waiting for the APDU result.
        if (!s_out_held && !s_out_armed) {
            s_rx_len = 0;
            arm_out();
        }
    }
    return true;
}

const usbd_class_driver_t ccid_driver = {
    .name = "CCID",
    .init = drv_init,
    .deinit = drv_deinit,
    .reset = drv_reset,
    .open = drv_open,
    .control_xfer_cb = drv_control_xfer_cb,
    .xfer_cb = drv_xfer_cb,
    .sof = NULL,
};

void ccid_init(void)
{
    s_in_free = xSemaphoreCreateBinary();
    xSemaphoreGive(s_in_free);
    uint8_t tck = 0;
    for (size_t i = 1; i < sizeof(s_atr) - 1; i++) tck ^= s_atr[i];
    s_atr[sizeof(s_atr) - 1] = tck;

    static esp_timer_handle_t t;
    const esp_timer_create_args_t args = {.callback = time_ext_cb, .name = "ccid_ext"};
    ESP_ERROR_CHECK(esp_timer_create(&args, &t));
    ESP_ERROR_CHECK(esp_timer_start_periodic(t, 200 * 1000));
}

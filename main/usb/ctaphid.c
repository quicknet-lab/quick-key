#include "ctaphid.h"
#include "core/worker.h"
#include "core/crypto.h"
#include "core/up.h"
#include "fido/ctap2.h"
#include "fido/u2f.h"
#include "apps/admin.h"
#include <string.h>
#include "tinyusb.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#define CID_BROADCAST   0xFFFFFFFFu
#define MSG_TIMEOUT_US  500000
#define REPORT_TIMEOUT_US 1000000   // host not polling IN (device closed, suspend)
#define MAX_CIDS        8           // channels remembered for validation
#define INIT_DATA       (CTAPHID_PACKET - 7)
#define CONT_DATA       (CTAPHID_PACKET - 5)

typedef enum { RX_IDLE, RX_ASSEMBLING, RX_BUSY } rx_state_t;

typedef struct {
    uint32_t cid;
    uint8_t cmd;
    uint16_t len;
    const uint8_t *data;    // NULL: use inl
    uint8_t inl[17];
    SemaphoreHandle_t done;
} tx_item_t;

static struct {
    volatile rx_state_t state;
    uint32_t cid;
    uint8_t cmd;
    uint16_t bcnt;
    uint16_t got;
    uint8_t seq;
    int64_t last_us;
} s_rx;

static uint8_t s_req[CTAPHID_MAX_MSG];
static uint8_t s_resp[CTAPHID_MAX_MSG];
static volatile bool s_cancel;
static volatile uint32_t s_txn;    // bumped when INIT resyncs the busy channel
static uint32_t s_proc_txn;        // s_txn when the worker took the request
static uint32_t s_cids[MAX_CIDS];  // channels handed out by INIT (random, never 0/broadcast)
static int s_cid_next;
static QueueHandle_t s_txq;
static SemaphoreHandle_t s_tx_done;

static inline uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static inline void wr32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

// ---- TX ----

// False if the host doesn't take the report in time: the rest of the message
// is dropped instead of blocking the worker (and with it CCID) for good.
static bool send_report(const uint8_t *pkt)
{
    int64_t start = esp_timer_get_time();
    while (!tud_hid_ready()) {
        if (!tud_mounted() || esp_timer_get_time() - start > REPORT_TIMEOUT_US) return false;
        vTaskDelay(1);
    }
    return tud_hid_report(0, pkt, CTAPHID_PACKET);
}

static void tx_task(void *arg)
{
    tx_item_t it;
    uint8_t pkt[CTAPHID_PACKET];
    for (;;) {
        xQueueReceive(s_txq, &it, portMAX_DELAY);
        const uint8_t *d = it.data ? it.data : it.inl;
        size_t off = 0;
        memset(pkt, 0, sizeof(pkt));
        wr32(pkt, it.cid);
        pkt[4] = it.cmd;
        pkt[5] = it.len >> 8;
        pkt[6] = it.len & 0xFF;
        size_t n = it.len < INIT_DATA ? it.len : INIT_DATA;
        memcpy(pkt + 7, d, n);
        off = n;
        bool ok = send_report(pkt);
        for (uint8_t seq = 0; ok && off < it.len; seq++) {
            memset(pkt, 0, sizeof(pkt));
            wr32(pkt, it.cid);
            pkt[4] = seq;
            n = it.len - off < CONT_DATA ? it.len - off : CONT_DATA;
            memcpy(pkt + 5, d + off, n);
            off += n;
            ok = send_report(pkt);
        }
        if (it.done) xSemaphoreGive(it.done);
    }
}

// Small message, copied; safe from any task, never blocks.
static void send_small(uint32_t cid, uint8_t cmd, const void *data, uint16_t len)
{
    tx_item_t it = {.cid = cid, .cmd = cmd, .len = len};
    if (len) memcpy(it.inl, data, len);
    xQueueSend(s_txq, &it, 0);
}

static void send_error(uint32_t cid, uint8_t err)
{
    send_small(cid, CTAPHID_ERROR, &err, 1);
}

// Large message from the worker; waits until fully sent.
static void send_msg(uint32_t cid, uint8_t cmd, const uint8_t *data, uint16_t len)
{
    tx_item_t it = {.cid = cid, .cmd = cmd, .len = len, .data = data, .done = s_tx_done};
    xQueueSend(s_txq, &it, portMAX_DELAY);
    xSemaphoreTake(s_tx_done, portMAX_DELAY);
}

// Replies of the worker; dropped if INIT resynced the channel meanwhile, so
// that an old answer can't pass for the answer to the next request.
static void reply(uint32_t cid, uint8_t cmd, const uint8_t *data, uint16_t len)
{
    if (s_proc_txn == s_txn) send_msg(cid, cmd, data, len);
}

static void reply_error(uint32_t cid, uint8_t err)
{
    if (s_proc_txn == s_txn) send_error(cid, err);
}

// ---- RX (USB task) ----

static bool cid_known(uint32_t cid)
{
    for (int i = 0; i < MAX_CIDS; i++) {
        if (s_cids[i] == cid) return true;
    }
    return false;
}

static void handle_init(uint32_t cid, const uint8_t *nonce)
{
    uint8_t r[17];
    memcpy(r, nonce, 8);
    uint32_t new_cid = cid;
    if (cid == CID_BROADCAST) {
        // Random channel IDs: another program can't guess a client's channel
        // to cancel or resync its request.
        do {
            crypto_random((uint8_t *)&new_cid, sizeof(new_cid));
        } while (new_cid == 0 || new_cid == CID_BROADCAST || cid_known(new_cid));
        s_cids[s_cid_next] = new_cid;
        s_cid_next = (s_cid_next + 1) % MAX_CIDS;
    }
    wr32(r + 8, new_cid);
    r[12] = 2;      // CTAPHID protocol version
    fw_version(r + 13);     // device version major, minor, build
    r[16] = 0x01 | 0x04;  // CAPABILITY_WINK | CAPABILITY_CBOR
    send_small(cid, CTAPHID_INIT, r, sizeof(r));
}

void ctaphid_rx(const uint8_t *pkt, size_t len)
{
    if (len < CTAPHID_PACKET) return;
    uint32_t cid = rd32(pkt);
    int64_t now = esp_timer_get_time();

    if (s_rx.state == RX_ASSEMBLING && now - s_rx.last_us > MSG_TIMEOUT_US) {
        send_error(s_rx.cid, CTAPHID_ERR_MSG_TIMEOUT);
        s_rx.state = RX_IDLE;
    }

    if (pkt[4] & 0x80) {
        uint8_t cmd = pkt[4];
        uint16_t bcnt = ((uint16_t)pkt[5] << 8) | pkt[6];
        if (cid == 0) {
            send_error(cid, CTAPHID_ERR_INVALID_CHANNEL);
            return;
        }
        if (cmd == CTAPHID_INIT) {
            if (bcnt != 8) {
                send_error(cid, CTAPHID_ERR_INVALID_LEN);
                return;
            }
            if (cid != CID_BROADCAST && !cid_known(cid)) {
                send_error(cid, CTAPHID_ERR_INVALID_CHANNEL);
                return;
            }
            if (s_rx.state == RX_ASSEMBLING && s_rx.cid == cid) s_rx.state = RX_IDLE;
            if (s_rx.state == RX_BUSY && s_rx.cid == cid) {
                s_cancel = true;
                s_txn++;
            }
            handle_init(cid, pkt + 7);
            return;
        }
        if (cid == CID_BROADCAST || !cid_known(cid)) {
            send_error(cid, CTAPHID_ERR_INVALID_CHANNEL);
            return;
        }
        if (cmd == CTAPHID_CANCEL) {
            if (s_rx.state == RX_BUSY && s_rx.cid == cid) s_cancel = true;
            return;
        }
        if (s_rx.state == RX_BUSY) {
            send_error(cid, CTAPHID_ERR_CHANNEL_BUSY);
            return;
        }
        if (s_rx.state == RX_ASSEMBLING) {
            if (s_rx.cid != cid) {
                send_error(cid, CTAPHID_ERR_CHANNEL_BUSY);
            } else {
                send_error(cid, CTAPHID_ERR_INVALID_SEQ);
                s_rx.state = RX_IDLE;
            }
            return;
        }
        if (bcnt > CTAPHID_MAX_MSG) {
            send_error(cid, CTAPHID_ERR_INVALID_LEN);
            return;
        }
        s_rx.cid = cid;
        s_rx.cmd = cmd;
        s_rx.bcnt = bcnt;
        s_rx.got = bcnt < INIT_DATA ? bcnt : INIT_DATA;
        s_rx.seq = 0;
        s_rx.last_us = now;
        memcpy(s_req, pkt + 7, s_rx.got);
    } else {
        if (s_rx.state != RX_ASSEMBLING || cid != s_rx.cid) return;
        if (pkt[4] != s_rx.seq) {
            send_error(cid, CTAPHID_ERR_INVALID_SEQ);
            s_rx.state = RX_IDLE;
            return;
        }
        s_rx.seq++;
        uint16_t n = s_rx.bcnt - s_rx.got;
        if (n > CONT_DATA) n = CONT_DATA;
        memcpy(s_req + s_rx.got, pkt + 5, n);
        s_rx.got += n;
        s_rx.last_us = now;
    }

    if (s_rx.got >= s_rx.bcnt) {
        s_rx.state = RX_BUSY;
        s_cancel = false;
        if (!worker_post(REQ_HID)) {
            s_rx.state = RX_IDLE;
            send_error(cid, CTAPHID_ERR_CHANNEL_BUSY);
        }
    } else {
        s_rx.state = RX_ASSEMBLING;
    }
}

// ---- Worker ----

bool ctaphid_keepalive(uint8_t status)
{
    if (s_proc_txn == s_txn) send_small(s_rx.cid, CTAPHID_KEEPALIVE, &status, 1);
    return !s_cancel;
}

void ctaphid_process(void)
{
    uint32_t cid = s_rx.cid;
    uint8_t cmd = s_rx.cmd;
    uint16_t len = s_rx.bcnt;
    size_t rlen = 0;
    s_proc_txn = s_txn;

    switch (cmd) {
    case CTAPHID_PING:
        reply(cid, cmd, s_req, len);
        break;
    case CTAPHID_MSG:
        rlen = u2f_process(s_req, len, s_resp, sizeof(s_resp));
        reply(cid, cmd, s_resp, rlen);
        break;
    case CTAPHID_CBOR:
        if (len == 0) {
            reply_error(cid, CTAPHID_ERR_INVALID_LEN);
            break;
        }
        rlen = ctap2_process(s_req, len, s_resp, sizeof(s_resp));
        reply(cid, cmd, s_resp, rlen);
        break;
    case CTAPHID_WINK:
        up_wink();
        reply(cid, cmd, NULL, 0);
        break;
    default:
        // CTAPHID_LOCK (optional) is not supported, rather than claimed and ignored.
        if (cmd >= CTAPHID_VENDOR_FIRST) {
            int r = admin_hid(cmd & 0x7F, s_req, len, s_resp, sizeof(s_resp));
            if (r >= 0) {
                reply(cid, cmd, s_resp, r);
                break;
            }
        }
        reply_error(cid, CTAPHID_ERR_INVALID_CMD);
        break;
    }
    s_rx.state = RX_IDLE;
}

void ctaphid_init(void)
{
    s_txq = xQueueCreate(16, sizeof(tx_item_t));
    s_tx_done = xSemaphoreCreateBinary();
    xTaskCreatePinnedToCore(tx_task, "ctaphid_tx", 4096, NULL, 6, NULL, 1);
}

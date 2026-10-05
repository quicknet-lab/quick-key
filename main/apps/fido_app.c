// FIDO over ISO 7816 (the NFC/CCID transport of CTAP): U2F APDUs and CTAP2 via INS 0x10.
#include "apps.h"
#include "fido/ctap2.h"
#include "fido/u2f.h"
#include <string.h>

static const uint8_t s_aid[] = {0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01};
static uint8_t s_buf[2048];

static uint16_t fido_select(const apdu_t *a, rbuf_t *r)
{
    rb_put(r, "U2F_V2", 6);
    return SW_OK;
}

static uint16_t fido_process(const apdu_t *a, rbuf_t *r)
{
    if (a->ins == 0x10) {               // NFCCTAP_MSG
        if (a->lc == 0) return SW_WRONG_LENGTH;
        size_t n = ctap2_process(a->data, a->lc, s_buf, sizeof(s_buf));
        rb_put(r, s_buf, n);
        return SW_OK;
    }
    if (a->ins >= 0x01 && a->ins <= 0x03) {
        // Re-frame as an extended-length U2F APDU.
        uint8_t req[7 + 256];
        if (a->lc > 256) return SW_WRONG_LENGTH;
        req[0] = a->cla;
        req[1] = a->ins;
        req[2] = a->p1;
        req[3] = a->p2;
        req[4] = 0;
        req[5] = a->lc >> 8;
        req[6] = a->lc & 0xFF;
        memcpy(req + 7, a->data, a->lc);
        size_t n = u2f_process(req, 7 + a->lc, s_buf, sizeof(s_buf));
        uint16_t sw = (s_buf[n - 2] << 8) | s_buf[n - 1];
        rb_put(r, s_buf, n - 2);
        return sw;
    }
    return SW_INS_NOT_SUPPORTED;
}

const app_t app_fido = {
    .name = "fido",
    .aid = s_aid,
    .aid_len = sizeof(s_aid),
    .select = fido_select,
    .process = fido_process,
};

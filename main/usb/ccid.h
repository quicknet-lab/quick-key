#pragma once
#include <stdint.h>
#include "tusb.h"
#include "device/usbd_pvt.h"

#define CCID_MAX_DATA   4096
#define CCID_HDR        10
#define CCID_EP_SIZE    64

#define CCID_DESC_LEN   (9 + 54 + 7 + 7 + 7)

#define U32LE(v) (uint8_t)(v), (uint8_t)((v) >> 8), (uint8_t)((v) >> 16), (uint8_t)((v) >> 24)

// Interface + CCID class descriptor + bulk OUT/IN + interrupt IN.
#define CCID_DESCRIPTOR(_itf, _stridx, _epout, _epin, _epint) \
    9, TUSB_DESC_INTERFACE, _itf, 0, 3, 0x0B, 0x00, 0x00, _stridx, \
    54, 0x21, 0x10, 0x01,       /* bcdCCID 1.10 */ \
    0x00,                       /* bMaxSlotIndex */ \
    0x07,                       /* bVoltageSupport 5V/3V/1.8V */ \
    U32LE(0x00000002),          /* dwProtocols: T=1 */ \
    U32LE(4000), U32LE(4000),   /* default/max clock kHz */ \
    0x00,                       /* bNumClockSupported */ \
    U32LE(9600), U32LE(9600),   /* default/max data rate */ \
    0x00,                       /* bNumDataRatesSupported */ \
    U32LE(254),                 /* dwMaxIFSD */ \
    U32LE(0),                   /* dwSynchProtocols */ \
    U32LE(0),                   /* dwMechanical */ \
    U32LE(0x000400FE),          /* dwFeatures: automatic everything, extended APDU */ \
    U32LE(CCID_HDR + CCID_MAX_DATA), /* dwMaxCCIDMessageLength */ \
    0xFF, 0xFF,                 /* bClassGetResponse, bClassEnvelope */ \
    0x00, 0x00,                 /* wLcdLayout */ \
    0x00,                       /* bPINSupport */ \
    0x01,                       /* bMaxCCIDBusySlots */ \
    7, TUSB_DESC_ENDPOINT, _epout, TUSB_XFER_BULK, U16_TO_U8S_LE(CCID_EP_SIZE), 0, \
    7, TUSB_DESC_ENDPOINT, _epin, TUSB_XFER_BULK, U16_TO_U8S_LE(CCID_EP_SIZE), 0, \
    7, TUSB_DESC_ENDPOINT, _epint, TUSB_XFER_INTERRUPT, U16_TO_U8S_LE(8), 16

extern const usbd_class_driver_t ccid_driver;

void ccid_init(void);
// Worker task: run the pending XfrBlock through the APDU layer and reply.
void ccid_process(void);

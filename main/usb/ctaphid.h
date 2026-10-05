#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define CTAPHID_PACKET      64
#define CTAPHID_MAX_MSG     7609

#define CTAPHID_PING        0x81
#define CTAPHID_MSG         0x83
#define CTAPHID_LOCK        0x84
#define CTAPHID_INIT        0x86
#define CTAPHID_WINK        0x88
#define CTAPHID_CBOR        0x90
#define CTAPHID_CANCEL      0x91
#define CTAPHID_KEEPALIVE   0xBB
#define CTAPHID_ERROR       0xBF
#define CTAPHID_VENDOR_FIRST 0xC0

#define CTAPHID_ERR_INVALID_CMD     0x01
#define CTAPHID_ERR_INVALID_PAR     0x02
#define CTAPHID_ERR_INVALID_LEN     0x03
#define CTAPHID_ERR_INVALID_SEQ     0x04
#define CTAPHID_ERR_MSG_TIMEOUT     0x05
#define CTAPHID_ERR_CHANNEL_BUSY    0x06
#define CTAPHID_ERR_INVALID_CHANNEL 0x0B
#define CTAPHID_ERR_OTHER           0x7F

void ctaphid_init(void);
// USB task: one OUT report received.
void ctaphid_rx(const uint8_t *pkt, size_t len);
// Worker task: process the assembled message.
void ctaphid_process(void);
// Worker task: send KEEPALIVE; returns false if the host sent CANCEL.
bool ctaphid_keepalive(uint8_t status);

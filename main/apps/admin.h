#pragma once
#include <stdint.h>
#include <stddef.h>

#define ADMIN_VERSION       0x41
#define ADMIN_UUID          0x42
#define ADMIN_REBOOT        0x43
#define ADMIN_RNG           0x44
#define ADMIN_FACTORY_RESET 0x45
#define ADMIN_BOOTLOADER    0x46
#define ADMIN_OTA_BEGIN     0x47    // u32 BE image size; button confirmation
#define ADMIN_OTA_WRITE     0x48    // u32 BE offset || data
#define ADMIN_OTA_END       0x49    // verify signature, switch partition, reboot

#define OTA_OK              0x00
#define OTA_NOT_CONFIRMED   0x01
#define OTA_BAD_STATE       0x02
#define OTA_FLASH_ERROR     0x03
#define OTA_VERIFY_FAILED   0x04
#define OTA_DOWNGRADE       0x05    // signed, but older than the running firmware

// Firmware version (PROJECT_VER) as major, minor, patch; returns 3.
int fw_version(uint8_t out[3]);

// Vendor command (CTAPHID 0x40..0x7F). Returns response length or -1 if unknown.
int admin_hid(uint8_t cmd, const uint8_t *req, size_t len, uint8_t *resp, size_t cap);

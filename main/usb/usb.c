// USB composite device: FIDO HID + CCID smart card reader.
#include "usb.h"
#include "ccid.h"
#include "ctaphid.h"
#include "board.h"
#include <stdio.h>
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "device/usbd_pvt.h"
#include "esp_mac.h"

static const tusb_desc_device_t s_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = 0x00,
    .bDeviceSubClass = 0x00,
    .bDeviceProtocol = 0x00,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = QK_USB_VID,
    .idProduct = QK_USB_PID,
    .bcdDevice = 0x0100,
    .iManufacturer = 1,
    .iProduct = 2,
    .iSerialNumber = 3,
    .bNumConfigurations = 1,
};

static const uint8_t s_hid_report[] = {
    TUD_HID_REPORT_DESC_FIDO_U2F(CFG_TUD_HID_EP_BUFSIZE)
};

#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN + CCID_DESC_LEN)

static const uint8_t s_config[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_COUNT, 0, CONFIG_TOTAL_LEN, 0x80, 100),
    TUD_HID_INOUT_DESCRIPTOR(ITF_HID, 4, HID_ITF_PROTOCOL_NONE, sizeof(s_hid_report),
                             EP_HID_OUT, EP_HID_IN, CFG_TUD_HID_EP_BUFSIZE, 1),
    CCID_DESCRIPTOR(ITF_CCID, 5, EP_CCID_OUT, EP_CCID_IN, EP_CCID_INT),
};

static char s_serial[13];
static const char *s_strings[] = {
    (const char[]){0x09, 0x04},  // English
    QK_MANUFACTURER,
    QK_PRODUCT,
    s_serial,
    "FIDO",
    "CCID",
};

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance)
{
    (void)instance;
    return s_hid_report;
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type,
                               uint8_t *buffer, uint16_t reqlen)
{
    return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type,
                           uint8_t const *buffer, uint16_t bufsize)
{
    ctaphid_rx(buffer, bufsize);
}

usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count)
{
    *driver_count = 1;
    return &ccid_driver;
}

void usb_init(void)
{
    uint8_t mac[6];
    esp_efuse_mac_get_default(mac);
    snprintf(s_serial, sizeof(s_serial), "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    ctaphid_init();
    ccid_init();

    tinyusb_config_t cfg = TINYUSB_DEFAULT_CONFIG();
    cfg.descriptor.device = &s_device;
    cfg.descriptor.full_speed_config = s_config;
    cfg.descriptor.string = s_strings;
    cfg.descriptor.string_count = sizeof(s_strings) / sizeof(s_strings[0]);
    ESP_ERROR_CHECK(tinyusb_driver_install(&cfg));
}

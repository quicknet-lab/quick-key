#pragma once

#define EP_HID_OUT   0x01
#define EP_HID_IN    0x81
#define EP_CCID_OUT  0x02
#define EP_CCID_IN   0x82
#define EP_CCID_INT  0x83

#define ITF_HID      0
#define ITF_CCID     1
#define ITF_COUNT    2

void usb_init(void);

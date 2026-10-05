#pragma once
#include "apdu/apdu.h"

extern const app_t app_openpgp;
extern const app_t app_piv;
extern const app_t app_oath;
extern const app_t app_pwd;
extern const app_t app_admin;
extern const app_t app_fido;

// Erases all applications and the device PIN, then reboots. The caller gets the
// user's confirmation first.
void factory_reset(void);

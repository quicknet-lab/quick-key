// Host stand-in for the "pins" partition: NOR flash in RAM (a write only
// clears bits, an erase sets a whole sector to FF).
#include "esp_partition.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define SIZE    0x2000
#define SECTOR  0x1000

uint8_t g_flash[SIZE];
// Tests: the power goes off during the n-th erase/write from now (0 = never).
// That operation is left half done and it and every later one fail until the
// test sets it again.
int g_flash_cut;

static const esp_partition_t s_part = {.size = SIZE};
static int s_ops;
static bool s_off;

// 1: power on; 0: off, nothing happens; -1: goes off during this operation.
static int power(void)
{
    if (s_off) return 0;
    if (g_flash_cut && ++s_ops == g_flash_cut) {
        s_off = true;
        return -1;
    }
    return 1;
}

void flash_power_on(void)
{
    g_flash_cut = 0;
    s_ops = 0;
    s_off = false;
}

const esp_partition_t *esp_partition_find_first(int type, int subtype, const char *label)
{
    (void)type;
    (void)subtype;
    return strcmp(label, "pins") ? NULL : &s_part;
}

esp_err_t esp_partition_read(const esp_partition_t *p, size_t off, void *dst, size_t len)
{
    if (off + len > p->size) return ESP_FAIL;
    memcpy(dst, g_flash + off, len);
    return ESP_OK;
}

esp_err_t esp_partition_read_raw(const esp_partition_t *p, size_t off, void *dst, size_t len)
{
    return esp_partition_read(p, off, dst, len);
}

esp_err_t esp_partition_write(const esp_partition_t *p, size_t off, const void *src, size_t len)
{
    if (off + len > p->size || off % 16 || len % 16) return ESP_FAIL;
    int on = power();
    if (on == 0) return ESP_FAIL;
    if (on < 0) len = len / 2 & ~(size_t)15;
    for (size_t i = 0; i < len; i++) g_flash[off + i] &= ((const uint8_t *)src)[i];
    return on > 0 ? ESP_OK : ESP_FAIL;
}

esp_err_t esp_partition_erase_range(const esp_partition_t *p, size_t off, size_t len)
{
    if (off + len > p->size || off % SECTOR || len % SECTOR) return ESP_FAIL;
    int on = power();
    if (on == 0) return ESP_FAIL;
    if (on < 0) len = len > SECTOR ? SECTOR : len / 2;
    memset(g_flash + off, 0xFF, len);
    return on > 0 ? ESP_OK : ESP_FAIL;
}

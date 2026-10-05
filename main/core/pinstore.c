#include "pinstore.h"
#include "crypto.h"
#include <stdint.h>
#include <string.h>
#include "esp_partition.h"

// Sector image: header | body | SHA-256(header | body) | zero padding to 16
// bytes (flash encryption writes 16-byte blocks). The partition is
// 'encrypted', so on a key with flash encryption the image is never in the
// clear in flash.
#define SECTOR      0x1000
#define MAGIC       0x5350514Bu     // "KQPS"

typedef struct {
    uint32_t magic, seq, len, reserved;
} hdr_t;

static uint8_t s_buf[SECTOR];

static const esp_partition_t *part(void)
{
    static const esp_partition_t *p;
    if (!p) p = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "pins");
    return p;
}

static size_t image_len(size_t len)
{
    return (sizeof(hdr_t) + len + 32 + 15) & ~(size_t)15;
}

static bool newer(uint32_t a, uint32_t b)
{
    return (int32_t)(a - b) > 0;
}

// Reads sector i into s_buf: 1 a valid copy (its header in *h), 0 none,
// -1 the flash can't be read.
static int load(int i, hdr_t *h)
{
    uint8_t d[32];
    if (esp_partition_read(part(), i * SECTOR, h, sizeof(*h)) != ESP_OK) return -1;
    if (h->magic != MAGIC || h->len > PINSTORE_MAX) return 0;
    if (esp_partition_read(part(), i * SECTOR, s_buf, image_len(h->len)) != ESP_OK) return -1;
    sha256(s_buf, sizeof(hdr_t) + h->len, d);
    return memcmp(d, s_buf + sizeof(hdr_t) + h->len, 32) == 0;
}

static bool blank(int i)
{
    uint8_t b[256];
    for (size_t off = 0; off < SECTOR; off += sizeof(b)) {
        if (esp_partition_read_raw(part(), i * SECTOR + off, b, sizeof(b)) != ESP_OK) return false;
        for (size_t j = 0; j < sizeof(b); j++) if (b[j] != 0xFF) return false;
    }
    return true;
}

static bool erase(int i)
{
    return esp_partition_erase_range(part(), i * SECTOR, SECTOR) == ESP_OK;
}

// The sector with the newest valid copy, -1 if none; -2 if the flash can't
// be read. Every other sector that is not blank is erased.
static int current(hdr_t *h)
{
    hdr_t hh[2];
    int v[2], best = -1;
    for (int i = 0; i < 2; i++) {
        v[i] = load(i, &hh[i]);
        if (v[i] < 0) return -2;
        if (v[i] && (best < 0 || newer(hh[i].seq, hh[best].seq))) best = i;
    }
    for (int i = 0; i < 2; i++) if (i != best && !blank(i)) erase(i);
    if (best >= 0) *h = hh[best];
    return best;
}

int pinstore_read(void *buf, size_t len)
{
    hdr_t h;
    if (!part()) return -1;
    int cur = current(&h);
    int res = cur == -1 ? 0 : -1;
    if (cur >= 0 && h.len == len && load(cur, &h) == 1) {
        memcpy(buf, s_buf + sizeof(hdr_t), len);
        res = 1;
    }
    memset(s_buf, 0, sizeof(s_buf));
    return res;
}

bool pinstore_write(const void *buf, size_t len)
{
    hdr_t h = {.magic = MAGIC, .seq = 0};
    if (!part() || len > PINSTORE_MAX) return false;
    int cur = current(&h);
    if (cur == -2) return false;
    int dst = cur == 0;
    hdr_t nh = {.magic = MAGIC, .seq = h.seq + 1, .len = len};
    memset(s_buf, 0, sizeof(s_buf));
    memcpy(s_buf, &nh, sizeof(nh));
    memcpy(s_buf + sizeof(nh), buf, len);
    sha256(s_buf, sizeof(nh) + len, s_buf + sizeof(nh) + len);
    // current() has left dst blank (a failed erase shows in the read-back).
    bool ok = esp_partition_write(part(), dst * SECTOR, s_buf, image_len(len)) == ESP_OK;
    // Read back: the new copy must be whole before the old one goes.
    ok = ok && load(dst, &h) == 1 && h.seq == nh.seq && h.len == len &&
         memcmp(s_buf + sizeof(hdr_t), buf, len) == 0;
    memset(s_buf, 0, sizeof(s_buf));
    if (!ok) return false;
    // The new copy is in place; should erasing the old one fail, the next
    // start erases it (current()).
    if (cur >= 0) erase(cur);
    return true;
}

bool pinstore_erase(void)
{
    return part() && esp_partition_erase_range(part(), 0, 2 * SECTOR) == ESP_OK;
}

#include "crypto.h"
#include <string.h>
#include "esp_random.h"
#include "bootloader_random.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "third_party/monocypher/monocypher.h"
#include "third_party/monocypher/monocypher-ed25519.h"

void crypto_init(void)
{
    // No Wi-Fi/BT in use, so keep the SAR ADC entropy source enabled for the TRNG.
    bootloader_random_enable();
}

void crypto_random(void *buf, size_t len)
{
    esp_fill_random(buf, len);
}

int crypto_rng(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

void sha1(const uint8_t *in, size_t len, uint8_t out[20])
{
    mbedtls_sha1(in, len, out);
}

void sha256(const uint8_t *in, size_t len, uint8_t out[32])
{
    mbedtls_sha256(in, len, out, 0);
}

void sha512(const uint8_t *in, size_t len, uint8_t out[64])
{
    mbedtls_sha512(in, len, out, 0);
}

void hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *in, size_t len, uint8_t out[32])
{
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, klen, in, len, out);
}

size_t hmac_any(int md, const uint8_t *key, size_t klen, const uint8_t *in, size_t len, uint8_t *out)
{
    mbedtls_md_type_t t = md == 1 ? MBEDTLS_MD_SHA1 : md == 2 ? MBEDTLS_MD_SHA256 : MBEDTLS_MD_SHA512;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(t);
    mbedtls_md_hmac(info, key, klen, in, len, out);
    return mbedtls_md_get_size(info);
}

void hkdf_sha256(const uint8_t *salt, size_t slen, const uint8_t *ikm, size_t ilen,
                 const char *info, uint8_t *out, size_t olen)
{
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, slen, ikm, ilen,
                 (const uint8_t *)info, strlen(info), out, olen);
}

void pbkdf2_sha256(const uint8_t *pw, size_t plen, const uint8_t *salt, size_t slen,
                   uint32_t iter, uint8_t *out, size_t olen)
{
    mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, pw, plen, salt, slen, iter, olen, out);
}

bool aes256_cbc(bool enc, const uint8_t key[32], const uint8_t iv[16],
                const uint8_t *in, uint8_t *out, size_t len)
{
    if (len % 16) return false;
    mbedtls_aes_context ctx;
    uint8_t ivc[16];
    memcpy(ivc, iv, 16);
    mbedtls_aes_init(&ctx);
    int rc = enc ? mbedtls_aes_setkey_enc(&ctx, key, 256) : mbedtls_aes_setkey_dec(&ctx, key, 256);
    if (rc == 0) {
        rc = mbedtls_aes_crypt_cbc(&ctx, enc ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, len, ivc, in, out);
    }
    mbedtls_aes_free(&ctx);
    return rc == 0;
}

bool aes256_gcm(bool enc, const uint8_t key[32], const uint8_t iv[12],
                const uint8_t *in, uint8_t *out, size_t len, uint8_t tag[16])
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (rc == 0) {
        rc = enc ? mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len, iv, 12, NULL, 0, in, out, 16, tag)
                 : mbedtls_gcm_auth_decrypt(&ctx, len, iv, 12, NULL, 0, tag, 16, in, out);
    }
    mbedtls_gcm_free(&ctx);
    return rc == 0;
}

static void p256_group(mbedtls_ecp_group *grp)
{
    mbedtls_ecp_group_init(grp);
    mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);
}

static bool point_to_raw(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *q, uint8_t pub[64])
{
    uint8_t buf[65];
    size_t olen;
    if (mbedtls_ecp_point_write_binary(grp, q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, sizeof(buf)) != 0) {
        return false;
    }
    memcpy(pub, buf + 1, 64);
    return true;
}

bool p256_pubkey(const uint8_t priv[32], uint8_t pub[64])
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    p256_group(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);
    bool ok = mbedtls_mpi_read_binary(&d, priv, 32) == 0 &&
              mbedtls_ecp_check_privkey(&grp, &d) == 0 &&
              mbedtls_ecp_mul(&grp, &q, &d, &grp.G, crypto_rng, NULL) == 0 &&
              point_to_raw(&grp, &q, pub);
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

void p256_fix_privkey(uint8_t priv[32])
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    p256_group(&grp);
    mbedtls_mpi_init(&d);
    for (;;) {
        mbedtls_mpi_read_binary(&d, priv, 32);
        if (mbedtls_ecp_check_privkey(&grp, &d) == 0) break;
        sha256(priv, 32, priv);
    }
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
}

bool p256_keygen(uint8_t priv[32], uint8_t pub[64])
{
    crypto_random(priv, 32);
    p256_fix_privkey(priv);
    return p256_pubkey(priv, pub);
}

bool p256_sign(const uint8_t priv[32], const uint8_t *hash, size_t hlen, uint8_t sig_rs[64])
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    p256_group(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    bool ok = mbedtls_mpi_read_binary(&d, priv, 32) == 0 &&
              mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, hlen, crypto_rng, NULL) == 0 &&
              mbedtls_mpi_write_binary(&r, sig_rs, 32) == 0 &&
              mbedtls_mpi_write_binary(&s, sig_rs + 32, 32) == 0;
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool p256_ecdh(const uint8_t priv[32], const uint8_t peer[64], uint8_t shared_x[32])
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point q;
    uint8_t buf[65] = {0x04};
    memcpy(buf + 1, peer, 64);
    p256_group(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&q);
    bool ok = mbedtls_mpi_read_binary(&d, priv, 32) == 0 &&
              mbedtls_ecp_point_read_binary(&grp, &q, buf, sizeof(buf)) == 0 &&
              mbedtls_ecp_check_pubkey(&grp, &q) == 0 &&
              mbedtls_ecdh_compute_shared(&grp, &z, &q, &d, crypto_rng, NULL) == 0 &&
              mbedtls_mpi_write_binary(&z, shared_x, 32) == 0;
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

bool p256_ecdh_point(const uint8_t priv[32], const uint8_t peer[64], uint8_t shared[64])
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q, z;
    uint8_t buf[65] = {0x04};
    memcpy(buf + 1, peer, 64);
    p256_group(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);
    mbedtls_ecp_point_init(&z);
    bool ok = mbedtls_mpi_read_binary(&d, priv, 32) == 0 &&
              mbedtls_ecp_point_read_binary(&grp, &q, buf, sizeof(buf)) == 0 &&
              mbedtls_ecp_check_pubkey(&grp, &q) == 0 &&
              mbedtls_ecp_mul(&grp, &z, &d, &q, crypto_rng, NULL) == 0 &&
              point_to_raw(&grp, &z, shared);
    mbedtls_ecp_point_free(&z);
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ok;
}

static size_t der_int(const uint8_t *v, uint8_t *out)
{
    int i = 0;
    while (i < 31 && v[i] == 0) i++;
    size_t n = 32 - i;
    bool pad = v[i] & 0x80;
    out[0] = 0x02;
    out[1] = (uint8_t)(n + pad);
    if (pad) out[2] = 0;
    memcpy(out + 2 + pad, v + i, n);
    return 2 + pad + n;
}

size_t ecdsa_sig_to_der(const uint8_t rs[64], uint8_t *der)
{
    size_t n = der_int(rs, der + 2);
    n += der_int(rs + 32, der + 2 + n);
    der[0] = 0x30;
    der[1] = (uint8_t)n;
    return n + 2;
}

bool ct_equal(const void *a, const void *b, size_t len)
{
    const uint8_t *x = a, *y = b;
    uint8_t d = 0;
    for (size_t i = 0; i < len; i++) d |= x[i] ^ y[i];
    return d == 0;
}

void ed25519_pubkey(const uint8_t seed[32], uint8_t pub[32])
{
    uint8_t sk[64], s[32];
    memcpy(s, seed, 32);                    // key_pair wipes the seed
    crypto_ed25519_key_pair(sk, pub, s);
    crypto_wipe(sk, sizeof(sk));
}

void ed25519_sign(const uint8_t seed[32], const uint8_t *msg, size_t len, uint8_t sig[64])
{
    uint8_t sk[64], pub[32], s[32];
    memcpy(s, seed, 32);
    crypto_ed25519_key_pair(sk, pub, s);
    crypto_ed25519_sign(sig, sk, msg, len);
    crypto_wipe(sk, sizeof(sk));
}

void x25519_pubkey(const uint8_t priv[32], uint8_t pub[32])
{
    crypto_x25519_public_key(pub, priv);
}

bool x25519(const uint8_t priv[32], const uint8_t peer[32], uint8_t shared[32])
{
    static const uint8_t zero[32];
    crypto_x25519(shared, priv, peer);
    return !ct_equal(shared, zero, 32);
}

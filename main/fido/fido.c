#include "fido.h"
#include "core/crypto.h"
#include "core/store.h"
#include <string.h>
#include "esp_log.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/x509_crt.h"

static const char *TAG = "fido";

// Random AAGUID for Quick-Key 3.
const uint8_t fido_aaguid[16] = {
    0x5a, 0x1e, 0x4b, 0x2c, 0x9d, 0x37, 0x4f, 0x61, 0xa8, 0x0e, 0x3c, 0x52, 0x7b, 0x19, 0xd4, 0x86,
};

static uint8_t s_k_derive[32];
static uint8_t s_k_mac[32];
static uint8_t s_k_hmac[32];
static uint8_t s_k_lbk[32];
static uint32_t s_counter;
static uint8_t s_att_priv[32];
static uint8_t s_att_cert[600];
static size_t s_att_cert_len;

static void load_master(void)
{
    uint8_t master[32];
    if (!store_read(NS_FIDO, "master", master, sizeof(master))) {
        crypto_random(master, sizeof(master));
        store_set(NS_FIDO, "master", master, sizeof(master));
        ESP_LOGI(TAG, "new master secret");
    }
    hkdf_sha256(NULL, 0, master, 32, "qk fido derive", s_k_derive, 32);
    hkdf_sha256(NULL, 0, master, 32, "qk fido mac", s_k_mac, 32);
    hkdf_sha256(NULL, 0, master, 32, "qk fido hmac-secret", s_k_hmac, 32);
    hkdf_sha256(NULL, 0, master, 32, "qk fido largeBlobKey", s_k_lbk, 32);
    memset(master, 0, sizeof(master));
    if (!store_read(NS_FIDO, "ctr", &s_counter, sizeof(s_counter))) s_counter = 0;
}

static bool make_att_cert(void)
{
    mbedtls_pk_context pk;
    mbedtls_x509write_cert crt;
    uint8_t buf[600];
    uint8_t serial[8];
    int rc;

    mbedtls_pk_init(&pk);
    mbedtls_x509write_crt_init(&crt);
    rc = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (rc == 0) rc = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk), s_att_priv, 32);
    if (rc == 0) rc = mbedtls_ecp_keypair_calc_public(mbedtls_pk_ec(pk), crypto_rng, NULL);
    if (rc == 0) {
        crypto_random(serial, sizeof(serial));
        serial[0] &= 0x7F;
        const char *dn = "C=DE,O=Quick-Key,OU=Authenticator Attestation,CN=Quick-Key 3 Attestation";
        mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
        mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
        mbedtls_x509write_crt_set_subject_key(&crt, &pk);
        mbedtls_x509write_crt_set_issuer_key(&crt, &pk);
        mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial));
        rc = mbedtls_x509write_crt_set_subject_name(&crt, dn);
        if (rc == 0) rc = mbedtls_x509write_crt_set_issuer_name(&crt, dn);
        if (rc == 0) rc = mbedtls_x509write_crt_set_validity(&crt, "20250101000000", "20991231235959");
        if (rc == 0) rc = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
        // id-fido-gen-ce-aaguid (1.3.6.1.4.1.45724.1.1.4): OCTET STRING with the AAGUID.
        static const char oid_aaguid[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x01, 0x01, 0x04};
        uint8_t ext[18] = {0x04, 0x10};
        memcpy(ext + 2, fido_aaguid, 16);
        if (rc == 0) rc = mbedtls_x509write_crt_set_extension(&crt, oid_aaguid, sizeof(oid_aaguid), 0, ext, sizeof(ext));
    }
    if (rc == 0) {
        rc = mbedtls_x509write_crt_der(&crt, buf, sizeof(buf), crypto_rng, NULL);
        if (rc > 0) {
            // DER is written at the end of the buffer.
            s_att_cert_len = rc;
            memcpy(s_att_cert, buf + sizeof(buf) - rc, rc);
            rc = 0;
        }
    }
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&pk);
    if (rc != 0) ESP_LOGE(TAG, "attestation cert failed: -0x%x", -rc);
    return rc == 0;
}

static void load_attestation(void)
{
    size_t n = sizeof(s_att_cert);
    if (store_read(NS_SYS, "att_key", s_att_priv, 32) &&
        store_get(NS_SYS, "att_crt", s_att_cert, &n) == ESP_OK) {
        s_att_cert_len = n;
        return;
    }
    uint8_t pub[64];
    p256_keygen(s_att_priv, pub);
    if (make_att_cert()) {
        store_set(NS_SYS, "att_key", s_att_priv, 32);
        store_set(NS_SYS, "att_crt", s_att_cert, s_att_cert_len);
        ESP_LOGI(TAG, "new attestation certificate (%u bytes)", (unsigned)s_att_cert_len);
    }
}

void fido_init(void)
{
    load_master();
    load_attestation();
}

void fido_reset(void)
{
    store_erase_ns(NS_FIDO);
    load_master();
}

static void derive(const uint8_t rp_id_hash[32], const uint8_t *cred_id, uint8_t priv[32], uint8_t tag[16])
{
    uint8_t msg[1 + 16 + 32], mac[32];
    memcpy(msg, cred_id, 1 + 16);
    memcpy(msg + 17, rp_id_hash, 32);
    hmac_sha256(s_k_mac, 32, msg, sizeof(msg), mac);
    memcpy(tag, mac, 16);
    if (priv) {
        hmac_sha256(s_k_derive, 32, msg, sizeof(msg), priv);
        // Ed25519 takes the 32 bytes as a seed; P-256 needs a scalar in range.
        if (!(cred_id[0] & CRED_ED25519)) p256_fix_privkey(priv);
    }
}

void fido_new_cred(const uint8_t rp_id_hash[32], uint8_t meta, uint8_t cred_id[CRED_ID_LEN], uint8_t priv[32])
{
    cred_id[0] = meta;
    crypto_random(cred_id + 1, 16);
    derive(rp_id_hash, cred_id, priv, cred_id + 17);
}

bool fido_open_cred(const uint8_t rp_id_hash[32], const uint8_t *cred_id, size_t len, uint8_t priv[32])
{
    uint8_t tag[16];
    if (len != CRED_ID_LEN) return false;
    uint8_t m = cred_id[0];
    if ((CRED_KIND(m) != CRED_ID_VER && CRED_KIND(m) != CRED_ID_VER_RK) || (m & 0x80)) return false;
    derive(rp_id_hash, cred_id, NULL, tag);
    if (!ct_equal(tag, cred_id + 17, 16)) return false;
    derive(rp_id_hash, cred_id, priv, tag);
    return true;
}

void fido_cred_random(const uint8_t cred_id[CRED_ID_LEN], bool uv, uint8_t out[32])
{
    uint8_t msg[1 + CRED_ID_LEN];
    msg[0] = uv ? 1 : 0;
    memcpy(msg + 1, cred_id, CRED_ID_LEN);
    hmac_sha256(s_k_hmac, 32, msg, sizeof(msg), out);
}

void fido_large_blob_key(const uint8_t cred_id[CRED_ID_LEN], uint8_t out[32])
{
    hmac_sha256(s_k_lbk, 32, cred_id, CRED_ID_LEN, out);
}

bool fido_next_counter(uint32_t *ctr)
{
    s_counter++;
    *ctr = s_counter;
    return store_set(NS_FIDO, "ctr", &s_counter, sizeof(s_counter)) == ESP_OK;
}

const uint8_t *fido_att_priv(void)
{
    return s_att_priv;
}

const uint8_t *fido_att_cert(size_t *len)
{
    *len = s_att_cert_len;
    return s_att_cert;
}

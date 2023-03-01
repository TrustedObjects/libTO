/*
 *
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2019 Trusted Objects. All rights reserved.
 */

#ifndef _TO_DRIVER_H_
#define _TO_DRIVER_H_

#include "TO_cfg.h"
#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"

#include <stddef.h>

#define TODRV_API_MAJOR 5
#define TODRV_API_MINOR 1

typedef struct TODRV_api_version_s {
	uint8_t major; /**< API version major */
	uint8_t minor; /**< API version minor */
	uint16_t rfu; /**< RFU */
} TODRV_api_version_t;

#define TODRV_API_OFFSET_NOT_AVAILABLE 0

#define TODRV_API_OFFSET_COMMON (offsetof(TODRV_api_features_t, common) / sizeof(uintptr_t))

#if !defined(TO_DISABLE_TO_INFO) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_TO_INFO (1 << 0)
#define TODRV_API_OFFSET_TO_INFO (offsetof(TODRV_api_features_t, to_info) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_TO_INFO 0
#define TODRV_API_OFFSET_TO_INFO TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_SHA256) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_SHA256 (1 << 1)
#define TODRV_API_OFFSET_SHA256 (offsetof(TODRV_api_features_t, sha256) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_SHA256 0
#define TODRV_API_OFFSET_SHA256 TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_KEYS_MGMT) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_KEYS_MGMT (1 << 2)
#define TODRV_API_OFFSET_KEYS_MGMT (offsetof(TODRV_api_features_t, keys_mgmt) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_KEYS_MGMT 0
#define TODRV_API_OFFSET_KEYS_MGMT TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_AES_ENCRYPT) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_AES_ENCRYPT (1 << 3)
#define TODRV_API_OFFSET_AES_ENCRYPT (offsetof(TODRV_api_features_t, aes_encrypt) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_AES_ENCRYPT 0
#define TODRV_API_OFFSET_AES_ENCRYPT TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_HMAC) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_HMAC (1 << 4)
#define TODRV_API_OFFSET_HMAC (offsetof(TODRV_api_features_t, hmac) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_HMAC 0
#define TODRV_API_OFFSET_HMAC TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_CMAC) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_CMAC (1 << 5)
#define TODRV_API_OFFSET_CMAC (offsetof(TODRV_api_features_t, cmac) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_CMAC 0
#define TODRV_API_OFFSET_CMAC TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_SEC_MSG) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_SEC_MSG (1 << 6)
#define TODRV_API_OFFSET_SEC_MSG (offsetof(TODRV_api_features_t, sec_msg) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_SEC_MSG 0
#define TODRV_API_OFFSET_SEC_MSG TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_SIGNING) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_SIGNING (1 << 7)
#define TODRV_API_OFFSET_SIGNING (offsetof(TODRV_api_features_t, signing) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_SIGNING 0
#define TODRV_API_OFFSET_SIGNING TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_CERT_MGMT) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_CERT_MGMT (1 << 8)
#define TODRV_API_OFFSET_CERT_MGMT (offsetof(TODRV_api_features_t, cert_mgmt) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_CERT_MGMT 0
#define TODRV_API_OFFSET_CERT_MGMT TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_NVM) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_NVM (1 << 9)
#define TODRV_API_OFFSET_NVM (offsetof(TODRV_api_features_t, nvm) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_NVM 0
#define TODRV_API_OFFSET_NVM TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_TLS) || !defined(TO_DISABLE_TLS_OPTIMIZED) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_TLS (1 << 10)
#define TODRV_API_OFFSET_TLS (offsetof(TODRV_api_features_t, tls) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_TLS 0
#define TODRV_API_OFFSET_TLS TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_LORA) || !defined(TO_DISABLE_LORA_OPTIMIZED) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_LORA (1 << 11)
#define TODRV_API_OFFSET_LORA (offsetof(TODRV_api_features_t, lora) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_LORA 0
#define TODRV_API_OFFSET_LORA TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_ADMIN) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_ADMIN (1 << 12)
#define TODRV_API_OFFSET_ADMIN (offsetof(TODRV_api_features_t, admin) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_ADMIN 0
#define TODRV_API_OFFSET_ADMIN TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_STATUS_PIO_CONFIG) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_STATUS_PIO (1 << 14)
#define TODRV_API_OFFSET_STATUS_PIO (offsetof(TODRV_api_features_t, status_pio) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_STATUS_PIO 0
#define TODRV_API_OFFSET_STATUS_PIO TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_API_GET_RANDOM) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_RANDOM (1 << 15)
#define TODRV_API_OFFSET_RANDOM (offsetof(TODRV_api_features_t, random) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_RANDOM 0
#define TODRV_API_OFFSET_RANDOM TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_LOADER) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_LOADER (1 << 16)
#define TODRV_API_OFFSET_LOADER (offsetof(TODRV_api_features_t, loader) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_LOADER 0
#define TODRV_API_OFFSET_LOADER TODRV_API_OFFSET_NOT_AVAILABLE
#endif
#if !defined(TO_DISABLE_MEASURE) || defined(TODRV_API_CONFIG_ALL)
#define TODRV_API_CONFIG_MEASURE (1 << 17)
#define TODRV_API_OFFSET_MEASURE (offsetof(TODRV_api_features_t, measure) / sizeof(uintptr_t))
#else
#define TODRV_API_CONFIG_MEASURE 0
#define TODRV_API_OFFSET_MEASURE TODRV_API_OFFSET_NOT_AVAILABLE
#endif


#define TODRV_API_VERSION { \
	.major = TODRV_API_MAJOR, \
	.minor = TODRV_API_MINOR, \
}

#define TODRV_API_OFFSETS { \
	.common = TODRV_API_OFFSET_COMMON, \
	.to_info = TODRV_API_OFFSET_TO_INFO, \
	.sha256= TODRV_API_OFFSET_SHA256, \
	.keys_mgmt = TODRV_API_OFFSET_KEYS_MGMT, \
	.aes_encrypt = TODRV_API_OFFSET_AES_ENCRYPT, \
	.hmac = TODRV_API_OFFSET_HMAC, \
	.cmac = TODRV_API_OFFSET_CMAC, \
	.sec_msg = TODRV_API_OFFSET_SEC_MSG, \
	.signing = TODRV_API_OFFSET_SIGNING, \
	.cert_mgmt = TODRV_API_OFFSET_CERT_MGMT, \
	.nvm = TODRV_API_OFFSET_NVM, \
	.tls = TODRV_API_OFFSET_TLS, \
	.lora = TODRV_API_OFFSET_LORA, \
	.admin = TODRV_API_OFFSET_ADMIN, \
	.status_pio = TODRV_API_OFFSET_STATUS_PIO, \
	.random = TODRV_API_OFFSET_RANDOM, \
	.loader = TODRV_API_OFFSET_LOADER, \
	.measure = TODRV_API_OFFSET_MEASURE, \
}

typedef struct TODRV_api_offsets_s {
	uint8_t common;
	uint8_t to_info;
	uint8_t sha256;
	uint8_t keys_mgmt;
	uint8_t aes_encrypt;
	uint8_t hmac;
	uint8_t cmac;
	uint8_t sec_msg;
	uint8_t signing;
	uint8_t cert_mgmt;
	uint8_t nvm;
	uint8_t tls;
	uint8_t lora;
	uint8_t admin;
	uint8_t status_pio;
	uint8_t random;
	uint8_t loader;
	uint8_t measure;
	uint8_t rfu1;
	uint8_t rfu2;
} TODRV_api_offsets_t;

/*
 * These are all the definitions for the function pointer types needed for the driver structure
 */
typedef uint32_t (TODRV_ctx_get_size_f)(void);
typedef TO_ret_t (TODRV_init_f)(void *priv_ctx, TO_log_ctx_t *log_ctx);
typedef TO_ret_t (TODRV_fini_f)(void *priv_ctx);
#if TODRV_API_CONFIG_TO_INFO > 0
typedef TO_ret_t (TODRV_get_serial_number_f)(void *priv_ctx,uint8_t serial_number[TO_SN_SIZE]);
typedef TO_ret_t (TODRV_get_product_number_f)(void *priv_ctx,uint8_t product_number[TO_PN_SIZE]);
typedef TO_ret_t (TODRV_get_hardware_version_f)(void *priv_ctx,
		uint8_t hardware_version[TO_HW_VERSION_SIZE]);
typedef TO_ret_t (TODRV_get_hardware_serial_number_f)(void *priv_ctx, uint8_t hardware_serial_number[TO_HW_SN_SIZE]);
typedef TO_ret_t (TODRV_get_software_version_f)(void *priv_ctx,uint8_t* major, uint8_t* minor,
		uint8_t* revision);
typedef TO_ret_t (TODRV_get_product_id_f)(void *priv_ctx,uint8_t product_id[TO_PRODUCT_ID_SIZE]);
typedef TO_ret_t (TODRV_access_dummy_data_f)(void *ctx,	uint8_t write_data, uint32_t* dummy_data);
#endif
#if TODRV_API_CONFIG_SHA256 > 0
typedef TO_ret_t (TODRV_sha256_f)(void *priv_ctx,const uint8_t* data, const uint16_t data_length,
		uint8_t sha256[TO_SHA256_HASHSIZE]);
typedef TO_ret_t (TODRV_sha256_init_f)(void *priv_ctx);
typedef TO_ret_t (TODRV_sha256_update_f)(void *priv_ctx,const uint8_t* data, const uint16_t length);
typedef TO_ret_t (TODRV_sha256_final_f)(void *priv_ctx,uint8_t sha256[TO_SHA256_HASHSIZE]);
#endif
#if TODRV_API_CONFIG_KEYS_MGMT > 0
typedef TO_ret_t (TODRV_set_remote_public_key_f)(void *priv_ctx,const uint8_t key_index,
		const uint8_t public_key[TO_ECC_PUB_KEYSIZE],
		const uint8_t signature[TO_SIGNATURE_SIZE]);
typedef TO_ret_t (TODRV_renew_ecc_keys_f)(void *priv_ctx,const uint8_t key_index);
typedef TO_ret_t (TODRV_get_public_key_f)(void *priv_ctx,const uint8_t key_index,
		uint8_t public_key[TO_ECC_PUB_KEYSIZE],
		uint8_t signature[TO_SIGNATURE_SIZE]);
typedef TO_ret_t (TODRV_get_unsigned_public_key_f)(void *priv_ctx,const uint8_t key_index,
		uint8_t public_key[TO_ECC_PUB_KEYSIZE]);
typedef TO_ret_t (TODRV_renew_shared_keys_f)(void *priv_ctx,const uint8_t key_index,
		const uint8_t public_key_index);
typedef TO_ret_t (TODRV_get_key_fingerprint_f)(void *priv_ctx,TO_key_type_t key_type,
		uint8_t key_index,
		uint8_t* fingerprint[TO_KEY_FINGERPRINT_SIZE]);
#endif
#if TODRV_API_CONFIG_AES_ENCRYPT > 0
typedef TO_ret_t (TODRV_aes128cbc_encrypt_f)(void *priv_ctx,const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram);
typedef TO_ret_t (TODRV_aes128cbc_iv_encrypt_f)(void *priv_ctx,const uint8_t key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* data, const uint16_t data_length,
		uint8_t* cryptogram);
typedef TO_ret_t (TODRV_aes128cbc_decrypt_f)(void *priv_ctx,const uint8_t key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		uint8_t* data);
typedef TO_ret_t (TODRV_aes128gcm_encrypt_f)(void *priv_ctx,const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		const uint8_t* aad, const uint16_t aad_length,
		uint8_t initial_vector[TO_AESGCM_INITIALVECTOR_SIZE],
		uint8_t* cryptogram, uint8_t tag[TO_AESGCM_TAG_SIZE]);
typedef TO_ret_t (TODRV_aes128gcm_decrypt_f)(void *priv_ctx,const uint8_t key_index,
		const uint8_t initial_vector[TO_AESGCM_INITIALVECTOR_SIZE],
		const uint8_t* aad, const uint16_t aad_length,
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		const uint8_t tag[TO_AESGCM_TAG_SIZE], uint8_t* data);
typedef TO_ret_t (TODRV_aes128ccm_encrypt_f)(void *priv_ctx,const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		const uint8_t* aad, const uint16_t aad_length,
		uint8_t nonce[TO_AESCCM_NONCE_SIZE],
		uint8_t* cryptogram, uint8_t tag[TO_AESCCM_TAG_SIZE]);
typedef TO_ret_t (TODRV_aes128ccm_decrypt_f)(void *priv_ctx,const uint8_t key_index,
		const uint8_t nonce[TO_AESCCM_NONCE_SIZE],
		const uint8_t* aad, const uint16_t aad_length,
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		const uint8_t tag[TO_AESCCM_TAG_SIZE], uint8_t* data);
typedef TO_ret_t (TODRV_aes128ecb_encrypt_f)(void *priv_ctx,const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		uint8_t* cryptogram);
typedef TO_ret_t (TODRV_aes128ecb_decrypt_f)(void *priv_ctx,const uint8_t key_index,
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		uint8_t* data);
#endif
#if TODRV_API_CONFIG_HMAC > 0
typedef TO_ret_t (TODRV_compute_hmac_f)(void *priv_ctx,const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, uint8_t hmac_data[TO_HMAC_SIZE]);
typedef TO_ret_t (TODRV_compute_hmac_init_f)(void *priv_ctx,uint8_t key_index);
typedef TO_ret_t (TODRV_compute_hmac_update_f)(void *priv_ctx,const uint8_t* data, uint16_t length);
typedef TO_ret_t (TODRV_compute_hmac_final_f)(void *priv_ctx,uint8_t hmac[TO_HMAC_SIZE]);
typedef TO_ret_t (TODRV_verify_hmac_f)(void *priv_ctx,const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, const uint8_t hmac_data[TO_HMAC_SIZE]);
typedef TO_ret_t (TODRV_verify_hmac_init_f)(void *priv_ctx,uint8_t key_index);
typedef TO_ret_t (TODRV_verify_hmac_update_f)(void *priv_ctx,const uint8_t* data, uint16_t length);
typedef TO_ret_t (TODRV_verify_hmac_final_f)(void *priv_ctx,const uint8_t hmac[TO_HMAC_SIZE]);
#endif
#if TODRV_API_CONFIG_CMAC > 0
typedef TO_ret_t (TODRV_compute_cmac_f)(void *priv_ctx,const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, uint8_t cmac_data[TO_CMAC_SIZE]);
typedef TO_ret_t (TODRV_verify_cmac_f)(void *priv_ctx,const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, const uint8_t cmac_data[TO_CMAC_SIZE]);
#endif
#if TODRV_API_CONFIG_SEC_MSG > 0
typedef TO_ret_t (TODRV_aes128cbc_hmac_secure_message_f)(void *priv_ctx, const uint8_t aes_key_index,
		const uint8_t hmac_key_index, const uint8_t* data, const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE], uint8_t* cryptogram, uint8_t hmac[TO_HMAC_SIZE]);
typedef TO_ret_t (TODRV_aes128cbc_hmac_unsecure_message_f)(void *priv_ctx, const uint8_t aes_key_index,
		const uint8_t hmac_key_index, const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		const uint8_t hmac[TO_HMAC_SIZE], uint8_t* data);
typedef TO_ret_t (TODRV_aes128cbc_cmac_secure_message_f)(void *priv_ctx, const uint8_t aes_key_index,
		const uint8_t cmac_key_index, const uint8_t* data, const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE], uint8_t* cryptogram, uint8_t cmac[TO_CMAC_SIZE]);
typedef TO_ret_t (TODRV_aes128cbc_cmac_unsecure_message_f)(void *priv_ctx, const uint8_t aes_key_index,
		const uint8_t cmac_key_index, const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		const uint8_t cmac[TO_CMAC_SIZE], uint8_t* data);
typedef TO_ret_t (TODRV_secure_payload_f)(void *priv_ctx,const uint8_t key_index,
		const TO_enc_alg_t enc_alg, const TO_mac_alg_t mac_alg,
		const uint8_t* data, const uint16_t data_len,
		uint8_t* payload, uint16_t* payload_len);
typedef TO_ret_t (TODRV_secure_payload_init_f)(void *priv_ctx, const uint8_t key_index,
		const TO_enc_alg_t enc_alg, const TO_mac_alg_t mac_alg,
		const uint16_t data_len, uint8_t sequence[TO_SEQUENCE_SIZE],
		uint8_t *iv, uint16_t *iv_len);
typedef TO_ret_t (TODRV_secure_payload_update_f)(void *priv_ctx, const uint8_t* data,
		const uint16_t data_len, uint8_t* cryptogram);
typedef TO_ret_t (TODRV_secure_payload_final_f)(void *priv_ctx, const uint8_t* data, const uint16_t data_len,
		uint8_t* cryptogram, uint16_t* cryptogram_len);
typedef TO_ret_t (TODRV_unsecure_payload_f)(void *priv_ctx,const uint8_t key_index,
		const TO_enc_alg_t enc_alg, const TO_mac_alg_t mac_alg,
		const uint8_t* payload, const uint16_t payload_len,
		uint8_t* data, uint16_t* data_len);
typedef TO_ret_t (TODRV_unsecure_payload_init_cbc_f)(void *priv_ctx, const uint8_t key_index,
		const TO_enc_alg_t enc_alg, const TO_mac_alg_t mac_alg,
		const uint16_t cryptogram_len, const uint8_t sequence[TO_SEQUENCE_SIZE],
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE]);
typedef TO_ret_t (TODRV_unsecure_payload_init_aead_f)(void *priv_ctx, const uint8_t key_index,
		const TO_enc_alg_t enc_alg, const TO_mac_alg_t mac_alg,
		const uint16_t cryptogram_len,
		const uint8_t sequence[TO_SEQUENCE_SIZE]);
typedef TO_ret_t (TODRV_unsecure_payload_update_f)(void *priv_ctx, const uint8_t* cryptogram,
		const uint16_t cryptogram_len, uint8_t* data, uint16_t* data_len);
typedef TO_ret_t (TODRV_unsecure_payload_final_f)(void *priv_ctx);
#endif
#if TODRV_API_CONFIG_SIGNING > 0
typedef TO_ret_t (TODRV_sign_f)(void *priv_ctx,const uint8_t key_index, const uint8_t* challenge,
		const uint16_t challenge_length, uint8_t* signature);
typedef TO_ret_t (TODRV_verify_f)(void *priv_ctx,const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, const uint8_t* signature);
typedef TO_ret_t (TODRV_sign_hash_f)(void *priv_ctx,const uint8_t key_index,
		const uint8_t hash[TO_HASH_SIZE], uint8_t* signature);
typedef TO_ret_t (TODRV_verify_hash_signature_f)(void *priv_ctx,const uint8_t key_index,
		const uint8_t hash[TO_HASH_SIZE], const uint8_t* signature);
#endif
#if TODRV_API_CONFIG_CERT_MGMT > 0
typedef TO_ret_t (TODRV_get_certificate_subject_cn_f)(void *priv_ctx,const uint8_t certificate_index,
		char subject_cn[TO_CERT_SUBJECT_CN_MAXSIZE + 1]);
typedef TO_ret_t (TODRV_set_certificate_signing_request_dn_f)(void *priv_ctx,const uint8_t certificate_index,
		const uint8_t csr_dn[TO_CERT_DN_MAXSIZE], const uint16_t csr_dn_len);
typedef TO_ret_t (TODRV_get_certificate_signing_request_f)(void *priv_ctx,const uint8_t certificate_index,
		uint8_t* csr, uint16_t* size);
typedef TO_ret_t (TODRV_get_certificate_f)(void *priv_ctx,const uint8_t certificate_index,
		const TO_certificate_format_t format, uint8_t* certificate);
typedef TO_ret_t (TODRV_get_certificate_x509_f)(void *priv_ctx,const uint8_t certificate_index,
		uint8_t* certificate, uint16_t* size);
typedef TO_ret_t (TODRV_set_certificate_x509_f)(void *priv_ctx,const uint8_t certificate_index,
		const uint8_t* certificate, const uint16_t size);

typedef TO_ret_t (TODRV_set_certificate_x509_init_f)(void *priv_ctx, const uint8_t certificate_index);
typedef TO_ret_t (TODRV_set_certificate_x509_update_f)(void *priv_ctx,
		const uint8_t* certificate, const uint16_t size);

typedef TO_ret_t (TODRV_set_certificate_x509_final_f)(void *priv_ctx);
typedef TO_ret_t (TODRV_get_certificate_and_sign_f)(void *priv_ctx,const uint8_t certificate_index,
		const TO_certificate_format_t format,
		const uint8_t* challenge, const uint16_t challenge_length,
		uint8_t* certificate, uint8_t* signature);
typedef TO_ret_t (TODRV_get_certificate_x509_and_sign_f)(void *priv_ctx,const uint8_t certificate_index,
		const uint8_t* challenge, const uint16_t challenge_length,
		uint8_t* certificate, uint16_t* size, uint8_t* signature);
typedef TO_ret_t (TODRV_get_certificate_x509_init_f)(void *priv_ctx,
		const uint8_t certificate_index);
typedef TO_ret_t (TODRV_get_certificate_x509_update_f)(void *priv_ctx,
		uint8_t* certificate, uint16_t* size);
typedef TO_ret_t (TODRV_get_certificate_x509_final_f)(void *priv_ctx,
		const uint8_t* challenge, const uint16_t challenge_length,
		uint8_t* signature);
typedef TO_ret_t (TODRV_verify_certificate_and_store_f)(void *priv_ctx,const uint8_t ca_key_id,
		const TO_certificate_format_t format, const uint8_t* certificate);
typedef TO_ret_t (TODRV_verify_ca_certificate_and_store_f)(void *priv_ctx,const uint8_t ca_key_index,
		const uint8_t subca_key_index, const uint8_t *certificate,
		const uint16_t certificate_len);
typedef TO_ret_t (TODRV_get_challenge_and_store_f)(void *priv_ctx,
		uint8_t challenge[TO_CHALLENGE_SIZE]);
typedef TO_ret_t (TODRV_verify_challenge_signature_f)(void *priv_ctx,
		const uint8_t signature[TO_SIGNATURE_SIZE]);
typedef TO_ret_t (TODRV_verify_chain_certificate_and_store_init_f)(void *priv_ctx,
		const uint8_t ca_key_index);
typedef TO_ret_t (TODRV_verify_chain_certificate_and_store_update_f)(void *priv_ctx,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length);
typedef TO_ret_t (TODRV_verify_chain_certificate_and_store_final_f)(void *priv_ctx);
typedef TO_ret_t (TODRV_verify_chain_ca_certificate_and_store_init_f)(void *priv_ctx,
		const uint8_t ca_key_index, const uint8_t subca_key_index);
typedef TO_ret_t (TODRV_verify_chain_ca_certificate_and_store_update_f)(void *priv_ctx,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length);
typedef TO_ret_t (TODRV_verify_chain_ca_certificate_and_store_final_f)(void *priv_ctx);
#endif
#if TODRV_API_CONFIG_NVM > 0
typedef TO_ret_t (TODRV_write_nvm_f)(void *priv_ctx,const uint16_t offset, const void *data,
		unsigned int length, const uint8_t key[TO_AES_KEYSIZE]);
typedef TO_ret_t (TODRV_read_nvm_f)(void *priv_ctx,const uint16_t offset, void *data,
		unsigned int length, const uint8_t key[TO_AES_KEYSIZE]);
typedef TO_ret_t (TODRV_get_nvm_size_f)(void *priv_ctx,uint16_t *size);
#endif
#if TODRV_API_CONFIG_TLS > 0
typedef TO_ret_t (TODRV_set_tls_server_random_f)(void *priv_ctx,
		uint8_t random[TO_TLS_RANDOM_SIZE]);
typedef TO_ret_t (TODRV_set_tls_server_eph_pub_key_f)(void *priv_ctx,
		uint8_t key_index,
		uint8_t ecc_params[TO_TLS_SERVER_PARAMS_SIZE],
		uint8_t signature[TO_SIGNATURE_SIZE]);
typedef TO_ret_t (TODRV_get_tls_random_and_store_f)(void *priv_ctx,
		uint8_t timestamp[TO_TIMESTAMP_SIZE],
		uint8_t random[TO_TLS_RANDOM_SIZE]);
typedef TO_ret_t (TODRV_get_tls_master_secret_f)(void *priv_ctx,
		uint8_t master_secret[TO_TLS_MASTER_SECRET_SIZE]);
typedef TO_ret_t (TODRV_get_tls_master_secret_derived_keys_f)(void *priv_ctx,
		uint8_t key_block_length,
		uint8_t key_block[]);
typedef TO_ret_t (TODRV_renew_tls_keys_ecdhe_f)(void *priv_ctx,const uint8_t kpriv_index,
		const uint8_t kpub_index, const uint8_t enc_key_index,
		const uint8_t dec_key_index);
typedef TO_ret_t (TODRV_tls_calculate_finished_f)(void *priv_ctx,const int from,
		const uint8_t handshake_hash[TO_HASH_SIZE],
		uint8_t finished[TO_TLS_FINISHED_SIZE]);
typedef TO_ret_t (TODRV_tls_reset_f)(void *priv_ctx);
typedef TO_ret_t (TODRV_tls_set_mode_f)(void *priv_ctx,const TO_tls_mode_t mode);
typedef TO_ret_t (TODRV_tls_set_config_f)(void *priv_ctx,const TO_tls_config_id_t config_id,
		const uint8_t *config, const uint16_t config_len);
typedef TO_ret_t (TODRV_tls_set_session_f)(void *priv_ctx,const uint8_t session);
typedef TO_ret_t (TODRV_tls_set_cid_ext_id_f)(void *priv_ctx,const TO_tls_extension_t cid_ext_id);
typedef TO_ret_t (TODRV_tls_get_client_hello_f)(void *priv_ctx,
		const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		uint8_t *client_hello, uint16_t *client_hello_len);
typedef TO_ret_t (TODRV_tls_get_client_hello_ext_f)(void *priv_ctx,
		const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		const uint8_t *ext_data, uint8_t ext_length,
		uint8_t *client_hello, uint16_t *client_hello_len);
typedef TO_ret_t (TODRV_tls_get_client_hello_init_f)(void *priv_ctx,
		const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		const uint8_t *ext_data, uint8_t ext_length,
		uint16_t *client_hello_len, uint8_t *final_flag);
typedef TO_ret_t (TODRV_tls_get_client_hello_update_f)(void *priv_ctx,
		uint8_t *data, uint16_t *part_len, uint8_t *final_flag);
typedef TO_ret_t (TODRV_tls_get_client_hello_final_f)(void *priv_ctx,
		uint8_t *data);
typedef TO_ret_t (TODRV_tls_handle_hello_verify_request_f)(void *priv_ctx,
		const uint8_t *hello_verify_request,
		const uint32_t hello_verify_request_len);
typedef TO_ret_t (TODRV_tls_handle_server_hello_f)(void *priv_ctx,const uint8_t *server_hello,
		const uint32_t server_hello_len);
typedef TO_ret_t (TODRV_tls_handle_server_hello_init_f)(void *priv_ctx,
		const uint16_t server_hello_len);
typedef TO_ret_t (TODRV_tls_handle_server_hello_update_f)(void *priv_ctx,
		const uint8_t *data, const uint16_t part_len);
typedef TO_ret_t (TODRV_tls_handle_server_hello_final_f)(void *priv_ctx,
		const uint8_t *data, const uint16_t final_len);
typedef TO_ret_t (TODRV_tls_handle_server_certificate_f)(void *priv_ctx,
		const uint8_t *server_certificate,
		const uint32_t server_certificate_len);
typedef TO_ret_t (TODRV_tls_handle_server_certificate_init_f)(void *priv_ctx,
		const uint8_t *server_certificate_init,
		const uint32_t server_certificate_init_len);
typedef TO_ret_t (TODRV_tls_handle_server_certificate_update_f)(void *priv_ctx,
		const uint8_t *server_certificate,
		const uint32_t server_certificate_len);
typedef TO_ret_t (TODRV_tls_handle_server_certificate_final_f)(void *priv_ctx);
typedef TO_ret_t (TODRV_tls_handle_server_key_exchange_f)(void *priv_ctx,const uint8_t *server_key_exchange,
		const uint32_t server_key_exchange_len);
typedef TO_ret_t (TODRV_tls_handle_server_key_exchange_init_f)(void *priv_ctx,
		const uint8_t *server_key_exchange_init,
		const uint32_t server_key_exchange_init_len);
typedef TO_ret_t (TODRV_tls_handle_server_key_exchange_update_f)(void *priv_ctx,
		const uint8_t *server_key_exchange,
		const uint32_t server_key_exchange_len);
typedef TO_ret_t (TODRV_tls_handle_server_key_exchange_final_f)(void *priv_ctx);
typedef TO_ret_t (TODRV_tls_handle_certificate_request_f)(void *priv_ctx,const uint8_t *certificate_request,
		const uint32_t certificate_request_len);
typedef TO_ret_t (TODRV_tls_handle_server_hello_done_f)(void *priv_ctx,
		const uint8_t *server_hello_done,
		const uint32_t server_hello_done_len);
typedef TO_ret_t (TODRV_tls_handle_mediator_certificate_f)(void *priv_ctx,
		const uint8_t *mediator_certificate,
		const uint32_t mediator_certificate_len);
typedef TO_ret_t (TODRV_tls_get_certificate_f)(void *priv_ctx,
		uint8_t *certificate, uint16_t *certificate_len);
typedef TO_ret_t (TODRV_tls_get_certificate_init_f)(void *priv_ctx,
		uint8_t *certificate,
		uint16_t *certificate_len);
typedef TO_ret_t (TODRV_tls_get_certificate_update_f)(void *priv_ctx,
		uint8_t *certificate, uint16_t *certificate_len);
typedef TO_ret_t (TODRV_tls_get_certificate_final_f)(void *priv_ctx);
typedef TO_ret_t (TODRV_tls_get_client_key_exchange_f)(void *priv_ctx,
		uint8_t *client_key_exchange,
		uint16_t *client_key_exchange_len);
typedef TO_ret_t (TODRV_tls_get_certificate_verify_f)(void *priv_ctx,
		uint8_t *certificate_verify,
		uint16_t *certificate_verify_len);
typedef TO_ret_t (TODRV_tls_get_change_cipher_spec_f)(void *priv_ctx,
		uint8_t *change_cipher_spec,
		uint16_t *change_cipher_spec_len);
typedef TO_ret_t (TODRV_tls_get_finished_f)(void *priv_ctx,
		uint8_t *finished,
		uint16_t *finished_len);
typedef TO_ret_t (TODRV_tls_handle_change_cipher_spec_f)(void *priv_ctx,
		const uint8_t *change_cipher_spec,
		const uint32_t change_cipher_spec_len);
typedef TO_ret_t (TODRV_tls_handle_finished_f)(void *priv_ctx,
		const uint8_t *finished,
		const uint32_t finished_len);
typedef TO_ret_t (TODRV_tls_get_certificate_slot_f)(void *priv_ctx,
		uint8_t *slot);
typedef TO_ret_t (TODRV_tls_secure_payload_f)(void *priv_ctx,
		const uint8_t *header, const uint16_t header_len,
		const uint8_t* data, const uint16_t data_len,
		uint8_t *payload, uint16_t *payload_len);
typedef TO_ret_t (TODRV_tls_secure_payload_init_cbc_f)(void *priv_ctx,
		const uint8_t *header, const uint16_t header_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE]);
typedef TO_ret_t (TODRV_tls_secure_payload_init_aead_f)(void *priv_ctx,
		const uint8_t *header, const uint16_t header_len,
		uint8_t initial_vector[TO_TLS_AEAD_EXPLICIT_NONCE_SIZE]);
typedef TO_ret_t (TODRV_tls_secure_payload_update_f)(void *priv_ctx,const uint8_t* data,
		const uint16_t data_len, uint8_t *cryptogram);
typedef TO_ret_t (TODRV_tls_secure_payload_final_f)(void *priv_ctx,const uint8_t* data, const uint16_t data_len,
		uint8_t *cryptogram, uint16_t *cryptogram_len);
typedef TO_ret_t (TODRV_tls_unsecure_payload_f)(void *priv_ctx,
		const uint8_t *header, const uint16_t header_len,
		const uint8_t* payload, const uint16_t payload_len,
		uint8_t *data, uint16_t *data_len);
typedef TO_ret_t (TODRV_tls_unsecure_payload_init_cbc_f)(void *priv_ctx,const uint16_t cryptogram_len,
		const uint8_t *header, const uint16_t header_len,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE]);
typedef TO_ret_t (TODRV_tls_unsecure_payload_init_aead_f)(void *priv_ctx,const uint16_t cryptogram_len,
		const uint8_t *header, const uint16_t header_len,
		const uint8_t initial_vector[TO_TLS_AEAD_EXPLICIT_NONCE_SIZE]);
typedef TO_ret_t (TODRV_tls_unsecure_payload_update_f)(void *priv_ctx,const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t *data, uint16_t *data_len);
typedef TO_ret_t (TODRV_tls_unsecure_payload_final_f)(void *priv_ctx);
#endif
#if TODRV_API_CONFIG_LORA > 0
typedef TO_ret_t (TODRV_lora_compute_mic_f)(void *priv_ctx,const uint8_t *data, uint16_t data_length,
		uint32_t address, uint8_t direction, uint32_t seq_counter,
		uint8_t mic[TO_LORA_MIC_SIZE]);
typedef TO_ret_t (TODRV_lora_encrypt_payload_f)(void *priv_ctx,const uint8_t *data,
		uint16_t data_length, const uint8_t *fport,
		uint32_t address, uint8_t direction, uint32_t seq_counter,
		uint8_t *enc_buffer);
typedef TO_ret_t (TODRV_lora_join_compute_mic_f)(void *priv_ctx,const uint8_t *data,
		uint16_t data_length, uint8_t mic[TO_LORA_MIC_SIZE]);
typedef TO_ret_t (TODRV_lora_decrypt_join_f)(void *priv_ctx,const uint8_t *data, uint16_t data_length,
		uint8_t *dec_buffer);
typedef TO_ret_t (TODRV_lora_compute_shared_keys_f)(void *priv_ctx,const uint8_t *app_nonce,
		const uint8_t *net_id, uint16_t dev_nonce);
typedef TO_ret_t (TODRV_lora_get_app_eui_f)(void *priv_ctx,uint8_t app_eui[TO_LORA_APPEUI_SIZE]);
typedef TO_ret_t (TODRV_lora_get_dev_eui_f)(void *priv_ctx,uint8_t dev_eui[TO_LORA_DEVEUI_SIZE]);
typedef TO_ret_t (TODRV_lora_get_dev_addr_f)(void *priv_ctx,uint8_t dev_addr[TO_LORA_DEVADDR_SIZE]);
typedef TO_ret_t (TODRV_lora_get_join_request_phypayload_f)(void *priv_ctx,
		uint8_t data[TO_LORA_JOINREQUEST_SIZE]);
typedef TO_ret_t (TODRV_lora_handle_join_accept_phypayload_f)(void *priv_ctx,const uint8_t *data,
		const uint16_t data_length,
		uint8_t dec_buffer[TO_LORA_JOINACCEPT_CLEAR_MAXSIZE]);
typedef TO_ret_t (TODRV_lora_secure_phypayload_f)(void *priv_ctx,const uint8_t mhdr,
		const uint8_t fctrl, const uint8_t *fopts, const uint8_t fport,
		const uint8_t *payload, const int payload_size,
		uint8_t *enc_buffer);
typedef TO_ret_t (TODRV_lora_unsecure_phypayload_f)(void *priv_ctx,const uint8_t *data,
		const uint16_t data_length, uint8_t *dec_buffer);
#endif
#if TODRV_API_CONFIG_ADMIN > 0
typedef TO_ret_t (TODRV_admin_session_init_f)(void *priv_ctx,
		const uint8_t server_challenge[TO_ADMIN_CHALLENGE_SIZE],
		uint8_t se_challenge[TO_ADMIN_CHALLENGE_SIZE],
		uint8_t se_cryptogram[TO_ADMIN_CRYPTOGRAM_SIZE],
		uint8_t diversification_data[TO_ADMIN_DIVERS_DATA_SIZE],
		uint8_t protocol_info[TO_ADMIN_PROTO_INFO_SIZE]);
typedef TO_ret_t (TODRV_admin_session_auth_server_f)(void *priv_ctx,
		const uint8_t options[TO_ADMIN_OPTIONS_SIZE],
		const uint8_t server_cryptogram[TO_ADMIN_CRYPTOGRAM_SIZE],
		const uint8_t mac[TO_ADMIN_MAC_SIZE]);
typedef TO_ret_t (TODRV_admin_command_f)(void *priv_ctx,const uint8_t *command, uint16_t length);
typedef TO_ret_t (TODRV_admin_command_with_response_f)(void *priv_ctx,const uint8_t *command, uint16_t length,
		uint8_t *response, uint16_t response_length);
typedef TO_ret_t (TODRV_admin_command_with_response2_f)(void *priv_ctx,const uint8_t *command, uint16_t length,
		uint8_t *response, uint16_t *response_length);
typedef TO_ret_t (TODRV_admin_session_fini_f)(void *priv_ctx,uint8_t mac[TO_ADMIN_MAC_SIZE]);
typedef TO_ret_t (TODRV_admin_set_slot_f)(void *priv_ctx, const uint8_t index);
#endif
#if TODRV_API_CONFIG_STATUS_PIO > 0
typedef TO_ret_t (TODRV_set_status_PIO_config_f)(void *priv_ctx, int enable,
		int opendrain, int ready_level, int idle_hz);
typedef TO_ret_t (TODRV_get_status_PIO_config_f)(void *priv_ctx, int *enable,
		int *opendrain, int *ready_level, int *idle_hz);
#endif
typedef TO_ret_t (TODRV_flush_f)(void *priv_ctx);
#if TODRV_API_CONFIG_RANDOM > 0
typedef TO_ret_t (TODRV_get_random_f)(void *priv_ctx,const uint16_t random_length, uint8_t* random);
#endif
#if TODRV_API_CONFIG_LOADER > 0
typedef TO_ret_t (TODRV_loader_broadcast_get_info_f)(
		void *priv_ctx,
		uint8_t loader_version[TO_SW_VERSION_SIZE],
		uint8_t software_version[TO_SW_VERSION_SIZE],
		uint8_t upgrade_version[TO_SW_VERSION_SIZE]);
typedef TO_ret_t (TODRV_loader_broadcast_restore_loader_f)(
		void *priv_ctx,
		const uint8_t upgrade_version[TO_SW_VERSION_SIZE],
		const uint8_t minimum_version[TO_SW_VERSION_SIZE],
		const uint8_t cmac[TO_CMAC_SIZE],
		const uint8_t password[TO_LD_BCAST_RESTORE_PASSWORD_SIZE]);
typedef TO_ret_t (TODRV_loader_broadcast_send_init_data_f)(
		void *priv_ctx,
		const uint8_t init_data[TO_LD_BCAST_INIT_DATA_SIZE],
		const uint8_t cmac[TO_CMAC_SIZE]);
typedef TO_ret_t (TODRV_loader_broadcast_write_data_f)(
		void *priv_ctx,
		const uint8_t *segment,
		uint16_t length);
typedef TO_ret_t (TODRV_loader_broadcast_commit_release_f)(
		void *priv_ctx,
		const uint8_t cmac[TO_CMAC_SIZE]);
typedef TO_ret_t (TODRV_data_migration_f)(void *priv_ctx);
#endif

#if TODRV_API_CONFIG_MEASURE > 0
typedef TO_ret_t (TODRV_measured_boot_f)(void *priv_ctx,
		const uint8_t *hash,
		uint16_t hash_length);

typedef TO_ret_t (TODRV_validate_new_fw_hash_f)(void *priv_ctx,
		const uint8_t* hash,
		uint16_t hash_length);

typedef TO_ret_t (TODRV_commit_new_fw_hash_f)(void *priv_ctx,
		const uint8_t signed_challenge[TO_HMAC_SIZE]);

typedef TO_ret_t (TODRV_store_new_trusted_fw_hash_f)(void *priv_ctx,
		const uint8_t* fw_hash,
		uint16_t fw_hash_length,
		const uint8_t  signed_fw_hash_and_challenge[TO_HMAC_SIZE]);

typedef TO_ret_t (TODRV_get_boot_measurement_f)(void *priv_ctx,
		uint8_t* fw_hash,
		uint16_t fw_hash_length,
		const uint8_t* challenge,
		uint16_t challenge_length,
		measure_outcome_t* outcome,
		uint8_t signed_fw_hash_and_challenge[TO_HMAC_SIZE]);

typedef TO_ret_t (TODRV_get_se_measurement_f)(void *priv_ctx,
		uint8_t* hash,
		uint16_t hash_length,
		const uint8_t* challenge,
		uint16_t challenge_length,
		measure_outcome_t* outcome,
		uint8_t signed_hash_and_challenge[TO_HMAC_SIZE]);

typedef TO_ret_t (TODRV_invalidate_new_hash_f)(void *priv_ctx,
		const uint8_t password_challenge_hash[TO_SHA256_HASHSIZE]);
#endif

typedef struct TODRV_api_common_s {
	TODRV_init_f *init;
	TODRV_fini_f *fini;
	TODRV_flush_f *flush;
} TODRV_api_common_t;
#if TODRV_API_CONFIG_TO_INFO > 0
typedef struct TODRV_api_to_info_s {
	TODRV_get_serial_number_f *get_serial_number;
	TODRV_get_hardware_serial_number_f *get_hardware_serial_number;
	TODRV_get_product_number_f *get_product_number;
	TODRV_get_hardware_version_f *get_hardware_version;
	TODRV_get_software_version_f *get_software_version;
	TODRV_get_product_id_f *get_product_id;
	TODRV_access_dummy_data_f *access_dummy_data;
} TODRV_api_to_info_t;
#endif
#if TODRV_API_CONFIG_SHA256 > 0
typedef struct TODRV_api_sha256_s {
	TODRV_sha256_f *sha256;
	TODRV_sha256_init_f *sha256_init;
	TODRV_sha256_update_f *sha256_update;
	TODRV_sha256_final_f *sha256_final;
} TODRV_api_sha256_t;
#endif
#if TODRV_API_CONFIG_KEYS_MGMT > 0
typedef struct TODRV_api_keys_mgmt_s {
	TODRV_set_remote_public_key_f *set_remote_public_key;
	TODRV_renew_ecc_keys_f *renew_ecc_keys;
	TODRV_get_public_key_f *get_public_key;
	TODRV_get_unsigned_public_key_f *get_unsigned_public_key;
	TODRV_renew_shared_keys_f *renew_shared_keys;
	TODRV_get_key_fingerprint_f *get_key_fingerprint;
} TODRV_api_keys_mgmt_t;
#endif
#if TODRV_API_CONFIG_AES_ENCRYPT > 0
typedef struct TODRV_api_aes_encrypt_s {
	TODRV_aes128cbc_encrypt_f *aes128cbc_encrypt;
	TODRV_aes128cbc_iv_encrypt_f *aes128cbc_iv_encrypt;
	TODRV_aes128cbc_decrypt_f *aes128cbc_decrypt;
	TODRV_aes128gcm_encrypt_f *aes128gcm_encrypt;
	TODRV_aes128gcm_decrypt_f *aes128gcm_decrypt;
	TODRV_aes128ccm_encrypt_f *aes128ccm_encrypt;
	TODRV_aes128ccm_decrypt_f *aes128ccm_decrypt;
	TODRV_aes128ecb_encrypt_f *aes128ecb_encrypt;
	TODRV_aes128ecb_decrypt_f *aes128ecb_decrypt;
} TODRV_api_aes_encrypt_t;
#endif
#if TODRV_API_CONFIG_HMAC > 0
typedef struct TODRV_api_hmac_s {
	TODRV_compute_hmac_f *compute_hmac;
	TODRV_compute_hmac_init_f *compute_hmac_init;
	TODRV_compute_hmac_update_f *compute_hmac_update;
	TODRV_compute_hmac_final_f *compute_hmac_final;
	TODRV_verify_hmac_f *verify_hmac;
	TODRV_verify_hmac_init_f *verify_hmac_init;
	TODRV_verify_hmac_update_f *verify_hmac_update;
	TODRV_verify_hmac_final_f *verify_hmac_final;
} TODRV_api_hmac_t;
#endif
#if TODRV_API_CONFIG_CMAC > 0
typedef struct TODRV_api_cmac_s {
	TODRV_compute_cmac_f *compute_cmac;
	TODRV_verify_cmac_f *verify_cmac;
} TODRV_api_cmac_t;
#endif
#if TODRV_API_CONFIG_SEC_MSG > 0
typedef struct TODRV_api_sec_msg_s {
	TODRV_aes128cbc_hmac_secure_message_f *aes128cbc_hmac_secure_message;
	TODRV_aes128cbc_hmac_unsecure_message_f *aes128cbc_hmac_unsecure_message;
	TODRV_aes128cbc_cmac_secure_message_f *aes128cbc_cmac_secure_message;
	TODRV_aes128cbc_cmac_unsecure_message_f *aes128cbc_cmac_unsecure_message;
	TODRV_secure_payload_f *secure_payload;
	TODRV_secure_payload_init_f *secure_payload_init;
	TODRV_secure_payload_update_f *secure_payload_update;
	TODRV_secure_payload_final_f *secure_payload_final;
	TODRV_unsecure_payload_f *unsecure_payload;
	TODRV_unsecure_payload_init_cbc_f *unsecure_payload_init_cbc;
	TODRV_unsecure_payload_init_aead_f *unsecure_payload_init_aead;
	TODRV_unsecure_payload_update_f *unsecure_payload_update;
	TODRV_unsecure_payload_final_f *unsecure_payload_final;
} TODRV_api_sec_msg_t;
#endif
#if TODRV_API_CONFIG_SIGNING > 0
typedef struct TODRV_api_signing_s {
	TODRV_sign_f *sign;
	TODRV_verify_f *verify;
	TODRV_sign_hash_f *sign_hash;
	TODRV_verify_hash_signature_f *verify_hash_signature;
} TODRV_api_signing_t;
#endif
#if TODRV_API_CONFIG_CERT_MGMT > 0
typedef struct TODRV_api_cert_mgmt_s {
	TODRV_get_certificate_subject_cn_f *get_certificate_subject_cn;
	TODRV_set_certificate_signing_request_dn_f *set_certificate_signing_request_dn;
	TODRV_get_certificate_signing_request_f *get_certificate_signing_request;
	TODRV_get_certificate_f *get_certificate;
	TODRV_get_certificate_x509_f *get_certificate_x509;
	TODRV_set_certificate_x509_f *set_certificate_x509;
	TODRV_set_certificate_x509_init_f *set_certificate_x509_init;
	TODRV_set_certificate_x509_update_f *set_certificate_x509_update;
	TODRV_set_certificate_x509_final_f *set_certificate_x509_final;
	TODRV_get_certificate_and_sign_f *get_certificate_and_sign;
	TODRV_get_certificate_x509_and_sign_f *get_certificate_x509_and_sign;
	TODRV_get_certificate_x509_init_f *get_certificate_x509_init;
	TODRV_get_certificate_x509_update_f *get_certificate_x509_update;
	TODRV_get_certificate_x509_final_f *get_certificate_x509_final;
	TODRV_verify_certificate_and_store_f *verify_certificate_and_store;
	TODRV_verify_ca_certificate_and_store_f *verify_ca_certificate_and_store;
	TODRV_get_challenge_and_store_f *get_challenge_and_store;
	TODRV_verify_challenge_signature_f *verify_challenge_signature;
	TODRV_verify_chain_certificate_and_store_init_f *verify_chain_certificate_and_store_init;
	TODRV_verify_chain_certificate_and_store_update_f *verify_chain_certificate_and_store_update;
	TODRV_verify_chain_certificate_and_store_final_f *verify_chain_certificate_and_store_final;
	TODRV_verify_chain_ca_certificate_and_store_init_f *verify_chain_ca_certificate_and_store_init;
	TODRV_verify_chain_ca_certificate_and_store_update_f *verify_chain_ca_certificate_and_store_update;
	TODRV_verify_chain_ca_certificate_and_store_final_f *verify_chain_ca_certificate_and_store_final;
} TODRV_api_cert_mgmt_t;
#endif
#if TODRV_API_CONFIG_NVM > 0
typedef struct TODRV_api_nvm_s {
	TODRV_write_nvm_f *write_nvm;
	TODRV_read_nvm_f *read_nvm;
	TODRV_get_nvm_size_f *get_nvm_size;
} TODRV_api_nvm_t;
#endif
#if TODRV_API_CONFIG_TLS > 0
typedef struct TODRV_api_tls_s {
	TODRV_set_tls_server_random_f *set_tls_server_random;
	TODRV_set_tls_server_eph_pub_key_f *set_tls_server_eph_pub_key;
	TODRV_get_tls_random_and_store_f *get_tls_random_and_store;
	TODRV_get_tls_master_secret_f *get_tls_master_secret;
	TODRV_renew_tls_keys_ecdhe_f *renew_tls_keys_ecdhe;
	TODRV_tls_calculate_finished_f *tls_calculate_finished;
	TODRV_tls_reset_f *tls_reset;
	TODRV_tls_set_mode_f *tls_set_mode;
	TODRV_tls_set_config_f *tls_set_config;
	TODRV_tls_set_session_f *tls_set_session;
	TODRV_tls_set_cid_ext_id_f *tls_set_cid_ext_id;
	TODRV_tls_get_client_hello_f *tls_get_client_hello;
	TODRV_tls_get_client_hello_ext_f *tls_get_client_hello_ext;
	TODRV_tls_get_client_hello_init_f *tls_get_client_hello_init;
	TODRV_tls_get_client_hello_update_f *tls_get_client_hello_update;
	TODRV_tls_get_client_hello_final_f *tls_get_client_hello_final;
	TODRV_tls_handle_hello_verify_request_f *tls_handle_hello_verify_request;
	TODRV_tls_handle_server_hello_f *tls_handle_server_hello;
	TODRV_tls_handle_server_hello_init_f *tls_handle_server_hello_init;
	TODRV_tls_handle_server_hello_update_f *tls_handle_server_hello_update;
	TODRV_tls_handle_server_hello_final_f *tls_handle_server_hello_final;
	TODRV_tls_handle_server_certificate_f *tls_handle_server_certificate;
	TODRV_tls_handle_server_certificate_init_f *tls_handle_server_certificate_init;
	TODRV_tls_handle_server_certificate_update_f *tls_handle_server_certificate_update;
	TODRV_tls_handle_server_certificate_final_f *tls_handle_server_certificate_final;
	TODRV_tls_handle_server_key_exchange_f *tls_handle_server_key_exchange;
	TODRV_tls_handle_server_key_exchange_init_f *tls_handle_server_key_exchange_init;
	TODRV_tls_handle_server_key_exchange_update_f *tls_handle_server_key_exchange_update;
	TODRV_tls_handle_server_key_exchange_final_f *tls_handle_server_key_exchange_final;
	TODRV_tls_handle_certificate_request_f *tls_handle_certificate_request;
	TODRV_tls_handle_server_hello_done_f *tls_handle_server_hello_done;
	TODRV_tls_handle_mediator_certificate_f *tls_handle_mediator_certificate;
	TODRV_tls_get_certificate_f *tls_get_certificate;
	TODRV_tls_get_certificate_init_f *tls_get_certificate_init;
	TODRV_tls_get_certificate_update_f *tls_get_certificate_update;
	TODRV_tls_get_certificate_final_f *tls_get_certificate_final;
	TODRV_tls_get_client_key_exchange_f *tls_get_client_key_exchange;
	TODRV_tls_get_certificate_verify_f *tls_get_certificate_verify;
	TODRV_tls_get_change_cipher_spec_f *tls_get_change_cipher_spec;
	TODRV_tls_get_finished_f *tls_get_finished;
	TODRV_tls_handle_change_cipher_spec_f *tls_handle_change_cipher_spec;
	TODRV_tls_handle_finished_f *tls_handle_finished;
	TODRV_tls_get_certificate_slot_f *tls_get_certificate_slot;
	TODRV_tls_secure_payload_f *tls_secure_payload;
	TODRV_tls_secure_payload_init_cbc_f *tls_secure_payload_init_cbc;
	TODRV_tls_secure_payload_init_aead_f *tls_secure_payload_init_aead;
	TODRV_tls_secure_payload_update_f *tls_secure_payload_update;
	TODRV_tls_secure_payload_final_f *tls_secure_payload_final;
	TODRV_tls_unsecure_payload_f *tls_unsecure_payload;
	TODRV_tls_unsecure_payload_init_cbc_f *tls_unsecure_payload_init_cbc;
	TODRV_tls_unsecure_payload_init_aead_f *tls_unsecure_payload_init_aead;
	TODRV_tls_unsecure_payload_update_f *tls_unsecure_payload_update;
	TODRV_tls_unsecure_payload_final_f *tls_unsecure_payload_final;
	TODRV_get_tls_master_secret_derived_keys_f *get_tls_master_secret_derived_keys;
} TODRV_api_tls_t;
#endif
#if TODRV_API_CONFIG_LORA > 0
typedef struct TODRV_api_lora_s {
	TODRV_lora_compute_mic_f *lora_compute_mic;
	TODRV_lora_encrypt_payload_f *lora_encrypt_payload;
	TODRV_lora_join_compute_mic_f *lora_join_compute_mic;
	TODRV_lora_decrypt_join_f *lora_decrypt_join;
	TODRV_lora_compute_shared_keys_f *lora_compute_shared_keys;
	TODRV_lora_get_app_eui_f *lora_get_app_eui;
	TODRV_lora_get_dev_eui_f *lora_get_dev_eui;
	TODRV_lora_get_dev_addr_f *lora_get_dev_addr;
	TODRV_lora_get_join_request_phypayload_f *lora_get_join_request_phypayload;
	TODRV_lora_handle_join_accept_phypayload_f *lora_handle_join_accept_phypayload;
	TODRV_lora_secure_phypayload_f *lora_secure_phypayload;
	TODRV_lora_unsecure_phypayload_f *lora_unsecure_phypayload;
} TODRV_api_lora_t;
#endif
#if TODRV_API_CONFIG_ADMIN > 0
typedef struct TODRV_api_admin_s {
	TODRV_admin_session_init_f *admin_session_init;
	TODRV_admin_session_auth_server_f *admin_session_auth_server;
	TODRV_admin_command_f *admin_command;
	TODRV_admin_command_with_response_f *admin_command_with_response;
	TODRV_admin_command_with_response2_f *admin_command_with_response2;
	TODRV_admin_session_fini_f *admin_session_fini;
	TODRV_admin_set_slot_f *admin_set_slot;
} TODRV_api_admin_t;
#endif
#if TODRV_API_CONFIG_STATUS_PIO > 0
typedef struct TODRV_api_status_pio_s {
	TODRV_set_status_PIO_config_f *set_status_PIO_config;
	TODRV_get_status_PIO_config_f *get_status_PIO_config;
} TODRV_api_status_pio_t;
#endif
#if TODRV_API_CONFIG_RANDOM > 0
typedef struct TODRV_api_random_s {
	TODRV_get_random_f *get_random;
} TODRV_api_random_t;
#endif
#if TODRV_API_CONFIG_LOADER > 0
typedef struct TODRV_api_loader_s {
	TODRV_loader_broadcast_get_info_f *loader_broadcast_get_info;
	TODRV_loader_broadcast_restore_loader_f *loader_broadcast_restore_loader;
	TODRV_loader_broadcast_send_init_data_f *loader_broadcast_send_init_data;
	TODRV_loader_broadcast_write_data_f *loader_broadcast_write_data;
	TODRV_loader_broadcast_commit_release_f *loader_broadcast_commit_release;
	TODRV_data_migration_f *data_migration;
} TODRV_api_loader_t;
#endif

#if TODRV_API_CONFIG_MEASURE > 0
typedef struct TODRV_api_measure_s {
	TODRV_measured_boot_f *measured_boot;
	TODRV_validate_new_fw_hash_f *validate_new_fw_hash;
	TODRV_commit_new_fw_hash_f *commit_new_fw_hash;
	TODRV_store_new_trusted_fw_hash_f *store_new_trusted_fw_hash;
	TODRV_get_boot_measurement_f *get_boot_measurement;
	TODRV_get_se_measurement_f *get_se_measurement;
	TODRV_invalidate_new_hash_f *invalidate_new_hash;
} TODRV_api_measure_t;
#endif

typedef struct TODRV_api_features_s {
	TODRV_api_common_t common;
#if TODRV_API_CONFIG_TO_INFO > 0
	TODRV_api_to_info_t to_info;
#endif
#if TODRV_API_CONFIG_SHA256 > 0
	TODRV_api_sha256_t sha256;
#endif
#if TODRV_API_CONFIG_KEYS_MGMT > 0
	TODRV_api_keys_mgmt_t keys_mgmt;
#endif
#if TODRV_API_CONFIG_AES_ENCRYPT > 0
	TODRV_api_aes_encrypt_t aes_encrypt;
#endif
#if TODRV_API_CONFIG_HMAC > 0
	TODRV_api_hmac_t hmac;
#endif
#if TODRV_API_CONFIG_CMAC > 0
	TODRV_api_cmac_t cmac;
#endif
#if TODRV_API_CONFIG_SEC_MSG > 0
	TODRV_api_sec_msg_t sec_msg;
#endif
#if TODRV_API_CONFIG_SIGNING > 0
	TODRV_api_signing_t signing;
#endif
#if TODRV_API_CONFIG_CERT_MGMT > 0
	TODRV_api_cert_mgmt_t cert_mgmt;
#endif
#if TODRV_API_CONFIG_NVM > 0
	TODRV_api_nvm_t nvm;
#endif
#if TODRV_API_CONFIG_TLS > 0
	TODRV_api_tls_t tls;
#endif
#if TODRV_API_CONFIG_LORA > 0
	TODRV_api_lora_t lora;
#endif
#if TODRV_API_CONFIG_ADMIN > 0
	TODRV_api_admin_t admin;
#endif
#if TODRV_API_CONFIG_STATUS_PIO > 0
	TODRV_api_status_pio_t status_pio;
#endif
#if TODRV_API_CONFIG_RANDOM > 0
	TODRV_api_random_t random;
#endif
#if TODRV_API_CONFIG_LOADER > 0
	TODRV_api_loader_t loader;
#endif
#if TODRV_API_CONFIG_MEASURE > 0
	TODRV_api_measure_t measure;
#endif
} TODRV_api_features_t;

typedef struct TODRV_api_s {
	uint32_t binary_size;			/**< Final size of the binary */
	uint16_t binary_crc;			/**< Integrity of the binary */
	uint16_t binary_offset;			/**< Indicates from which byte to start computing the integrity. */
	TODRV_api_version_t api_version; 	/**< Driver API version */
	uint32_t ctx_size; 			/**< Driver private context size */
	TODRV_api_offsets_t offsets;		/**< Offsets to reach such or such API */
	TODRV_api_features_t api;		/**< Pointers to each API entry point */
} TODRV_api_t;

/* Ensure that 1 byte is enough for offsets */
COMPILE_ASSERT(sizeof(TODRV_api_features_t) / sizeof(uintptr_t) <= UINT8_MAX);

#endif // _TO_DRIVER_H_


/*
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

/**
 * @file TODRV_HSE_encrypt.h
 * @brief
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#ifndef _TODRV_HSE_ENCRYPT_H_
#define _TODRV_HSE_ENCRYPT_H_

#ifndef TODRV_HSE_ENCRYPT_API
#ifdef __linux__
#define TODRV_HSE_ENCRYPT_API
#elif _WIN32
#define TODRV_HSE_ENCRYPT_API __declspec(dllexport);
#else
#define TODRV_HSE_ENCRYPT_API
#endif /* __LINUX__ */
#endif

#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128cbc_encrypt(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128cbc_iv_encrypt(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t* cryptogram);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128cbc_decrypt(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram,
		const uint16_t cryptogram_length,
		uint8_t* data);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128gcm_encrypt(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		const uint8_t* aad,
		const uint16_t aad_length,
		uint8_t initial_vector[TO_AESGCM_INITIALVECTOR_SIZE],
		uint8_t* cryptogram,
		uint8_t tag[TO_AESGCM_TAG_SIZE]);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128gcm_decrypt(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t initial_vector[TO_AESGCM_INITIALVECTOR_SIZE],
		const uint8_t* aad,
		const uint16_t aad_length,
		const uint8_t* cryptogram,
		const uint16_t cryptogram_length,
		const uint8_t tag[TO_AESGCM_TAG_SIZE],
		uint8_t* data);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128ccm_encrypt(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		const uint8_t* aad,
		const uint16_t aad_length,
		uint8_t nonce[TO_AESCCM_NONCE_SIZE],
		uint8_t* cryptogram,
		uint8_t tag[TO_AESCCM_TAG_SIZE]);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128ccm_decrypt(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t nonce[TO_AESCCM_NONCE_SIZE],
		const uint8_t* aad,
		const uint16_t aad_length,
		const uint8_t* cryptogram,
		const uint16_t cryptogram_length,
		const uint8_t tag[TO_AESCCM_TAG_SIZE],
		uint8_t* data);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128ecb_encrypt(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t* cryptogram);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128ecb_decrypt(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* cryptogram,
		const uint16_t cryptogram_length,
		uint8_t* data);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128cbc_hmac_secure_message(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t aes_key_index,
		const uint8_t hmac_key_index,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram,
		uint8_t hmac[TO_HMAC_SIZE]);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128cbc_hmac_unsecure_message(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t aes_key_index,
		const uint8_t hmac_key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram,
		const uint16_t cryptogram_length,
		const uint8_t hmac[TO_HMAC_SIZE],
		uint8_t* data);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128cbc_cmac_secure_message(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t aes_key_index,
		const uint8_t cmac_key_index,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram,
		uint8_t cmac[TO_CMAC_SIZE]);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128cbc_cmac_unsecure_message(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t aes_key_index,
		const uint8_t cmac_key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram,
		const uint16_t cryptogram_length,
		const uint8_t cmac[TO_CMAC_SIZE],
		uint8_t* data);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_message(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const TO_enc_alg_t enc_alg,
		const TO_mac_alg_t mac_alg,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t sequence[TO_SEQUENCE_SIZE],
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram,
		uint16_t* cryptogram_len);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_message_init(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const TO_enc_alg_t enc_alg,
		const TO_mac_alg_t mac_alg,
		uint8_t sequence[TO_SEQUENCE_SIZE],
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE]);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_message_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t* cryptogram);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_message_final(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t* cryptogram,
		uint16_t* cryptogram_len);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_message(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const TO_enc_alg_t enc_alg,
		const TO_mac_alg_t mac_alg,
		const uint8_t sequence[TO_SEQUENCE_SIZE],
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t* data,
		uint16_t* data_len);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_message_init(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const TO_enc_alg_t enc_alg,
		const TO_mac_alg_t mac_alg,
		const uint16_t cryptogram_len,
		const uint8_t sequence[TO_SEQUENCE_SIZE],
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE]);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_message_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t* data,
		uint16_t* data_len);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_message_final(
		TODRV_HSE_ctx_t *ctx);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_payload(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const TO_enc_alg_t enc_alg,
		const TO_mac_alg_t mac_alg,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t* payload,
		uint16_t* payload_len);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_payload_init(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const TO_enc_alg_t enc_alg,
		const TO_mac_alg_t mac_alg,
		const uint16_t data_len,
		uint8_t sequence[TO_SEQUENCE_SIZE],
		uint8_t *iv,
		uint16_t *iv_len);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_payload_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t* cryptogram);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_payload_final(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t* cryptogram,
		uint16_t* cryptogram_len);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_payload(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const TO_enc_alg_t enc_alg,
		const TO_mac_alg_t mac_alg,
		const uint8_t* payload,
		const uint16_t payload_len,
		uint8_t* data,
		uint16_t* data_len);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_payload_init_cbc(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const TO_enc_alg_t enc_alg,
		const TO_mac_alg_t mac_alg,
		const uint16_t cryptogram_len,
		const uint8_t sequence[TO_SEQUENCE_SIZE],
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE]);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_payload_init_aead(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const TO_enc_alg_t enc_alg,
		const TO_mac_alg_t mac_alg,
		const uint16_t cryptogram_len,
		const uint8_t sequence[TO_SEQUENCE_SIZE]);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_payload_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t* data,
		uint16_t* data_len);

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_payload_final(
		TODRV_HSE_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _TODRV_HSE_ENCRYPT_H_ */

#endif /* TODRV_HSE_DRIVER_DISABLE */


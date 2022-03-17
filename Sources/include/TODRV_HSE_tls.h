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
 * @file TODRV_HSE_tls.h
 * @brief
 */

#ifndef _TODRV_HSE_TLS_H_
#define _TODRV_HSE_TLS_H_

#ifndef TODRV_HSE_TLS_API
#ifdef __linux__
#define TODRV_HSE_TLS_API
#elif _WIN32
#define TODRV_HSE_TLS_API __declspec(dllexport)
#else
#define TODRV_HSE_TLS_API
#endif /* __LINUX__ */
#endif

#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_set_tls_server_random(
		TODRV_HSE_ctx_t *ctx,
		 uint8_t random[TO_TLS_RANDOM_SIZE]);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_set_tls_server_eph_pub_key(
		TODRV_HSE_ctx_t *ctx,
		uint8_t key_index,
		uint8_t ecc_params[TO_TLS_SERVER_PARAMS_SIZE],
		uint8_t signature[TO_SIGNATURE_SIZE]);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_get_tls_random_and_store(
		TODRV_HSE_ctx_t *ctx,
		uint8_t timestamp[TO_TIMESTAMP_SIZE],
		uint8_t random[TO_TLS_RANDOM_SIZE]);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_get_tls_master_secret(
		TODRV_HSE_ctx_t *ctx,
		uint8_t master_secret[TO_TLS_MASTER_SECRET_SIZE]);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_renew_tls_keys_ecdhe(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t kpriv_index,
		const uint8_t kpub_index,
		const uint8_t enc_key_index,
		const uint8_t dec_key_index);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_calculate_finished(
		TODRV_HSE_ctx_t *ctx,
		const int from,
		const uint8_t handshake_hash[TO_HASH_SIZE],
		uint8_t finished[TO_TLS_FINISHED_SIZE]);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_reset(
		TODRV_HSE_ctx_t *ctx);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_set_mode(
		TODRV_HSE_ctx_t *ctx,
		const TO_tls_mode_t mode);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_set_config(
		TODRV_HSE_ctx_t *ctx,
		const TO_tls_config_id_t config_id,
		const uint8_t *config,
		const uint16_t config_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_set_session(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t session);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_set_cid_ext_id(
		TODRV_HSE_ctx_t *ctx,
		const TO_tls_extension_t cid_ext_id);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_client_hello(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		uint8_t *client_hello,
		uint16_t *client_hello_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_client_hello_ext(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		const uint8_t *ext_data,
		uint8_t ext_length,
		uint8_t *client_hello,
		uint16_t *client_hello_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_client_hello_init(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		const uint8_t *ext_data,
		uint8_t ext_length,
		uint16_t *client_hello_len,
		uint8_t *final_flag);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_client_hello_update(
		TODRV_HSE_ctx_t *ctx,
		uint8_t *data,
		uint16_t *part_len,
		uint8_t *final_flag);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_client_hello_final(
		TODRV_HSE_ctx_t *ctx,
		uint8_t *data);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_hello_verify_request(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *hello_verify_request,
		const uint32_t hello_verify_request_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_hello(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *server_hello,
		const uint32_t server_hello_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_hello_init(
		TODRV_HSE_ctx_t *ctx,
		const uint16_t server_hello_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_hello_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *data,
		const uint16_t part_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_hello_final(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *data,
		const uint16_t last_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_certificate(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *server_certificate,
		const uint32_t server_certificate_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_certificate_init(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *server_certificate_init,
		const uint32_t server_certificate_init_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_certificate_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *server_certificate_update,
		const uint32_t server_certificate_update_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_certificate_final(
		TODRV_HSE_ctx_t *ctx);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_key_exchange(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *server_key_exchange,
		const uint32_t server_key_exchange_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_key_exchange_init(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *server_key_exchange_init,
		const uint32_t server_key_exchange_init_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_key_exchange_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *server_key_exchange_update,
		const uint32_t server_key_exchange_update_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_key_exchange_final(
		TODRV_HSE_ctx_t *ctx);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_certificate_request(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *certificate_request,
		const uint32_t certificate_request_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_hello_done(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *server_hello_done,
		const uint32_t server_hello_done_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_mediator_certificate(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *mediator_certificate,
		const uint32_t mediator_certificate_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_certificate(
		TODRV_HSE_ctx_t *ctx,
		uint8_t *certificate,
		uint16_t *certificate_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_certificate_init(
		TODRV_HSE_ctx_t *ctx,
		uint8_t *certificate,
		uint16_t *certificate_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_certificate_update(
		TODRV_HSE_ctx_t *ctx,
		uint8_t *certificate,
		uint16_t *certificate_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_certificate_final(
		TODRV_HSE_ctx_t *ctx);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_client_key_exchange(
		TODRV_HSE_ctx_t *ctx,
		uint8_t *client_key_exchange,
		uint16_t *client_key_exchange_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_certificate_verify(
		TODRV_HSE_ctx_t *ctx,
		uint8_t *certificate_verify,
		uint16_t *certificate_verify_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_change_cipher_spec(
		TODRV_HSE_ctx_t *ctx,
		uint8_t *change_cipher_spec,
		uint16_t *change_cipher_spec_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_finished(
		TODRV_HSE_ctx_t *ctx,
		uint8_t *finished,
		uint16_t *finished_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_change_cipher_spec(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *change_cipher_spec,
		const uint32_t change_cipher_spec_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_finished(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *finished,
		const uint32_t finished_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_certificate_slot(
		TODRV_HSE_ctx_t *ctx,
		uint8_t *slot);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_message(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t *cryptogram,
		uint16_t *cryptogram_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_message_init(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE]);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_message_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t *cryptogram);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_message_final(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t *cryptogram,
		uint16_t *cryptogram_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_message(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t *data,
		uint16_t *data_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_message_init(
		TODRV_HSE_ctx_t *ctx,
		const uint16_t cryptogram_len,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE]);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_message_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t *data,
		uint16_t *data_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_message_final(
		TODRV_HSE_ctx_t *ctx);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_payload(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t *payload,
		uint16_t *payload_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_payload_init_cbc(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE]);


TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_payload_init_aead(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		uint8_t initial_vector[TO_TLS_AEAD_EXPLICIT_NONCE_SIZE]);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_payload_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t *cryptogram);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_payload_final(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t *cryptogram,
		uint16_t *cryptogram_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_payload(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t* payload,
		const uint16_t payload_len,
		uint8_t *data,
		uint16_t *data_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_payload_init_cbc(
		TODRV_HSE_ctx_t *ctx,
		const uint16_t cryptogram_len,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE]);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_payload_init_aead(
		TODRV_HSE_ctx_t *ctx,
		const uint16_t cryptogram_len,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t initial_vector[TO_TLS_AEAD_EXPLICIT_NONCE_SIZE]);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_payload_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t *data,
		uint16_t *data_len);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_payload_final(
		TODRV_HSE_ctx_t *ctx);

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_get_tls_master_secret_derived_keys(
		TODRV_HSE_ctx_t *ctx,
		uint8_t key_block_length,
		uint8_t key_block[]);

#ifdef __cplusplus
}
#endif

#endif /* _TODRV_HSE_TLS_H_ */


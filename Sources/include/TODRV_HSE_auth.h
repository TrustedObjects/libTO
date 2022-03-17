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
 * @file TODRV_HSE_auth.h
 * @brief
 */

#ifndef _TODRV_HSE_AUTH_H_
#define _TODRV_HSE_AUTH_H_

#ifndef TODRV_HSE_AUTH_API
#ifdef __linux__
#define TODRV_HSE_AUTH_API
#elif _WIN32
#define TODRV_HSE_AUTH_API __declspec(dllexport)
#else
#define TODRV_HSE_AUTH_API
#endif /* __LINUX__ */
#endif

#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"
#include "TODRV_HSE.h"

#ifdef __cplusplus
extern "C" {
#endif

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_subject_cn(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index,
		char subject_cn[TO_CERT_SUBJECT_CN_MAXSIZE + 1]);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_set_certificate_signing_request_dn(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const uint8_t csr_dn[TO_CERT_DN_MAXSIZE],
		const uint16_t csr_dn_len);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_signing_request(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index,
		uint8_t* csr,
		uint16_t* size);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const TO_certificate_format_t format,
		uint8_t* certificate);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_x509(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index,
		uint8_t* certificate,
		uint16_t* size);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_set_certificate_x509(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const uint8_t* certificate,
		const uint16_t size);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_set_certificate_x509_init(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_set_certificate_x509_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* certificate,
		const uint16_t size);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_x509_init(
		TODRV_HSE_ctx_t *priv_ctx,
		const uint8_t certificate_index);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_x509_update(
		TODRV_HSE_ctx_t *priv_ctx,
		uint8_t* certificate, uint16_t* size);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_x509_final(
		TODRV_HSE_ctx_t *priv_ctx,
		const uint8_t* challenge, const uint16_t challenge_length,
		uint8_t* signature);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_set_certificate_x509_final(
		TODRV_HSE_ctx_t *ctx);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_and_sign(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const TO_certificate_format_t format,
		const uint8_t* challenge,
		const uint16_t challenge_length,
		uint8_t* certificate,
		uint8_t* signature);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_x509_and_sign(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const uint8_t* challenge,
		const uint16_t challenge_length,
		uint8_t* certificate,
		uint16_t* size,
		uint8_t* signature);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_certificate_and_store(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t ca_key_id,
		const TO_certificate_format_t format,
		const uint8_t* certificate);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_ca_certificate_and_store(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t ca_key_index,
		const uint8_t subca_key_index,
		const uint8_t *certificate,
		const uint16_t certificate_len);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_challenge_and_store(
		TODRV_HSE_ctx_t *ctx,
		uint8_t challenge[TO_CHALLENGE_SIZE]);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_challenge_signature(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t signature[TO_SIGNATURE_SIZE]);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_chain_certificate_and_store_init(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t ca_key_index);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_chain_certificate_and_store_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_chain_certificate_and_store_final(
		TODRV_HSE_ctx_t *ctx);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_chain_ca_certificate_and_store_init(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t ca_key_index,
		const uint8_t subca_key_index);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_chain_ca_certificate_and_store_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_chain_ca_certificate_and_store_final(
		TODRV_HSE_ctx_t *ctx);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_sign(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* challenge,
		const uint16_t challenge_length,
		uint8_t* signature);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		const uint8_t* signature);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_sign_hash(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t hash[TO_HASH_SIZE],
		uint8_t* signature);

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_hash_signature(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t hash[TO_HASH_SIZE],
		const uint8_t* signature);

#ifdef __cplusplus
}
#endif

#endif /* _TODRV_HSE_AUTH_H_ */


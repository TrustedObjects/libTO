/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2018 Trusted Objects. All rights reserved.
 */

/**
 * @file helper_certs.c
 * @brief Secure Element certificates helper, based on Secure Element APIs to
 * simplify commands sequences.
 */

#include "TO.h"
#include "TO_helper.h"

#if defined(TOSE_DRIVER_HSE) && !defined(TO_DISABLE_CERTS_HELPER)

#include "TODRV_HSE_cfg.h"
#include "TODRV_HSE_defs.h"

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define _VERIFY_CHAIN_CERTIFICATE_AND_STORE_UPDATE_SIZE (MIN(TODRV_HSE_MAXSIZE, TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE) - TODRV_HSE_CMDHEAD_SIZE)

TO_lib_ret_t TOSE_helper_verify_chain_certificate_and_store(TOSE_ctx_t *ctx,
		const uint8_t ca_key_index,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length)
{
	uint32_t offset = 0;
	TO_ret_t ret;

	ret = TOSE_verify_chain_certificate_and_store_init(ctx, ca_key_index);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	while (offset < chain_certificate_length) {
		uint32_t len = MIN(_VERIFY_CHAIN_CERTIFICATE_AND_STORE_UPDATE_SIZE,
				chain_certificate_length- offset);
		ret = TOSE_verify_chain_certificate_and_store_update(ctx,
				chain_certificate + offset, len);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
		offset += len;
	}

	ret = TOSE_verify_chain_certificate_and_store_final(ctx);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	return TO_OK;
}

#define _VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_UPDATE_SIZE (MIN(TODRV_HSE_MAXSIZE, TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE) - TODRV_HSE_CMDHEAD_SIZE)

TO_lib_ret_t TOSE_helper_verify_chain_ca_certificate_and_store(TOSE_ctx_t *ctx,
		const uint8_t ca_key_index,
		const uint8_t subca_key_index,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length)
{
	uint32_t offset = 0;
	TO_ret_t ret;

	ret = TOSE_verify_chain_ca_certificate_and_store_init(ctx, ca_key_index,
			subca_key_index);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	while (offset < chain_certificate_length) {
		uint32_t len = MIN(_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_UPDATE_SIZE,
				chain_certificate_length - offset);
		ret = TOSE_verify_chain_ca_certificate_and_store_update(ctx,
				chain_certificate + offset, len);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
		offset += len;
	}

	ret = TOSE_verify_chain_ca_certificate_and_store_final(ctx);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	return TO_OK;
}

#define _SET_CERTIFICATE_X509_UPDATE_SIZE (MIN(TODRV_HSE_MAXSIZE, TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE) - TODRV_HSE_CMDHEAD_SIZE)

#ifndef TO_DISABLE_API_SET_CERTIFICATE_X509_INIT_UPDATE_FINAL
TO_lib_ret_t TOSE_helper_set_certificate_x509(
		TOSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const uint8_t* certificate,
		const uint16_t size)
{
	uint32_t offset = 0;
	TO_ret_t ret;

	ret = TOSE_set_certificate_x509_init(ctx, certificate_index);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	while (offset < size) {
		uint32_t len = MIN(_SET_CERTIFICATE_X509_UPDATE_SIZE, size - offset);
		ret = TOSE_set_certificate_x509_update(ctx, certificate + offset, len);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
		offset += len;
	}

	ret = TOSE_set_certificate_x509_final(ctx);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	return TO_OK;
}
#endif

TO_lib_ret_t TOSE_helper_get_certificate_x509_and_sign(
		TOSE_ctx_t *ctx, const uint8_t certificate_index,
		const uint8_t *challenge, const uint16_t challenge_length,
		uint8_t *certificate, uint16_t *size, uint8_t signature[TO_SIGNATURE_SIZE])
{
	TO_ret_t ret;
	uint16_t chunk_sz = 200;
	uint16_t offset;

        ret = TOSE_get_certificate_x509_init(ctx, certificate_index);
	if (ret == TORSP_UNKNOWN_CMD) {
		/* If CAPI is not available, try direct API */
		ret = TOSE_get_certificate_x509_and_sign(ctx, certificate_index,
		challenge, challenge_length,
		certificate, size, signature);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
		return TO_OK;
	}
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	for (offset = 0; chunk_sz; offset += chunk_sz) {
		ret = TOSE_get_certificate_x509_update(ctx, certificate + offset, &chunk_sz);
		if (ret != TORSP_SUCCESS) {
			return TO_ERROR | ret;
		}
		
		chunk_sz = MIN(*size - offset, chunk_sz);
	}

	ret = TOSE_get_certificate_x509_final(ctx, challenge, challenge_length, signature);
	if (ret != TORSP_SUCCESS) {
		return TO_ERROR | ret;
	}

	/* adjust the size to the certificate's size just read */
	*size = offset;

	return TO_OK;
}

#endif // TOSE_DRIVER_HSE && !TO_DISABLE_CERTS_HELPER


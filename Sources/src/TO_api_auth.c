/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2017 Trusted Objects. All rights reserved.
 */

/**
 * @file api_auth.c
 * @brief Secure Element authentication functions (signatures, certificates).
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#include "TO_defs.h"
#include "TO_retcodes.h"
#include "TO_log.h"
#include "TO_utils.h"
#include "TO_endian.h"

#include "TODRV_HSE.h"
#include "TODRV_HSE_cfg.h"
#include "TODRV_HSE_cmd.h"
#include "TODRV_HSE_defs.h"
#include "TODRV_HSE_auth.h"
#include "TOH_log.h"

#ifndef TO_DISABLE_CERT_MGMT
#ifndef TO_DISABLE_API_GET_CERTIFICATE_SUBJECT_CN
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_subject_cn(TODRV_HSE_ctx_t *ctx, const uint8_t certificate_index,
		char subject_cn[TO_CERT_SUBJECT_CN_MAXSIZE + 1])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_CERT_SUBJECT_CN_MAXSIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, certificate_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_CERTIFICATE_SUBJECT_CN, 1,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	if (resp_data_len > TO_CERT_SUBJECT_CN_MAXSIZE)
		return TORSP_INVALID_LEN;

	TO_secure_memcpy(subject_cn, TODRV_HSE_response_data, resp_data_len);
	subject_cn[resp_data_len] = '\0';
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_SET_CERTIFICATE_SIGNING_REQUEST_DN
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_set_certificate_signing_request_dn(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const uint8_t csr_dn[TO_CERT_DN_MAXSIZE],
		const uint16_t csr_dn_len
)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, certificate_index);
	ret |= TODRV_HSE_prepare_command_data(1, csr_dn, csr_dn_len);
	if (TO_OK != ret)
		return ret;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SET_CERTIFICATE_SIGNING_REQUEST_DN,
			1 + csr_dn_len, &resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_CERTIFICATE_SIGNING_REQUEST
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_signing_request(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index,
		uint8_t* csr,
		uint16_t* size
)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len;

	(void)ctx;

	resp_data_len = TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE - TODRV_HSE_RSPHEAD_SIZE;
	ret = TODRV_HSE_prepare_command_data_byte(0, certificate_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_CERTIFICATE_SIGNING_REQUEST,
			1, &resp_data_len, &resp_status);
	if ((ret != TO_OK) || (resp_status != TORSP_SUCCESS))
		return ret | resp_status;

	if (csr != NULL) {
		TO_secure_memcpy(csr, TODRV_HSE_response_data, resp_data_len);
	}
	*size = resp_data_len;
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_CERTIFICATE
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate(TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const TO_certificate_format_t format,
		uint8_t* certificate)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len;

	(void)ctx;

	switch (format) {
		case TO_CERTIFICATE_STANDALONE:
			resp_data_len = sizeof(TO_cert_standalone_t);
			break;

		case TO_CERTIFICATE_SHORT:
			resp_data_len = sizeof(TO_cert_short_t);
			break;

		case TO_CERTIFICATE_X509:
			resp_data_len = 1024;
			break;

		case TO_CERTIFICATE_SHORT_V2:
			resp_data_len = sizeof(TO_cert_short_v2_t);
			break;

		default:
			resp_data_len = 0;
			break;
	}

	ret = TODRV_HSE_prepare_command_data_byte(0, certificate_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, format & 0xFF);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_CERTIFICATE, 2,
			&resp_data_len, &resp_status);
	if ((TO_OK != ret) || (TORSP_SUCCESS != resp_status))
		return ret | resp_status;

	TO_secure_memcpy(certificate, TODRV_HSE_response_data, resp_data_len);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_CERTIFICATE_X509
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_x509(TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index,
		uint8_t* certificate,
		uint16_t* size)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len;

	(void)ctx;

	resp_data_len = TODRV_HSE_RSP_MAXSIZE;
	ret = TODRV_HSE_prepare_command_data_byte(0, certificate_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, TOCERTF_X509);
	if (TO_OK != ret) {
		return ret;
	}
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_CERTIFICATE_X509, 2,
			&resp_data_len, &resp_status);
	if ((ret != TO_OK) || (resp_status != TORSP_SUCCESS))
		return ret | resp_status;

	if (certificate != NULL) {
		TO_secure_memcpy(certificate, TODRV_HSE_response_data, resp_data_len);
	}
	TOH_LOG_INF("LENGTH %d %x\n", resp_data_len, resp_status);
	*size = resp_data_len;
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_SET_CERTIFICATE_X509
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_set_certificate_x509(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const uint8_t* certificate,
		const uint16_t size
)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;
	uint16_t len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(len, certificate_index);
	len += 1;
	ret |= TODRV_HSE_prepare_command_data(len, certificate, size);
	len += size;
	if (TO_OK != ret)
		return ret;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SET_CERTIFICATE_X509,
			len, &resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_SET_CERTIFICATE_X509_INIT_UPDATE_FINAL
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_set_certificate_x509_init(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index
)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, certificate_index);
	if (TO_OK != ret)
		return ret;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SET_CERTIFICATE_INIT,
			1, &resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_set_certificate_x509_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* certificate,
		const uint16_t size
)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, certificate, size);
	if (TO_OK != ret)
		return ret;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SET_CERTIFICATE_UPDATE,
			size, &resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_set_certificate_x509_final(
		TODRV_HSE_ctx_t *ctx
)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SET_CERTIFICATE_FINAL,
			0, &resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_CERTIFICATE_AND_SIGN
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_and_sign(TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const TO_certificate_format_t format,
		const uint8_t* challenge,
		const uint16_t challenge_length,
		uint8_t* certificate,
		uint8_t* signature)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = challenge_length + 2;
	uint16_t resp_data_len;

	(void)ctx;

	switch (format) {
		case TO_CERTIFICATE_STANDALONE:
			resp_data_len = sizeof(TO_cert_standalone_t);
			break;

		case TO_CERTIFICATE_SHORT:
			resp_data_len = sizeof(TO_cert_short_t);
			break;

		case TO_CERTIFICATE_X509:
		default:
			break;
	}
	resp_data_len += TO_SIGNATURE_SIZE;

	cmd_len = challenge_length + 2;
	ret = TODRV_HSE_prepare_command_data_byte(0, certificate_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, format & 0xFF);
	ret |= TODRV_HSE_prepare_command_data(2, challenge, challenge_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_CERTIFICATE_AND_SIGN, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(certificate, TODRV_HSE_response_data, resp_data_len - 64);
	TO_secure_memcpy(signature, TODRV_HSE_response_data + (resp_data_len - 64), 64);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_CERTIFICATE_X509_AND_SIGN
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_x509_and_sign(TODRV_HSE_ctx_t *ctx, const uint8_t certificate_index,
		const uint8_t* challenge, const uint16_t challenge_length,
		uint8_t* certificate, uint16_t* size, uint8_t* signature)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = challenge_length + 2;
	uint16_t resp_data_len;

	(void)ctx;

	resp_data_len = TODRV_HSE_RSP_MAXSIZE;
	cmd_len = challenge_length + 2;
	ret = TODRV_HSE_prepare_command_data_byte(0, certificate_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, TOCERTF_X509);
	ret |= TODRV_HSE_prepare_command_data(2, challenge, challenge_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_CERTIFICATE_AND_SIGN, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(certificate, TODRV_HSE_response_data, resp_data_len - 64);
	*size = resp_data_len - TO_SIGNATURE_SIZE;
	TO_secure_memcpy(signature, TODRV_HSE_response_data + (resp_data_len - 64), 64);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_CERTIFICATE_X509_CAPI
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_x509_init(TODRV_HSE_ctx_t *ctx,
		const uint8_t certificate_index)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 2;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, certificate_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, TOCERTF_X509);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_CERTIFICATE_INIT, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_x509_update(TODRV_HSE_ctx_t *ctx,
		uint8_t *certificate, uint16_t *size)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 2;
	uint16_t resp_data_len = *size;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, (resp_data_len >> 8) & 0xff);
	ret |= TODRV_HSE_prepare_command_data_byte(1, resp_data_len & 0xff);
	ret |= TODRV_HSE_send_command(TODRV_HSE_CMD_GET_CERTIFICATE_UPDATE, cmd_len,
			&resp_data_len, &resp_status);
	if ((TO_OK != ret) || (TORSP_SUCCESS != resp_status))
		return ret | resp_status;

	TO_secure_memcpy(certificate, TODRV_HSE_response_data, resp_data_len);
	*size = resp_data_len;
	return resp_status;
}

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_certificate_x509_final(TODRV_HSE_ctx_t *ctx,
		const uint8_t* challenge, const uint16_t challenge_length,
		uint8_t* signature)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 0;
	uint16_t resp_data_len = 0;

	(void)ctx;

	if (challenge_length) {
		resp_data_len = TO_SIGNATURE_SIZE;
		cmd_len = challenge_length;
		ret = TODRV_HSE_prepare_command_data(0, challenge, challenge_length);
		if (TO_OK != ret)
			return ret;
	}
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_CERTIFICATE_FINAL, cmd_len,
			&resp_data_len, &resp_status);
	if ((TO_OK != ret) || (TORSP_SUCCESS != resp_status))
		return ret | resp_status;

	if (challenge_length) {
		TO_secure_memcpy(signature, TODRV_HSE_response_data, TO_SIGNATURE_SIZE);
	}
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_CERTIFICATE_AND_STORE
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_certificate_and_store(TODRV_HSE_ctx_t *ctx, const uint8_t ca_key_id,
		const TO_certificate_format_t format, const uint8_t* certificate)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 2; /* ca_id + format */
	uint16_t cert_size;
	uint16_t resp_data_len = 0;

	(void)ctx;

	switch(format) {
		case TO_CERTIFICATE_STANDALONE:
			cert_size = sizeof(TO_cert_standalone_t);
			break;
		case TO_CERTIFICATE_SHORT:
			cert_size = sizeof(TO_cert_short_t);
			break;
		case TO_CERTIFICATE_SHORT_V2:
			cert_size = sizeof(TO_cert_short_v2_t);
			break;
		case TO_CERTIFICATE_X509: {
			uint8_t len = certificate[1] & 0x7F;
			uint32_t _cert_size = 0;
			TO_secure_memcpy((uint8_t*)(&_cert_size) + sizeof(uint32_t) - len,
					certificate + 2, len);
			cert_size = 2 + len + (uint16_t)be32toh(_cert_size);
			break;
		}
		default:
			cert_size = 0;
			break;
	}
	cmd_len += cert_size;

	ret = TODRV_HSE_prepare_command_data_byte(0, ca_key_id);
	ret |= TODRV_HSE_prepare_command_data_byte(1, format & 0xFF);
	ret |= TODRV_HSE_prepare_command_data(2, certificate, cert_size);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_CERTIFICATE_AND_STORE, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_CA_CERTIFICATE_AND_STORE
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_ca_certificate_and_store(TODRV_HSE_ctx_t *ctx, const uint8_t ca_key_index,
		const uint8_t subca_key_index, const uint8_t *certificate,
		const uint16_t certificate_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 2 + certificate_len;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, ca_key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, subca_key_index);
	ret |= TODRV_HSE_prepare_command_data(2, certificate, certificate_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_CA_CERTIFICATE_AND_STORE, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_CHALLENGE_AND_STORE
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_get_challenge_and_store(TODRV_HSE_ctx_t *ctx, uint8_t challenge[TO_CHALLENGE_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_CHALLENGE_SIZE;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_CHALLENGE_AND_STORE, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(challenge, TODRV_HSE_response_data, TO_CHALLENGE_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_CHALLENGE_SIGNATURE
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_challenge_signature(TODRV_HSE_ctx_t *ctx,
		const uint8_t signature[TO_SIGNATURE_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = TO_SIGNATURE_SIZE;
	uint16_t resp_data_len = 0;

	(void)ctx;

	cmd_len = TO_SIGNATURE_SIZE;
	ret = TODRV_HSE_prepare_command_data(0, signature, TO_SIGNATURE_SIZE);
	if (TO_OK != ret)
		return ret;
	ret =  TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_CHALLENGE_SIGNATURE, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_CHAIN_CERTIFICATE_AND_STORE
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_chain_certificate_and_store_init(TODRV_HSE_ctx_t *ctx,
		const uint8_t ca_key_index)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, ca_key_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_INIT, 1,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_chain_certificate_and_store_update(TODRV_HSE_ctx_t *ctx,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, chain_certificate,
			chain_certificate_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_UPDATE,
			chain_certificate_length, &resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_chain_certificate_and_store_final(TODRV_HSE_ctx_t *ctx)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_FINAL, 0,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_chain_ca_certificate_and_store_init(TODRV_HSE_ctx_t *ctx,
		const uint8_t ca_key_index, const uint8_t subca_key_index)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, ca_key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, subca_key_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_INIT, 2,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_chain_ca_certificate_and_store_update(TODRV_HSE_ctx_t *ctx,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, chain_certificate,
			chain_certificate_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_UPDATE,
			chain_certificate_length, &resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_chain_ca_certificate_and_store_final(TODRV_HSE_ctx_t *ctx)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_FINAL, 0,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif
#endif // TO_DISABLE_CERT_MGMT

#ifndef TO_DISABLE_SIGNING
#ifndef TO_DISABLE_API_SIGN
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_sign(TODRV_HSE_ctx_t *ctx, const uint8_t key_index, const uint8_t* challenge,
		const uint16_t challenge_length, uint8_t* signature)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = challenge_length + 1;
	uint16_t resp_data_len = TO_SIGNATURE_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data(1, challenge, challenge_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SIGN, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(signature, TODRV_HSE_response_data, TO_SIGNATURE_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify(TODRV_HSE_ctx_t *ctx, const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, const uint8_t* signature)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 1 + data_length + TO_SIGNATURE_SIZE;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data(1, data, data_length);
	ret |= TODRV_HSE_prepare_command_data(1 + data_length, signature,
			TO_SIGNATURE_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_SIGN_HASH
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_sign_hash(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t hash[TO_HASH_SIZE], uint8_t* signature)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 1 + TO_HASH_SIZE;
	uint16_t resp_data_len = TO_SIGNATURE_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data(1, hash, TO_HASH_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SIGN_HASH, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(signature, TODRV_HSE_response_data, TO_SIGNATURE_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_HASH_SIGNATURE
TODRV_HSE_AUTH_API TO_ret_t TODRV_HSE_verify_hash_signature(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t hash[TO_HASH_SIZE], const uint8_t* signature)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 1 + TO_HASH_SIZE + TO_SIGNATURE_SIZE;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data(1, hash, TO_HASH_SIZE);
	ret |= TODRV_HSE_prepare_command_data(1 + TO_HASH_SIZE, signature,
			TO_SIGNATURE_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_HASH_SIGNATURE, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif
#endif // TO_DISABLE_SIGNING

#endif /* TODRV_HSE_DRIVER_DISABLE */


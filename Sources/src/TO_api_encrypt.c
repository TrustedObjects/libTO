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
 * @file api_encrypt.c
 * @brief Secure Element encryption and message securisation functions.
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#include "TO_cfg.h"
#include "TO_defs.h"
#include "TO_retcodes.h"
#include "TO_endian.h"
#include "TO_utils.h"

#include "TODRV_HSE.h"
#include "TODRV_HSE_cfg.h"
#include "TODRV_HSE_cmd.h"
#include "TODRV_HSE_defs.h"
#include "TODRV_HSE_encrypt.h"
#include "TOH_log.h"

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define MAC_MAX_SIZE MAX(TO_HMAC_SIZE, TO_CMAC_SIZE)

#ifndef TO_DISABLE_AES_ENCRYPT
#if !defined(TO_DISABLE_API_AES_ENCRYPT) \
	&& !defined(TO_DISABLE_API_AES128CBC_ENCRYPT)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128cbc_encrypt(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = data_length + 1;
	uint16_t resp_data_len = data_length + TO_INITIALVECTOR_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data(1, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_AES128CBC_ENCRYPT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(initial_vector, TODRV_HSE_response_data, TO_INITIALVECTOR_SIZE);
	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data + TO_INITIALVECTOR_SIZE,
			data_length);
	return resp_status;
}
#endif

#if !defined(TO_DISABLE_API_AES_IV_ENCRYPT) \
	&& !defined(TO_DISABLE_API_AES128CBC_IV_ENCRYPT)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128cbc_iv_encrypt(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* data, const uint16_t data_length,
		uint8_t* cryptogram)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 1 + TO_INITIALVECTOR_SIZE + data_length;
	uint16_t resp_data_len = data_length;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data(1, initial_vector,
			TO_INITIALVECTOR_SIZE);
	ret |= TODRV_HSE_prepare_command_data(1 + TO_INITIALVECTOR_SIZE,
			data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_AES128CBC_IV_ENCRYPT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data, data_length);
	return resp_status;
}
#endif

#if !defined(TO_DISABLE_API_AES_DECRYPT) \
	&& !defined(TO_DISABLE_API_AES128CBC_DECRYPT)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128cbc_decrypt(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		uint8_t* data)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = cryptogram_length + TO_INITIALVECTOR_SIZE + 1;
	uint16_t resp_data_len = cryptogram_length;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data(1, initial_vector,
			TO_INITIALVECTOR_SIZE);
	ret |= TODRV_HSE_prepare_command_data(1 + TO_INITIALVECTOR_SIZE,
			cryptogram, cryptogram_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_AES128CBC_DECRYPT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(data, TODRV_HSE_response_data, resp_data_len);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_AES128GCM_ENCRYPT
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128gcm_encrypt(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		const uint8_t* aad, const uint16_t aad_length,
		uint8_t initial_vector[TO_AESGCM_INITIALVECTOR_SIZE],
		uint8_t* cryptogram, uint8_t tag[TO_AESGCM_TAG_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 1 + TO_AESGCM_AAD_LEN_SIZE
		+ data_length + aad_length;
	uint16_t resp_data_len = TO_AESGCM_INITIALVECTOR_SIZE + data_length
		+ TO_AESGCM_TAG_SIZE;
	uint16_t tmp16;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	tmp16 = htobe16(aad_length);
	ret |= TODRV_HSE_prepare_command_data(1, (uint8_t *)&tmp16, sizeof(aad_length));
	ret |= TODRV_HSE_prepare_command_data(1 + sizeof(aad_length),
			data, data_length);
	ret |= TODRV_HSE_prepare_command_data(1 + sizeof(aad_length) + data_length,
			aad, aad_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_AES128GCM_ENCRYPT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(initial_vector, TODRV_HSE_response_data,
			TO_AESGCM_INITIALVECTOR_SIZE);
	TO_secure_memcpy(cryptogram,
			TODRV_HSE_response_data + TO_AESGCM_INITIALVECTOR_SIZE,
			data_length);
	TO_secure_memcpy(tag, TODRV_HSE_response_data + TO_AESGCM_INITIALVECTOR_SIZE
			+ data_length, TO_AESGCM_TAG_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_AES128GCM_DECRYPT
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128gcm_decrypt(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t initial_vector[TO_AESGCM_INITIALVECTOR_SIZE],
		const uint8_t* aad, const uint16_t aad_length,
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		const uint8_t tag[TO_AESGCM_TAG_SIZE], uint8_t* data)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 1 + TO_AESGCM_AAD_LEN_SIZE
		+ TO_AESGCM_INITIALVECTOR_SIZE + cryptogram_length + aad_length
		+ TO_AESGCM_TAG_SIZE;
	uint16_t resp_data_len = cryptogram_length;
	uint16_t tmp16;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	tmp16 = htobe16(aad_length);
	ret |= TODRV_HSE_prepare_command_data(1, (uint8_t *)&tmp16, sizeof(aad_length));
	ret |= TODRV_HSE_prepare_command_data(1 + sizeof(aad_length),
			initial_vector, TO_AESGCM_INITIALVECTOR_SIZE);
	ret |= TODRV_HSE_prepare_command_data(1 + sizeof(aad_length)
			+ TO_AESGCM_INITIALVECTOR_SIZE,
			cryptogram, cryptogram_length);
	ret |= TODRV_HSE_prepare_command_data(1 + sizeof(aad_length)
			+ TO_AESGCM_INITIALVECTOR_SIZE + cryptogram_length,
			aad, aad_length);
	ret |= TODRV_HSE_prepare_command_data(1 + sizeof(aad_length)
			+ TO_AESGCM_INITIALVECTOR_SIZE + cryptogram_length
			+ aad_length, tag, TO_AESGCM_TAG_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_AES128GCM_DECRYPT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	TO_secure_memcpy(data, TODRV_HSE_response_data, resp_data_len);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_AES128CCM_ENCRYPT
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128ccm_encrypt(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		const uint8_t* aad, const uint16_t aad_length,
		uint8_t nonce[TO_AESCCM_NONCE_SIZE],
		uint8_t* cryptogram, uint8_t tag[TO_AESCCM_TAG_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 1 + TO_AESCCM_AAD_LEN_SIZE
		+ data_length + aad_length;
	uint16_t resp_data_len = TO_AESCCM_NONCE_SIZE + data_length
		+ TO_AESCCM_TAG_SIZE;
	uint16_t tmp16;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	tmp16 = htobe16(aad_length);
	ret |= TODRV_HSE_prepare_command_data(1, (uint8_t *)&tmp16, sizeof(aad_length));
	ret |= TODRV_HSE_prepare_command_data(1 + sizeof(aad_length),
			data, data_length);
	ret |= TODRV_HSE_prepare_command_data(1 + sizeof(aad_length) + data_length,
			aad, aad_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_AES128CCM_ENCRYPT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(nonce, TODRV_HSE_response_data, TO_AESCCM_NONCE_SIZE);
	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data + TO_AESCCM_NONCE_SIZE,
			data_length);
	TO_secure_memcpy(tag, TODRV_HSE_response_data + TO_AESCCM_NONCE_SIZE + data_length,
			TO_AESCCM_TAG_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_AES128CCM_DECRYPT
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128ccm_decrypt(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t nonce[TO_AESCCM_NONCE_SIZE],
		const uint8_t* aad, const uint16_t aad_length,
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		const uint8_t tag[TO_AESCCM_TAG_SIZE], uint8_t* data)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 1 + TO_AESCCM_AAD_LEN_SIZE
		+ TO_AESCCM_NONCE_SIZE + cryptogram_length + aad_length
		+ TO_AESCCM_TAG_SIZE;
	uint16_t resp_data_len = cryptogram_length;
	uint16_t tmp16;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	tmp16 = htobe16(aad_length);
	ret |= TODRV_HSE_prepare_command_data(1, (uint8_t *)&tmp16, sizeof(aad_length));
	ret |= TODRV_HSE_prepare_command_data(1 + sizeof(aad_length),
			nonce, TO_AESCCM_NONCE_SIZE);
	ret |= TODRV_HSE_prepare_command_data(1 + sizeof(aad_length)
			+ TO_AESCCM_NONCE_SIZE,
			cryptogram, cryptogram_length);
	ret |= TODRV_HSE_prepare_command_data(1 + sizeof(aad_length)
			+ TO_AESCCM_NONCE_SIZE + cryptogram_length,
			tag, TO_AESCCM_TAG_SIZE);
	ret |= TODRV_HSE_prepare_command_data(1 + sizeof(aad_length)
			+ TO_AESCCM_NONCE_SIZE + cryptogram_length
			+ TO_AESCCM_TAG_SIZE, aad, aad_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_AES128CCM_DECRYPT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	TO_secure_memcpy(data, TODRV_HSE_response_data, resp_data_len);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_AES128ECB_ENCRYPT
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128ecb_encrypt(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t* data, const uint16_t data_length,
		uint8_t* cryptogram)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = data_length + 1;
	uint16_t resp_data_len = data_length;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data(1, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_AES128ECB_ENCRYPT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data, data_length);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_AES128ECB_DECRYPT
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128ecb_decrypt(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		uint8_t* data)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = cryptogram_length + 1;
	uint16_t resp_data_len = cryptogram_length;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data(1, cryptogram, cryptogram_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_AES128ECB_DECRYPT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(data, TODRV_HSE_response_data, resp_data_len);
	return resp_status;
}
#endif
#endif // TO_DISABLE_AES_ENCRYPT

#ifndef TO_DISABLE_SEC_MSG
#if !defined(TO_DISABLE_API_AES128CBC_HMAC_SECURE_MESSAGE)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128cbc_hmac_secure_message(TODRV_HSE_ctx_t *ctx, const uint8_t aes_key_index,
		const uint8_t hmac_key_index,
		const uint8_t* data, const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram, uint8_t hmac[TO_HMAC_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = data_length + 2;
	uint16_t resp_data_len = data_length + TO_INITIALVECTOR_SIZE
		+ TO_HMAC_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, aes_key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, hmac_key_index);
	ret |= TODRV_HSE_prepare_command_data(2, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_AES128CBC_HMAC_SECURE_MESSAGE, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(initial_vector, TODRV_HSE_response_data, TO_INITIALVECTOR_SIZE);
	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data + TO_INITIALVECTOR_SIZE,
			data_length);
	TO_secure_memcpy(hmac, TODRV_HSE_response_data + TO_INITIALVECTOR_SIZE
			+ data_length, TO_HMAC_SIZE);
	return resp_status;
}
#endif

#if !defined(TO_DISABLE_API_AES128CBC_HMAC_UNSECURE_MESSAGE)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128cbc_hmac_unsecure_message(TODRV_HSE_ctx_t *ctx, const uint8_t aes_key_index,
		const uint8_t hmac_key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		const uint8_t hmac[TO_HMAC_SIZE],
		uint8_t* data)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 2 + TO_INITIALVECTOR_SIZE + cryptogram_length +
		TO_HMAC_SIZE;
	uint16_t resp_data_len = cryptogram_length;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, aes_key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, hmac_key_index);
	ret |= TODRV_HSE_prepare_command_data(2, initial_vector,
			TO_INITIALVECTOR_SIZE);
	ret |= TODRV_HSE_prepare_command_data(2 + TO_INITIALVECTOR_SIZE,
			cryptogram, cryptogram_length);
	ret |= TODRV_HSE_prepare_command_data(2 + TO_INITIALVECTOR_SIZE
			+ cryptogram_length, hmac, TO_HMAC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_AES128CBC_HMAC_UNSECURE_MESSAGE, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(data, TODRV_HSE_response_data, cryptogram_length);
	return resp_status;
}
#endif

#if !defined(TO_DISABLE_API_AES128CBC_CMAC_SECURE_MESSAGE)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128cbc_cmac_secure_message(TODRV_HSE_ctx_t *ctx, const uint8_t aes_key_index,
		const uint8_t cmac_key_index,
		const uint8_t* data, const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram, uint8_t cmac[TO_CMAC_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = data_length + 2;
	uint16_t resp_data_len = data_length + TO_INITIALVECTOR_SIZE
		+ TO_CMAC_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, aes_key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, cmac_key_index);
	ret |= TODRV_HSE_prepare_command_data(2, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_AES128CBC_CMAC_SECURE_MESSAGE, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(initial_vector, TODRV_HSE_response_data, TO_INITIALVECTOR_SIZE);
	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data + TO_INITIALVECTOR_SIZE,
			data_length);
	TO_secure_memcpy(cmac, TODRV_HSE_response_data + TO_INITIALVECTOR_SIZE
			+ data_length, TO_CMAC_SIZE);
	return resp_status;
}
#endif

#if !defined(TO_DISABLE_API_AES128CBC_CMAC_UNSECURE_MESSAGE)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_aes128cbc_cmac_unsecure_message(TODRV_HSE_ctx_t *ctx, const uint8_t aes_key_index,
		const uint8_t cmac_key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_length,
		const uint8_t cmac[TO_CMAC_SIZE],
		uint8_t* data)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 2 + TO_INITIALVECTOR_SIZE + cryptogram_length +
		TO_CMAC_SIZE;
	uint16_t resp_data_len = cryptogram_length;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, aes_key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, cmac_key_index);
	ret |= TODRV_HSE_prepare_command_data(2, initial_vector,
			TO_INITIALVECTOR_SIZE);
	ret |= TODRV_HSE_prepare_command_data(2 + TO_INITIALVECTOR_SIZE,
			cryptogram, cryptogram_length);
	ret |= TODRV_HSE_prepare_command_data(2 + TO_INITIALVECTOR_SIZE
			+ cryptogram_length, cmac, TO_CMAC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_AES128CBC_CMAC_UNSECURE_MESSAGE, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(data, TODRV_HSE_response_data, cryptogram_length);
	return resp_status;
}
#endif

#if !defined(TO_DISABLE_API_SECURE_MESSAGE)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_message(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const TO_enc_alg_t enc_alg, const TO_mac_alg_t mac_alg,
		const uint8_t* data, const uint16_t data_len,
		uint8_t sequence[TO_SEQUENCE_SIZE],
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram, uint16_t* cryptogram_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 3 + data_len;
	uint16_t resp_data_len = TO_PAYLOAD_SECURED_PAYLOAD_SIZE(enc_alg, mac_alg,
	                                                         data_len);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, enc_alg);
	ret |= TODRV_HSE_prepare_command_data_byte(2, mac_alg);
	ret |= TODRV_HSE_prepare_command_data(3, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SECURE_MESSAGE, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(sequence, TODRV_HSE_response_data, TO_SEQUENCE_SIZE);
	TO_secure_memcpy(initial_vector, TODRV_HSE_response_data + TO_SEQUENCE_SIZE,
			TO_INITIALVECTOR_SIZE);
	*cryptogram_len = resp_data_len - TO_INITIALVECTOR_SIZE - TO_SEQUENCE_SIZE;
	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data + TO_SEQUENCE_SIZE
			+ TO_INITIALVECTOR_SIZE, *cryptogram_len);
	return resp_status;
}
#endif

#if !defined(TO_DISABLE_API_SECURE_MESSAGE_INIT_UPDATE_FINAL)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_message_init(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const TO_enc_alg_t enc_alg, const TO_mac_alg_t mac_alg,
		uint8_t sequence[TO_SEQUENCE_SIZE],
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_SEQUENCE_SIZE + TO_INITIALVECTOR_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, enc_alg);
	ret |= TODRV_HSE_prepare_command_data_byte(2, mac_alg);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SECURE_MESSAGE_INIT, 3,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(sequence, TODRV_HSE_response_data, TO_SEQUENCE_SIZE);
	TO_secure_memcpy(initial_vector, TODRV_HSE_response_data + TO_SEQUENCE_SIZE,
			TO_INITIALVECTOR_SIZE);
	return resp_status;
}

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_message_update(TODRV_HSE_ctx_t *ctx, const uint8_t* data,
		const uint16_t data_len, uint8_t* cryptogram)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = data_len;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SECURE_MESSAGE_UPDATE, data_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data, data_len);
	return resp_status;
}

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_message_final(TODRV_HSE_ctx_t *ctx, const uint8_t* data, const uint16_t data_len,
		uint8_t* cryptogram, uint16_t* cryptogram_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = data_len + TO_AES_BLOCK_SIZE + MAC_MAX_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SECURE_MESSAGE_FINAL, data_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*cryptogram_len = resp_data_len;
	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data, *cryptogram_len);
	return resp_status;
}
#endif

#if !defined(TO_DISABLE_API_UNSECURE_MESSAGE)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_message(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const TO_enc_alg_t enc_alg, const TO_mac_alg_t mac_alg,
		const uint8_t sequence[TO_SEQUENCE_SIZE],
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_len,
		uint8_t* data, uint16_t* data_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 0;
	uint16_t resp_data_len = cryptogram_len -
	                         TO_PAYLOAD_MAC_SIZE(enc_alg, mac_alg) - 1;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(cmd_len++, key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(cmd_len++, enc_alg);
	ret |= TODRV_HSE_prepare_command_data_byte(cmd_len++, mac_alg);
	ret |= TODRV_HSE_prepare_command_data(cmd_len, sequence, TO_SEQUENCE_SIZE);
	cmd_len += TO_SEQUENCE_SIZE;
	ret |= TODRV_HSE_prepare_command_data(cmd_len, initial_vector,
	                               TO_INITIALVECTOR_SIZE);
	cmd_len += TO_INITIALVECTOR_SIZE;
	ret |= TODRV_HSE_prepare_command_data(cmd_len, cryptogram, cryptogram_len);
	cmd_len += cryptogram_len;
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_UNSECURE_MESSAGE, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*data_len = resp_data_len;
	TO_secure_memcpy(data, TODRV_HSE_response_data, *data_len);
	return resp_status;
}
#endif

#if !defined(TO_DISABLE_API_UNSECURE_MESSAGE_INIT_UPDATE_FINAL)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_message_init(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const TO_enc_alg_t enc_alg, const TO_mac_alg_t mac_alg,
		const uint16_t cryptogram_len, const uint8_t sequence[TO_SEQUENCE_SIZE],
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;
	uint16_t cmd_len = 0;
	uint16_t _cryptogram_len = htobe16(cryptogram_len);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(cmd_len++, key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(cmd_len++, enc_alg);
	ret |= TODRV_HSE_prepare_command_data_byte(cmd_len++, mac_alg);
	ret |= TODRV_HSE_prepare_command_data(cmd_len, (uint8_t*)&_cryptogram_len,
	                               sizeof(uint16_t));
	cmd_len += sizeof(uint16_t);
	ret |= TODRV_HSE_prepare_command_data(cmd_len, sequence, TO_SEQUENCE_SIZE);
	cmd_len += TO_SEQUENCE_SIZE;
	ret |= TODRV_HSE_prepare_command_data(cmd_len, initial_vector,
	                               TO_INITIALVECTOR_SIZE);
	cmd_len += TO_INITIALVECTOR_SIZE;
	ret |= TODRV_HSE_prepare_command_data(cmd_len, last_block_iv,
	                               TO_INITIALVECTOR_SIZE);
	cmd_len += TO_INITIALVECTOR_SIZE;
	ret |= TODRV_HSE_prepare_command_data(cmd_len, last_block, TO_AES_BLOCK_SIZE);
	cmd_len += TO_AES_BLOCK_SIZE;
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_UNSECURE_MESSAGE_INIT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_message_update(TODRV_HSE_ctx_t *ctx, const uint8_t* cryptogram,
		const uint16_t cryptogram_len, uint8_t* data, uint16_t* data_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = cryptogram_len;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, cryptogram, cryptogram_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_UNSECURE_MESSAGE_UPDATE, cryptogram_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*data_len = resp_data_len;
	TO_secure_memcpy(data, TODRV_HSE_response_data, *data_len);
	return resp_status;
}

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_message_final(TODRV_HSE_ctx_t *ctx)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_UNSECURE_MESSAGE_FINAL, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}
#endif

#if !defined(TO_DISABLE_API_SECURE_PAYLOAD)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_payload(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const TO_enc_alg_t enc_alg, const TO_mac_alg_t mac_alg,
		const uint8_t* data, const uint16_t data_len,
		uint8_t* payload, uint16_t* payload_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 3 + data_len;
	uint16_t resp_data_len = TO_PAYLOAD_SECURED_PAYLOAD_SIZE(enc_alg, mac_alg,
	                                                         data_len);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, enc_alg);
	ret |= TODRV_HSE_prepare_command_data_byte(2, mac_alg);
	ret |= TODRV_HSE_prepare_command_data(3, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SECURE_MESSAGE, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*payload_len = resp_data_len;
	TO_secure_memcpy(payload, TODRV_HSE_response_data, *payload_len);
	return resp_status;
}
#endif

#if !defined(TO_DISABLE_API_SECURE_PAYLOAD_INIT_UPDATE_FINAL)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_payload_init(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const TO_enc_alg_t enc_alg, const TO_mac_alg_t mac_alg,
		const uint16_t data_len, uint8_t sequence[TO_SEQUENCE_SIZE],
		uint8_t *iv, uint16_t *iv_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 3 * sizeof(uint8_t);
	uint16_t resp_data_len = TO_SEQUENCE_SIZE + TO_PAYLOAD_IV_SIZE(enc_alg);
	uint16_t _data_len = htobe16(data_len);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, enc_alg);
	ret |= TODRV_HSE_prepare_command_data_byte(2, mac_alg);

	*iv_len = TO_PAYLOAD_IV_SIZE(enc_alg);

	switch (enc_alg) {
		case TO_ENC_ALG_AES128CBC:
			break;
		default:
			ret |= TODRV_HSE_prepare_command_data(cmd_len, (uint8_t*)&_data_len, sizeof(uint16_t));
			cmd_len += sizeof(uint16_t);
			break;
	}

	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SECURE_MESSAGE_INIT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(sequence, TODRV_HSE_response_data, TO_SEQUENCE_SIZE);
	TO_secure_memcpy(iv, TODRV_HSE_response_data + TO_SEQUENCE_SIZE, *iv_len);
	return resp_status;
}

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_payload_update(TODRV_HSE_ctx_t *ctx, const uint8_t* data,
		const uint16_t data_len, uint8_t* cryptogram)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = data_len;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SECURE_MESSAGE_UPDATE, data_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data, data_len);
	return resp_status;
}

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_secure_payload_final(TODRV_HSE_ctx_t *ctx, const uint8_t* data, const uint16_t data_len,
		uint8_t* cryptogram, uint16_t* cryptogram_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = data_len + TO_AES_BLOCK_SIZE + MAC_MAX_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SECURE_MESSAGE_FINAL, data_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*cryptogram_len = resp_data_len;
	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data, *cryptogram_len);
	return resp_status;
}
#endif

#if !defined(TO_DISABLE_API_UNSECURE_PAYLOAD)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_payload(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const TO_enc_alg_t enc_alg, const TO_mac_alg_t mac_alg,
		const uint8_t* payload, const uint16_t payload_len,
		uint8_t* data, uint16_t* data_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 0;
	uint16_t resp_data_len = TO_PAYLOAD_CLEAR_DATA_SIZE(enc_alg, mac_alg,
	                                                    payload_len);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(cmd_len++, key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(cmd_len++, enc_alg);
	ret |= TODRV_HSE_prepare_command_data_byte(cmd_len++, mac_alg);
	ret |= TODRV_HSE_prepare_command_data(cmd_len, payload, payload_len);
	cmd_len += payload_len;
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_UNSECURE_MESSAGE, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*data_len = resp_data_len;
	TO_secure_memcpy(data, TODRV_HSE_response_data, *data_len);
	return resp_status;
}
#endif

#if !defined(TO_DISABLE_API_UNSECURE_PAYLOAD_INIT_UPDATE_FINAL)
TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_payload_init_cbc(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const TO_enc_alg_t enc_alg, const TO_mac_alg_t mac_alg,
		const uint16_t cryptogram_len, const uint8_t sequence[TO_SEQUENCE_SIZE],
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;
	uint16_t cmd_len = 0;
	uint16_t _cryptogram_len = htobe16(cryptogram_len);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(cmd_len++, key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(cmd_len++, enc_alg);
	ret |= TODRV_HSE_prepare_command_data_byte(cmd_len++, mac_alg);
	ret |= TODRV_HSE_prepare_command_data(cmd_len, (uint8_t*)&_cryptogram_len,
	                               sizeof(uint16_t));
	cmd_len += sizeof(uint16_t);
	ret |= TODRV_HSE_prepare_command_data(cmd_len, sequence, TO_SEQUENCE_SIZE);
	cmd_len += TO_SEQUENCE_SIZE;
	ret |= TODRV_HSE_prepare_command_data(cmd_len, initial_vector,
	                               TO_INITIALVECTOR_SIZE);
	cmd_len += TO_INITIALVECTOR_SIZE;
	ret |= TODRV_HSE_prepare_command_data(cmd_len, last_block_iv,
	                               TO_INITIALVECTOR_SIZE);
	cmd_len += TO_INITIALVECTOR_SIZE;
	ret |= TODRV_HSE_prepare_command_data(cmd_len, last_block, TO_AES_BLOCK_SIZE);
	cmd_len += TO_AES_BLOCK_SIZE;
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_UNSECURE_MESSAGE_INIT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_payload_init_aead(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const TO_enc_alg_t enc_alg, const TO_mac_alg_t mac_alg,
		const uint16_t cryptogram_len, const uint8_t sequence[TO_SEQUENCE_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;
	uint16_t cmd_len = 0;
	uint16_t _cryptogram_len = htobe16(cryptogram_len);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(cmd_len++, key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(cmd_len++, enc_alg);
	ret |= TODRV_HSE_prepare_command_data_byte(cmd_len++, mac_alg);
	ret |= TODRV_HSE_prepare_command_data(cmd_len, (uint8_t*)&_cryptogram_len,
	                               sizeof(uint16_t));
	cmd_len += sizeof(uint16_t);
	ret |= TODRV_HSE_prepare_command_data(cmd_len, sequence, TO_SEQUENCE_SIZE);
	cmd_len += TO_SEQUENCE_SIZE;
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_UNSECURE_MESSAGE_INIT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_payload_update(TODRV_HSE_ctx_t *ctx, const uint8_t* cryptogram,
		const uint16_t cryptogram_len, uint8_t* data, uint16_t* data_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = cryptogram_len;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, cryptogram, cryptogram_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_UNSECURE_MESSAGE_UPDATE, cryptogram_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*data_len = resp_data_len;
	TO_secure_memcpy(data, TODRV_HSE_response_data, *data_len);
	return resp_status;
}

TODRV_HSE_ENCRYPT_API TO_ret_t TODRV_HSE_unsecure_payload_final(TODRV_HSE_ctx_t *ctx)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_UNSECURE_MESSAGE_FINAL, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}
#endif

#endif // TO_DISABLE_SEC_MSG

#endif /* TODRV_HSE_DRIVER_DISABLE */


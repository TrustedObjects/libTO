/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2021 Trusted Objects. All rights reserved.
 */

/**
 * @file api_measure.c
 * @brief Secure Element APIs for measure boot.
 */

#include "TO_cfg.h"
#include "TO_defs.h"
#include "TO_retcodes.h"
#include "TO_endian.h"
#include "TO_utils.h"

#include "TODRV_HSE.h"
#include "TODRV_HSE_cfg.h"
#include "TODRV_HSE_cmd.h"
#include "TODRV_HSE_defs.h"
#include "TODRV_HSE_measure.h"
#include "TOH_log.h"

#ifndef TO_DISABLE_MEASURE

TODRV_HSE_MEASURE_API TO_ret_t TODRV_HSE_measured_boot(TODRV_HSE_ctx_t *ctx,
		const uint8_t *hash, uint16_t hash_length)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	if (hash_length > TO_SHA256_HASHSIZE)
		return TO_INVALID_PARAM;
	ret = TODRV_HSE_prepare_command_data(0, hash, hash_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SET_MEASURE_BOOT,
			hash_length, &resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_MEASURE_API TO_ret_t TODRV_HSE_validate_new_fw_hash(TODRV_HSE_ctx_t *ctx,
		const uint8_t *hash, uint16_t hash_length)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	if (hash_length > TO_SHA256_HASHSIZE)
		return TO_INVALID_PARAM;
	ret = TODRV_HSE_prepare_command_data(0, hash, hash_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VALIDATE_NEW_FW_HASH,
			hash_length, &resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_MEASURE_API TO_ret_t TODRV_HSE_commit_new_fw_hash(TODRV_HSE_ctx_t *ctx,
		const uint8_t signed_challenge[TO_HMAC_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, signed_challenge, TO_HMAC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_COMMIT_NEW_FW_HASH,
			TO_HMAC_SIZE, &resp_data_len, &resp_status);

	return ret | resp_status;

}

TODRV_HSE_MEASURE_API TO_ret_t TODRV_HSE_store_new_trusted_fw_hash(TODRV_HSE_ctx_t *ctx,
		const uint8_t* fw_hash, const uint16_t fw_hash_length,
		const uint8_t  mac[TO_HMAC_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	if (fw_hash_length > TO_SHA256_HASHSIZE)
		return TO_INVALID_PARAM;
	ret = TODRV_HSE_prepare_command_data(0, fw_hash, fw_hash_length);
	ret |= TODRV_HSE_prepare_command_data(fw_hash_length,
			mac, TO_HMAC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_STORE_NEW_TRUSTED_FW_HASH,
			fw_hash_length+TO_HMAC_SIZE,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}


TODRV_HSE_MEASURE_API TO_ret_t TODRV_HSE_get_boot_measurement(TODRV_HSE_ctx_t *ctx,
		uint8_t* fw_hash, uint16_t fw_hash_length,
		const uint8_t* challenge, uint16_t challenge_length,
		measure_outcome_t* outcome, uint8_t mac[TO_HMAC_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 1 + TO_SHA256_HASHSIZE + TO_HMAC_SIZE;

	(void)ctx;

	if (fw_hash_length != TO_SHA256_HASHSIZE)
		return TO_INVALID_PARAM;
	if (challenge_length != TO_SHA256_HASHSIZE)
		return TO_INVALID_PARAM;
	ret = TODRV_HSE_prepare_command_data(0, challenge, challenge_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_BOOT_MEASUREMENT,
			challenge_length, &resp_data_len, &resp_status);

	if (TO_OK != ret || TORSP_SUCCESS != resp_status )
		return ret | resp_status;
	*outcome = TODRV_HSE_response_data[0];
	TO_secure_memcpy(fw_hash, &TODRV_HSE_response_data[1], fw_hash_length);
	TO_secure_memcpy(mac, &TODRV_HSE_response_data[1 + TO_SHA256_HASHSIZE],
			TO_HMAC_SIZE);

	return resp_status;
}

TODRV_HSE_MEASURE_API TO_ret_t TODRV_HSE_get_se_measurement(TODRV_HSE_ctx_t *ctx,
		uint8_t* hash, uint16_t hash_length,
		const uint8_t* challenge, uint16_t challenge_length,
		measure_outcome_t* outcome, uint8_t mac[TO_HMAC_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 1 + TO_SHA256_HASHSIZE + TO_HMAC_SIZE;

	(void)ctx;

	if (hash_length != TO_SHA256_HASHSIZE)
		return TO_INVALID_PARAM;
	if (challenge_length != TO_SHA256_HASHSIZE)
		return TO_INVALID_PARAM;
	ret = TODRV_HSE_prepare_command_data(0, challenge, challenge_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_SE_MEASUREMENT,
			challenge_length, &resp_data_len, &resp_status);

	if (TO_OK != ret || TORSP_SUCCESS != resp_status )
		return ret | resp_status;
	*outcome = TODRV_HSE_response_data[0];
	TO_secure_memcpy(hash, &TODRV_HSE_response_data[1], hash_length);
	TO_secure_memcpy(mac, &TODRV_HSE_response_data[1 + TO_SHA256_HASHSIZE],
			TO_HMAC_SIZE);

	return resp_status;
}

TODRV_HSE_MEASURE_API TO_ret_t TODRV_HSE_invalidate_new_hash(TODRV_HSE_ctx_t *ctx,
		const uint8_t password_challenge_hash[TO_SHA256_HASHSIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, password_challenge_hash,
			TO_SHA256_HASHSIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_INVALIDATE_NEW_HASH,
			TO_SHA256_HASHSIZE, &resp_data_len, &resp_status);

	return ret | resp_status;
}

#endif // TO_DISABLE_MEASURE

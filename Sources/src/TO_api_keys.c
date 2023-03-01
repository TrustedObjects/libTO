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
 * @file api_keys.c
 * @brief Secure Element keys management functions.
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#include "TO_defs.h"
#include "TO_retcodes.h"
#include "TO_utils.h"

#include "TODRV_HSE.h"
#include "TODRV_HSE_cfg.h"
#include "TODRV_HSE_cmd.h"
#include "TODRV_HSE_defs.h"
#include "TODRV_HSE_keys.h"
#include "TOH_log.h"

#ifndef TO_DISABLE_KEYS_MGMT
#ifndef TO_DISABLE_API_SET_REMOTE_PUBLIC_KEY
TODRV_HSE_KEYS_API TO_ret_t TODRV_HSE_set_remote_public_key(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t public_key[TO_ECC_PUB_KEYSIZE],
		const uint8_t signature[TO_SIGNATURE_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = 1 + TO_ECC_PUB_KEYSIZE + TO_SIGNATURE_SIZE;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data(1, public_key, TO_ECC_PUB_KEYSIZE);
	ret |= TODRV_HSE_prepare_command_data(1 + TO_ECC_PUB_KEYSIZE, signature,
			TO_SIGNATURE_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SET_REMOTE_PUBLIC_KEY, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_RENEW_ECC_KEYS
TODRV_HSE_KEYS_API TO_ret_t TODRV_HSE_renew_ecc_keys(TODRV_HSE_ctx_t *ctx, const uint8_t key_index)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_RENEW_ECC_KEYS, 1,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_PUBLIC_KEY
TODRV_HSE_KEYS_API TO_ret_t TODRV_HSE_get_public_key(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		uint8_t public_key[TO_ECC_PUB_KEYSIZE],
		uint8_t signature[TO_SIGNATURE_SIZE])
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = TO_ECC_PUB_KEYSIZE + TO_SIGNATURE_SIZE;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_PUBLIC_KEY, 1,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(public_key, TODRV_HSE_response_data, TO_ECC_PUB_KEYSIZE);
	TO_secure_memcpy(signature, TODRV_HSE_response_data + TO_ECC_PUB_KEYSIZE,
			TO_SIGNATURE_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_UNSIGNED_PUBLIC_KEY
TODRV_HSE_KEYS_API TO_ret_t TODRV_HSE_get_unsigned_public_key(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		uint8_t public_key[TO_ECC_PUB_KEYSIZE])
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = TO_ECC_PUB_KEYSIZE;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_UNSIGNED_PUBLIC_KEY, 1,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(public_key, TODRV_HSE_response_data, TO_ECC_PUB_KEYSIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_RENEW_SHARED_KEYS
TODRV_HSE_KEYS_API TO_ret_t TODRV_HSE_renew_shared_keys(TODRV_HSE_ctx_t *ctx, const uint8_t key_index,
		const uint8_t public_key_index)
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = 0;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data_byte(1, public_key_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_RENEW_SHARED_KEYS, 2,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif
#endif // TO_DISABLE_KEYS_MGMT

#ifndef TO_DISABLE_FINGERPRINT
#ifndef TO_DISABLE_API_GET_KEY_FINGERPRINT
TODRV_HSE_KEYS_API TO_ret_t TODRV_HSE_get_key_fingerprint(TODRV_HSE_ctx_t *ctx, TO_key_type_t key_type,
		uint8_t key_index,
		uint8_t* fingerprint[TO_KEY_FINGERPRINT_SIZE])
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = TO_KEY_FINGERPRINT_SIZE;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_type);
	ret |= TODRV_HSE_prepare_command_data_byte(1, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_KEY_FINGERPRINT, 2,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(fingerprint, TODRV_HSE_response_data, TO_KEY_FINGERPRINT_SIZE);
	return resp_status;
}
#endif
#endif // TO_DISABLE_FINGERPRINT

#endif /* TODRV_HSE_DRIVER_DISABLE */


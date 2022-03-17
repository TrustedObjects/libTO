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
 * @file api_mac.c
 * @brief Secure Element MAC (Message Authentication Code) functions.
 */

#include "TO_cfg.h"
#include "TO_defs.h"
#include "TO_retcodes.h"
#include "TO_utils.h"

#include "TODRV_HSE.h"
#include "TODRV_HSE_cfg.h"
#include "TODRV_HSE_cmd.h"
#include "TODRV_HSE_defs.h"
#include "TODRV_HSE_mac.h"
#include "TOH_log.h"

#ifndef TO_DISABLE_HMAC
#ifndef TO_DISABLE_API_COMPUTE_HMAC
TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_compute_hmac(TODRV_HSE_ctx_t *ctx, const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, uint8_t hmac_data[32])
{
	TO_lib_ret_t ret;
	uint16_t cmd_len = data_length + 1;
	uint16_t resp_data_len = TO_HMAC_SIZE;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data(1, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_COMPUTE_HMAC, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(hmac_data, TODRV_HSE_response_data, TO_HMAC_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_COMPUTE_HMAC_INIT_UPDATE_FINAL
TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_compute_hmac_init(TODRV_HSE_ctx_t *ctx, uint8_t key_index)
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = 0;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_COMPUTE_HMAC_INIT, 1,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_compute_hmac_update(TODRV_HSE_ctx_t *ctx, const uint8_t* data, uint16_t length)
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = 0;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_COMPUTE_HMAC_UPDATE, length,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_compute_hmac_final(TODRV_HSE_ctx_t *ctx, uint8_t hmac[TO_HMAC_SIZE])
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = TO_HMAC_SIZE;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_COMPUTE_HMAC_FINAL, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(hmac, TODRV_HSE_response_data, TO_HMAC_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_HMAC
TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_verify_hmac(TODRV_HSE_ctx_t *ctx, const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, const uint8_t hmac_data[32])
{
	TO_lib_ret_t ret;
	uint16_t cmd_len = data_length + TO_HMAC_SIZE + 1;
	uint16_t resp_data_len = 0;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data(1, data, data_length);
	ret |= TODRV_HSE_prepare_command_data(data_length + 1, hmac_data,
			TO_HMAC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_HMAC, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_HMAC_INIT_UPDATE_FINAL
TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_verify_hmac_init(TODRV_HSE_ctx_t *ctx, uint8_t key_index)
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = 0;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_HMAC_INIT, 1,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_verify_hmac_update(TODRV_HSE_ctx_t *ctx, const uint8_t* data, uint16_t length)
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = 0;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_HMAC_UPDATE, length,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_verify_hmac_final(TODRV_HSE_ctx_t *ctx, const uint8_t hmac[TO_HMAC_SIZE])
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = 0;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, hmac, TO_HMAC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_HMAC_FINAL, TO_HMAC_SIZE,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif
#endif // TO_DISABLE_HMAC

#ifndef TO_DISABLE_CMAC
#ifndef TO_DISABLE_API_COMPUTE_CMAC
TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_compute_cmac(TODRV_HSE_ctx_t *ctx, const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, uint8_t cmac_data[TO_CMAC_SIZE])
{
	TO_lib_ret_t ret;
	uint16_t cmd_len = data_length + 1;
	uint16_t resp_data_len = TO_CMAC_SIZE;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data(1, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_COMPUTE_CMAC, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(cmac_data, TODRV_HSE_response_data, TO_CMAC_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_VERIFY_CMAC
TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_verify_cmac(TODRV_HSE_ctx_t *ctx, const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, uint8_t cmac_data[TO_CMAC_SIZE])
{
	TO_lib_ret_t ret;
	uint16_t cmd_len = data_length + TO_CMAC_SIZE + 1;
	uint16_t resp_data_len = 0;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	ret |= TODRV_HSE_prepare_command_data(1, data, data_length);
	ret |= TODRV_HSE_prepare_command_data(data_length + 1, cmac_data,
			TO_CMAC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_VERIFY_CMAC, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif
#endif // TO_DISABLE_CMAC


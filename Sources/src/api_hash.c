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
 * @file api_hash.c
 * @brief Secure Element hash computation functions.
 */

#include "TO_cfg.h"
#include "TO_defs.h"
#include "TO_retcodes.h"
#include "TO_utils.h"

#include "TODRV_HSE.h"
#include "TODRV_HSE_cfg.h"
#include "TODRV_HSE_cmd.h"
#include "TODRV_HSE_defs.h"
#include "TODRV_HSE_hash.h"
#include "TOH_log.h"

#ifndef TO_DISABLE_SHA256
#ifndef TO_DISABLE_API_SHA256
TODRV_HSE_HASH_API TO_ret_t TODRV_HSE_sha256(TODRV_HSE_ctx_t *ctx, const uint8_t* data, const uint16_t data_length,
		uint8_t* sha256)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = data_length;
	uint16_t resp_data_len = TO_SHA256_HASHSIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SHA256, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(sha256, TODRV_HSE_response_data, TO_SHA256_HASHSIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_SHA256_INIT_UPDATE_FINAL
TODRV_HSE_HASH_API TO_ret_t TODRV_HSE_sha256_init(TODRV_HSE_ctx_t *ctx)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SHA256_INIT, 0,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_HASH_API TO_ret_t TODRV_HSE_sha256_update(TODRV_HSE_ctx_t *ctx, const uint8_t* data, const uint16_t length)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = length;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SHA256_UPDATE, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_HASH_API TO_ret_t TODRV_HSE_sha256_final(TODRV_HSE_ctx_t *ctx, uint8_t* sha256)
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = TO_SHA256_HASHSIZE;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SHA256_FINAL, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(sha256, TODRV_HSE_response_data, TO_SHA256_HASHSIZE);
	return resp_status;
}
#endif
#endif // TO_DISABLE_SHA256


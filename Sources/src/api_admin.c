/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2019 Trusted Objects. All rights reserved.
 */

/**
 * @file api_admin.c
 * @brief Secure Element administration functions.
 */

#include "TO_cfg.h"
#include "TO_defs.h"
#include "TO_retcodes.h"
#include "TO_utils.h"

#include "TODRV_HSE.h"
#include "TODRV_HSE_cfg.h"
#include "TODRV_HSE_cmd.h"
#include "TODRV_HSE_defs.h"
#include "TODRV_HSE_admin.h"
#include "TODRV_HSE_seclink.h"
#include "TOH_log.h"

#ifndef TO_DISABLE_ADMIN
TODRV_HSE_ADMIN_API TO_ret_t TODRV_HSE_admin_set_slot(TODRV_HSE_ctx_t *ctx, 
		const uint8_t index)
{
	TO_lib_ret_t ret;
	uint16_t cmd_len = sizeof(uint8_t);
	uint16_t resp_data_len = 0;
	TO_se_ret_t resp_status;
	int slink_prev_st;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, index);
	if (TO_OK != ret)
		return ret;
	slink_prev_st = TODRV_HSE_seclink_bypass(1);
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_ADMIN_SET_SLOT, cmd_len,
			&resp_data_len, &resp_status);
	TODRV_HSE_seclink_bypass(slink_prev_st);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_ADMIN_API TO_ret_t TODRV_HSE_admin_session_init(TODRV_HSE_ctx_t *ctx, 
		const uint8_t server_challenge[TO_ADMIN_CHALLENGE_SIZE],
		uint8_t se_challenge[TO_ADMIN_CHALLENGE_SIZE],
		uint8_t se_cryptogram[TO_ADMIN_CRYPTOGRAM_SIZE],
		uint8_t diversification_data[TO_ADMIN_DIVERS_DATA_SIZE],
		uint8_t protocol_info[TO_ADMIN_PROTO_INFO_SIZE])
{
	TO_lib_ret_t ret;
	uint16_t cmd_len = TO_ADMIN_CHALLENGE_SIZE;
	uint16_t resp_data_len = TO_ADMIN_CHALLENGE_SIZE
		+ TO_ADMIN_CRYPTOGRAM_SIZE + TO_ADMIN_DIVERS_DATA_SIZE
		+ TO_ADMIN_PROTO_INFO_SIZE;
	TO_se_ret_t resp_status;
	int slink_prev_st;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, server_challenge, TO_ADMIN_CHALLENGE_SIZE);
	if (TO_OK != ret)
		return ret;
	slink_prev_st = TODRV_HSE_seclink_bypass(1);
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_INIT_ADMIN_SESSION, cmd_len,
			&resp_data_len, &resp_status);
	TODRV_HSE_seclink_bypass(slink_prev_st);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(diversification_data, TODRV_HSE_response_data,
			TO_ADMIN_DIVERS_DATA_SIZE);
	TO_secure_memcpy(protocol_info, TODRV_HSE_response_data
			+ TO_ADMIN_DIVERS_DATA_SIZE, TO_ADMIN_PROTO_INFO_SIZE);
	TO_secure_memcpy(se_challenge, TODRV_HSE_response_data
			+ TO_ADMIN_DIVERS_DATA_SIZE + TO_ADMIN_PROTO_INFO_SIZE,
			TO_ADMIN_CHALLENGE_SIZE);
	TO_secure_memcpy(se_cryptogram, TODRV_HSE_response_data
			+ TO_ADMIN_DIVERS_DATA_SIZE + TO_ADMIN_PROTO_INFO_SIZE
			+ TO_ADMIN_CHALLENGE_SIZE, TO_ADMIN_CRYPTOGRAM_SIZE);
	return resp_status;
}

TODRV_HSE_ADMIN_API TO_ret_t TODRV_HSE_admin_session_auth_server(TODRV_HSE_ctx_t *ctx, 
		const uint8_t options[TO_ADMIN_OPTIONS_SIZE],
		const uint8_t server_cryptogram[TO_ADMIN_CRYPTOGRAM_SIZE],
		const uint8_t mac[TO_ADMIN_MAC_SIZE])
{
	TO_lib_ret_t ret;
	uint16_t cmd_len = TO_ADMIN_OPTIONS_SIZE + TO_ADMIN_CRYPTOGRAM_SIZE
		+ TO_ADMIN_MAC_SIZE;
	uint16_t resp_data_len = 0;
	TO_se_ret_t resp_status;
	int slink_prev_st;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, options, TO_ADMIN_OPTIONS_SIZE);
	ret |= TODRV_HSE_prepare_command_data(TO_ADMIN_OPTIONS_SIZE,
			server_cryptogram, TO_ADMIN_CRYPTOGRAM_SIZE);
	ret |= TODRV_HSE_prepare_command_data(
			TO_ADMIN_OPTIONS_SIZE + TO_ADMIN_CRYPTOGRAM_SIZE,
			mac, TO_ADMIN_MAC_SIZE);
	if (TO_OK != ret)
		return ret;
	slink_prev_st = TODRV_HSE_seclink_bypass(1);
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_AUTH_ADMIN_SESSION, cmd_len,
			&resp_data_len, &resp_status);
	TODRV_HSE_seclink_bypass(slink_prev_st);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_ADMIN_API TO_ret_t TODRV_HSE_admin_command(TODRV_HSE_ctx_t *ctx, const uint8_t *command,
		uint16_t length)
{
	TO_lib_ret_t ret;
	uint16_t cmd_len = length;
	uint16_t resp_data_len = 0;
	TO_se_ret_t resp_status;
	int slink_prev_st;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, command, length);
	if (TO_OK != ret)
		return ret;
	slink_prev_st = TODRV_HSE_seclink_bypass(1);
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_ADMIN_COMMAND, cmd_len,
			&resp_data_len, &resp_status);
	TODRV_HSE_seclink_bypass(slink_prev_st);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_ADMIN_API TO_ret_t TODRV_HSE_admin_command_with_response(TODRV_HSE_ctx_t *ctx, const uint8_t *command, uint16_t length,
		uint8_t *response, uint16_t response_length)
{
	TO_lib_ret_t ret;
	uint16_t cmd_len = length;
	uint16_t resp_data_len = response_length;
	TO_se_ret_t resp_status;
	int slink_prev_st;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, command, length);
	if (TO_OK != ret)
		return ret;
	slink_prev_st = TODRV_HSE_seclink_bypass(1);
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_ADMIN_COMMAND_WITH_RESPONSE, cmd_len,
			&resp_data_len, &resp_status);
	TODRV_HSE_seclink_bypass(slink_prev_st);
	if ((TO_OK != ret) || (TORSP_SUCCESS != resp_status))
		return ret | resp_status;

	TO_secure_memcpy(response, TODRV_HSE_response_data, response_length);
	return resp_status;
}

TODRV_HSE_ADMIN_API TO_ret_t TODRV_HSE_admin_command_with_response2(TODRV_HSE_ctx_t *ctx, const uint8_t *command, uint16_t length,
		uint8_t *response, uint16_t *response_length)
{
	TO_lib_ret_t ret;
	uint16_t cmd_len = length;
	TO_se_ret_t resp_status;
	int slink_prev_st;

	*response_length = MIN(*response_length, TODRV_HSE_RSP_MAXSIZE);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, command, length);
	if (TO_OK != ret)
		return ret;
	slink_prev_st = TODRV_HSE_seclink_bypass(1);
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_ADMIN_COMMAND_WITH_RESPONSE, cmd_len,
			response_length, &resp_status);
	TODRV_HSE_seclink_bypass(slink_prev_st);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(response, TODRV_HSE_response_data, *response_length);
	return resp_status;
}

TODRV_HSE_ADMIN_API TO_ret_t TODRV_HSE_admin_session_fini(TODRV_HSE_ctx_t *ctx, uint8_t mac[TO_ADMIN_MAC_SIZE])
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = TO_ADMIN_MAC_SIZE;
	TO_se_ret_t resp_status;
	int slink_prev_st;

	(void)ctx;

	slink_prev_st = TODRV_HSE_seclink_bypass(1);
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_FINI_ADMIN_SESSION, 0,
			&resp_data_len, &resp_status);
	TODRV_HSE_seclink_bypass(slink_prev_st);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(mac, TODRV_HSE_response_data, TO_ADMIN_MAC_SIZE);
	return resp_status;
}
#endif


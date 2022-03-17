/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2020 Trusted Objects. All rights reserved.
 */

/**
 * @file api_loader.c
 * @brief Secure Element loader functions
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
#include "TODRV_HSE_loader.h"
#include "TOH_log.h"

#ifndef TO_DISABLE_LOADER

TODRV_HSE_LOADER_API TO_ret_t TODRV_HSE_loader_broadcast_get_info(
		TODRV_HSE_ctx_t *ctx,
		uint8_t loader_version[TO_SW_VERSION_SIZE],
		uint8_t software_version[TO_SW_VERSION_SIZE],
		uint8_t upgrade_version[TO_SW_VERSION_SIZE])
{
	int ret;
	uint16_t resp_data_len = TO_LD_BCAST_INFO_SIZE;
	uint8_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LOADER_BCAST_GET_INFO, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	if (TODRV_HSE_response_data[0] != TO_LD_BCAST_ID) {
		// Unknown loader
		return TO_ERROR | resp_status;
	}
	memcpy(loader_version, TODRV_HSE_response_data + 1, TO_SW_VERSION_SIZE);
	memcpy(software_version, TODRV_HSE_response_data + 1 + TO_SW_VERSION_SIZE, TO_SW_VERSION_SIZE);
	if (upgrade_version != NULL) {
		if (resp_data_len == TO_LD_BCAST_INFO_SIZE) {
			memcpy(upgrade_version, TODRV_HSE_response_data + 1 + 2 * TO_SW_VERSION_SIZE, TO_SW_VERSION_SIZE);
		} else { /* resp_data_len == TO_LD_BCAST_INFO_SIZE_SHORT */
			memset(upgrade_version, 0, TO_SW_VERSION_SIZE);
		}
	}
	return resp_status;
}

TODRV_HSE_LOADER_API TO_ret_t TODRV_HSE_loader_broadcast_restore_loader(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t upgrade_version[TO_SW_VERSION_SIZE],
		const uint8_t minimum_version[TO_SW_VERSION_SIZE],
		const uint8_t cmac[TO_CMAC_SIZE],
		const uint8_t password[TO_LD_BCAST_RESTORE_PASSWORD_SIZE])
{
	int ret;
	uint16_t cmd_len = TO_SW_VERSION_SIZE + TO_CMAC_SIZE
		+ TO_LD_BCAST_RESTORE_PASSWORD_SIZE;
	uint16_t resp_data_len = 0;
	uint8_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, upgrade_version,
			TO_SW_VERSION_SIZE);
	if (minimum_version != NULL) {
		cmd_len += TO_SW_VERSION_SIZE;
		ret |= TODRV_HSE_prepare_command_data(TO_SW_VERSION_SIZE,
				minimum_version, TO_SW_VERSION_SIZE);
		ret |= TODRV_HSE_prepare_command_data(TO_SW_VERSION_SIZE * 2,
				cmac, TO_CMAC_SIZE);
		ret |= TODRV_HSE_prepare_command_data(TO_SW_VERSION_SIZE * 2 + TO_CMAC_SIZE,
				password, TO_LD_BCAST_RESTORE_PASSWORD_SIZE);
	} else {
		ret |= TODRV_HSE_prepare_command_data(TO_SW_VERSION_SIZE,
				cmac, TO_CMAC_SIZE);
		ret |= TODRV_HSE_prepare_command_data(TO_SW_VERSION_SIZE + TO_CMAC_SIZE,
				password, TO_LD_BCAST_RESTORE_PASSWORD_SIZE);
	}
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LOADER_BCAST_RESTORE,
			cmd_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_LOADER_API TO_ret_t TODRV_HSE_loader_broadcast_send_init_data(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t init_data[TO_LD_BCAST_INIT_DATA_SIZE],
		const uint8_t cmac[TO_CMAC_SIZE])
{
	int ret;
	uint16_t cmd_len = TO_LD_BCAST_INIT_DATA_SIZE + TO_CMAC_SIZE;
	uint16_t resp_data_len = 0;
	uint8_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, init_data,
			TO_LD_BCAST_INIT_DATA_SIZE);
	ret |= TODRV_HSE_prepare_command_data(TO_LD_BCAST_INIT_DATA_SIZE,
			cmac, TO_CMAC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LOADER_BCAST_INITIALIZE_UPGRADE,
			cmd_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_LOADER_API TO_ret_t TODRV_HSE_loader_broadcast_write_data(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *segment, uint16_t length)
{
	int ret;
	uint16_t resp_data_len = 0;
	uint8_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, segment, length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LOADER_BCAST_WRITE_DATA,
			length, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_LOADER_API TO_ret_t TODRV_HSE_loader_broadcast_commit_release(
		TODRV_HSE_ctx_t *ctx, const uint8_t cmac[TO_CMAC_SIZE])
{
	uint16_t cmd_len = TO_CMAC_SIZE;
	uint16_t resp_data_len = 0;
	uint8_t resp_status;
	int ret;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, cmac, TO_CMAC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LOADER_BCAST_COMMIT_RELEASE,
			cmd_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_LOADER_API TO_ret_t TODRV_HSE_data_migration(TODRV_HSE_ctx_t *ctx)
{
	int ret;
	uint16_t resp_data_len = 0;
	uint8_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_DATA_MIGRATION, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	return resp_status;
}

#endif // TO_DISABLE_LOADER

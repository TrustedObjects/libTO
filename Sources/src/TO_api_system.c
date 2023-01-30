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
 * @file api_system.c
 * @brief Secure Element system functions.
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
#include "TODRV_HSE_system.h"
#include "TOH_log.h"

#ifndef TO_DISABLE_TO_INFO
#ifndef TO_DISABLE_API_GET_SERIAL_NUMBER
TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_serial_number(TODRV_HSE_ctx_t *ctx, uint8_t serial_number[TO_SN_SIZE])
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = TO_SN_SIZE;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_SN, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(serial_number, TODRV_HSE_response_data, TO_SN_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_HARDWARE_SERIAL_NUMBER
TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_hardware_serial_number(TODRV_HSE_ctx_t *ctx, uint8_t hardware_serial_number[TO_HW_SN_SIZE])
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = TO_HW_SN_SIZE;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_HW_SN, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(hardware_serial_number, TODRV_HSE_response_data, TO_HW_SN_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_PRODUCT_NUMBER
TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_product_number(TODRV_HSE_ctx_t *ctx, uint8_t product_number[TO_PN_SIZE])
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = TO_PN_SIZE;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_PN, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(product_number, TODRV_HSE_response_data, TO_PN_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_HARDWARE_VERSION
TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_hardware_version(TODRV_HSE_ctx_t *ctx,
		uint8_t hardware_version[TO_HW_VERSION_SIZE])
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = TO_HW_VERSION_SIZE;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_HW_VERSION, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(hardware_version, TODRV_HSE_response_data, TO_HW_VERSION_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_SOFTWARE_VERSION
TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_software_version(TODRV_HSE_ctx_t *ctx, uint8_t* major, uint8_t* minor,
		uint8_t* revision)
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = TO_SW_VERSION_SIZE;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_SW_VERSION, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*major = TODRV_HSE_response_data[0];
	*minor = TODRV_HSE_response_data[1];
	*revision = TODRV_HSE_response_data[2];
	return resp_status;
}
#endif
#endif // TO_DISABLE_TO_INFO

#ifndef TO_DISABLE_API_GET_PRODUCT_ID
TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_product_id(TODRV_HSE_ctx_t *ctx, uint8_t product_id[TO_PRODUCT_ID_SIZE])
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = TO_PRODUCT_ID_SIZE;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_PRODUCT_ID, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(product_id, TODRV_HSE_response_data, TO_PRODUCT_ID_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_GET_RANDOM
TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_random(TODRV_HSE_ctx_t *ctx, const uint16_t random_length, uint8_t* random)
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = random_length;
	TO_se_ret_t resp_status;
	const uint16_t _random_length = htobe16(random_length);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, (uint8_t*)&_random_length,
			sizeof(_random_length));
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_RANDOM, 2,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(random, TODRV_HSE_response_data, random_length);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_STATUS_PIO_CONFIG
#ifndef TO_DISABLE_API_STATUS_PIO_CONFIG_SET
TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_set_status_PIO_config(TODRV_HSE_ctx_t *ctx, int enable,
		int opendrain, int ready_level, int idle_hz)
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = 0;
	TO_se_ret_t resp_status;
	uint16_t config = 0x00;

	(void)ctx;

	if (enable)
		config |= TO_STATUS_PIO_ENABLE;
	if (opendrain)
		config |= TO_STATUS_PIO_HIGH_OPENDRAIN_MASK;
	if (ready_level)
		config |= TO_STATUS_PIO_READY_LEVEL_MASK;
	if (idle_hz)
		config |= TO_STATUS_PIO_IDLE_HZ_MASK;
	config <<= 8;
	config = htobe16(config);
	ret = TODRV_HSE_prepare_command_data(0, (uint8_t*)&config, sizeof(config));
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_SET_STATUS_PIO_CONFIG, sizeof(config),
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}
#endif

#ifndef TO_DISABLE_API_STATUS_PIO_CONFIG_GET
TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_status_PIO_config(TODRV_HSE_ctx_t *ctx, int *enable,
		int *opendrain, int *ready_level, int *idle_hz)
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = 2;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_STATUS_PIO_CONFIG, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*enable = ((TODRV_HSE_response_data[0] & TO_STATUS_PIO_ENABLE)
			== TO_STATUS_PIO_ENABLE);
	*opendrain = ((TODRV_HSE_response_data[0]
				& TO_STATUS_PIO_HIGH_OPENDRAIN_MASK) != 0);
	*ready_level = ((TODRV_HSE_response_data[0]
				& TO_STATUS_PIO_READY_LEVEL_MASK) != 0);
	*idle_hz = ((TODRV_HSE_response_data[0]
				& TO_STATUS_PIO_IDLE_HZ_MASK) != 0);
	return resp_status;
}
#endif
#endif // TO_ENABLE_STATUS_PIO_CONFIG

#endif /* TODRV_HSE_DRIVER_DISABLE */


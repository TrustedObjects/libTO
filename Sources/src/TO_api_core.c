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
 * @file api_core.c
 * @brief Secure Element API implementation using I2C wrapper for Secure
 * Element communications.
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#include <stdbool.h>
#include "TO_cfg.h"
#include "TO_defs.h"
#include "TO_retcodes.h"
#include "TO_log.h"
#include "TO_endian.h"
#include "TO_utils.h"

#include "TODRV_HSE.h"
#include "TODRV_HSE_cfg.h"
#include "TODRV_HSE_i2c_wrapper.h"
#include "TODRV_HSE_core.h"
#include "TODRV_HSE_defs.h"
#include "TODRV_HSE_cmd.h"

#include "TO_seclink.h"
#include "TOH_log.h"

unsigned char TODRV_HSE_io_buffer[TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE];
unsigned char *TODRV_HSE_command_data = TODRV_HSE_io_buffer + TODRV_HSE_CMDHEAD_SIZE;
unsigned char *TODRV_HSE_response_data = TODRV_HSE_io_buffer + TODRV_HSE_RSPHEAD_SIZE;

static TODRV_HSE_pre_command_hook _pre_command_hook = NULL;
static TODRV_HSE_post_write_hook _post_write_hook = NULL;
static TODRV_HSE_post_command_hook _post_command_hook = NULL;

/*
 * Data parameters types to build command data buffer
 */
enum cmd_param_type_e {
	CMD_PARAM_PTR, /**< Pointer to a data buffer */
	CMD_PARAM_BYTE, /**< Single byte */
	CMD_PARAM_RANGE, /**< Bytes range to set to a defined value */
};

/*
 * Command data parameter description
 */
struct cmd_param_s {
	enum cmd_param_type_e type;
	uint16_t offset;
	void *data;
	uint16_t size;
};

/*
 * Data parameters description array, used to build command data buffer
 */
static struct cmd_param_s _cmd_param[TODRV_HSE_CMD_MAX_PARAMS];

/*
 * Last command parameter index in cmd_params
 */
static uint8_t _cmd_param_index = 0;

/*
 * Secure link bypassing
 */
static int _seclink_bypass = 0;

/*
 * Secure link status
 */
static int _seclink_ready = 0;

TODRV_HSE_CORE_API TO_ret_t TODRV_HSE_init(TODRV_HSE_ctx_t *ctx, TO_log_level_t *log_ctx)
{
	(void)ctx;
	(void)log_ctx;

	return TO_data_init();
}

TODRV_HSE_CORE_API TO_ret_t TODRV_HSE_fini(TODRV_HSE_ctx_t *ctx)
{
	(void)ctx;

	_seclink_ready = 0;
	return TO_data_fini();
}

TO_lib_ret_t TODRV_HSE_trp_write(const void *data, unsigned int length)
{
	TOH_LOG_DBG("");
	TOH_LOG_DBG_HEX((const unsigned char*)data, length);

	return TO_data_write(data, length);
}

TO_lib_ret_t TODRV_HSE_trp_read(void *data, unsigned int length)
{
	TO_lib_ret_t ret;
	ret = TO_data_read(data, length);
	TOH_LOG_DBG("");
	TOH_LOG_DBG_HEX((const unsigned char*)data, length);

	return ret;
}

TO_lib_ret_t TODRV_HSE_trp_last_command_duration(unsigned int *duration)
{
#ifdef TODRV_HSE_I2C_WRAPPER_LAST_COMMAND_DURATION
	TO_lib_ret_t ret;
	ret = TO_data_last_command_duration(duration);
	if (ret == TO_OK) {
		TOH_LOG_DBG("%d µs", *duration);
	}
	return ret;
#else
	*duration = 0;
	return TO_NOT_IMPLEMENTED;
#endif
}

#ifdef TODRV_HSE_I2C_WRAPPER_CONFIG
TO_lib_ret_t TODRV_HSE_trp_config(unsigned char i2c_addr, unsigned char misc_settings)
{
	TO_i2c_config_t config;
	config.i2c_addr = i2c_addr;
	config.misc_settings = misc_settings;
	return TO_data_config(&config);
}
#endif

TO_lib_ret_t TODRV_HSE_seclink_reset(void)
{
	TO_lib_ret_t ret;
	ret = TODRV_HSE_seclink_init();
	if (ret != TO_OK) {
		TOH_LOG_ERR("error: unable to initialize secure"
				" commands, error %X\n", ret);
		return ret;
	}
	_seclink_ready = 1;
	return TO_OK;
}

int TODRV_HSE_seclink_bypass(int bypass)
{
	int prev_state = _seclink_bypass;
	_seclink_bypass = bypass;
	return prev_state;
}

void TODRV_HSE_reset_command_data(void)
{
	_cmd_param_index = 0;
}

static int _check_cmd_param_index(void)
{
	if (_cmd_param_index >= TODRV_HSE_CMD_MAX_PARAMS) {
		TOH_LOG_ERR("error: command max parameters exceeded");
		TODRV_HSE_reset_command_data();
		return TO_MEMORY_ERROR;
	}
	return TO_OK;
}

TO_lib_ret_t TODRV_HSE_prepare_command_data(uint16_t offset,
		const unsigned char *data, uint16_t len)
{
	TO_lib_ret_t ret;

	/* Checks if command headers and data doesn't exceed buffer size */
	if (TODRV_HSE_CMDHEAD_SIZE + offset + len
			> TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE) {
		TOH_LOG_ERR("error: command data length exceeds internal"
			       " I/O buffer size");
		TODRV_HSE_reset_command_data();
		return TO_MEMORY_ERROR;
	}
	/* Save command parameter details */
	ret = _check_cmd_param_index();
	if (ret != TO_OK)
		return ret;
	_cmd_param[_cmd_param_index].type = CMD_PARAM_PTR;
	_cmd_param[_cmd_param_index].offset = offset;
	_cmd_param[_cmd_param_index].data = (void *)data;
	_cmd_param[_cmd_param_index].size = len;
	_cmd_param_index++;

	return TO_OK;
}

TO_lib_ret_t TODRV_HSE_prepare_command_data_byte(uint16_t offset, const char byte)
{
	TO_lib_ret_t ret;

	/* Checks if command headers and data byte doesn't exceed buffer size */
	if (TODRV_HSE_CMDHEAD_SIZE + offset
			> TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE) {
		TOH_LOG_ERR("error: command data byte exceeds internal"
				" I/O buffer size");
		TODRV_HSE_reset_command_data();
		return TO_MEMORY_ERROR;
	}
	/* Save command parameter details */
	ret = _check_cmd_param_index();
	if (ret != TO_OK)
		return ret;
	_cmd_param[_cmd_param_index].type = CMD_PARAM_BYTE;
	_cmd_param[_cmd_param_index].offset = offset;
	_cmd_param[_cmd_param_index].data = (void *)(long)byte;
	_cmd_param_index++;

	return TO_OK;
}

TO_lib_ret_t TODRV_HSE_set_command_data(uint16_t offset, const char byte, uint16_t len)
{
	TO_lib_ret_t ret;

	/* Checks if command headers and data doesn't exceed buffer size */
	if (TODRV_HSE_CMDHEAD_SIZE + offset + len
			> TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE) {
		TOH_LOG_ERR("error: command data range exceeds internal"
				" I/O buffer size");
		TODRV_HSE_reset_command_data();
		return TO_MEMORY_ERROR;
	}
	/* Save command parameter details */
	ret = _check_cmd_param_index();
	if (ret != TO_OK)
		return ret;
	_cmd_param[_cmd_param_index].type = CMD_PARAM_RANGE;
	_cmd_param[_cmd_param_index].offset = offset;
	_cmd_param[_cmd_param_index].data = (void *)(long)byte;
	_cmd_param[_cmd_param_index].size = len;
	_cmd_param_index++;

	return TO_OK;
}

/**
 * _write_command() - Write command to TO
 * @len: Command and data length
 *
 * This function first checks if internal I/O buffer size is greater than
 * command length, taking into account secure link data overhead if secure
 * command bypassing is disabled.
 * The command is secured if secure link bypassing is disabled, then written
 * to TO.
 *
 * Return: TO_OK on success
 */
static TO_lib_ret_t _write_command(uint16_t len)
{
	TO_lib_ret_t ret;
	uint16_t fullcmd_size;

	if (!_seclink_bypass) {
		if (!_seclink_ready) {
			ret = TODRV_HSE_seclink_reset();
			if (ret != TO_OK) {
				return ret;
			}
		}
		fullcmd_size = TODRV_HSE_seclink_compute_cmd_size(len);
	} else {
		fullcmd_size = len;
	}
	if (fullcmd_size > TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE) {
		TOH_LOG_ERR("error: length (%d) exceeds internal I/O"
				" buffer size (%d)\n", fullcmd_size,
				TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE);
		return TO_MEMORY_ERROR;
	}
	if (!_seclink_bypass) {
		ret = TODRV_HSE_seclink_secure(TODRV_HSE_io_buffer, len);
		if (ret != TO_OK) {
			TOH_LOG_ERR("error %X:"
					" unable to secure link\n",
					ret);
			return ret;
		}
	}

	return TO_data_write(TODRV_HSE_io_buffer, fullcmd_size);
}

/**
 * _read_response() - Read Secure Element response
 * @len: Expected response length
 *
 * This function first checks if internal I/O buffer size is greater than
 * response length, taking into account secure link data overhead if secure
 * command bypassing is disabled.
 * The response is read from TO, then is unsecured if secure link
 * bypassing is disabled.
 *
 * Return: TO_OK on success
 */
static TO_lib_ret_t _read_response(uint16_t len)
{
	TO_lib_ret_t ret;
	uint16_t fullrsp_size;

	if (!_seclink_bypass)
		fullrsp_size = TODRV_HSE_seclink_compute_rsp_size(len);
	else
		fullrsp_size = len;
	if (fullrsp_size < len) {
		TOH_LOG_ERR("data length overflow");

		return TO_MEMORY_ERROR;
	}
	if (fullrsp_size > TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE) {
		TOH_LOG_ERR("error: length (%d) exceeds internal I/O"
				" buffer size (%d)",
				fullrsp_size,
				TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE);
		return TO_MEMORY_ERROR;
	}

	ret = TO_data_read(TODRV_HSE_io_buffer, fullrsp_size);
	if (ret != TO_OK) {
		TOH_LOG_ERR("error %X: unable to read data",ret);
		return ret;
	}
	if (!_seclink_bypass) {
		ret = TODRV_HSE_seclink_unsecure(TODRV_HSE_io_buffer);
		if (ret != TO_OK) {
			if ((ret & 0x00FF) != TORSP_SECLINK_RENEW_KEY) {
				TOH_LOG_ERR("error %X:"
						" unable to unsecure link",ret);
			}
			return ret;
		}
	}

	return TO_OK;
}

static void _prepare_command_data_buffer(void)
{
	uint8_t i;
	struct cmd_param_s *param;
	for (i = 0; i < _cmd_param_index; i++) {
		param = &_cmd_param[i];
		switch (param->type) {
		case CMD_PARAM_PTR:
			TO_secure_memcpy(TODRV_HSE_command_data + param->offset,
					(char *)param->data, param->size);
			break;
		case CMD_PARAM_BYTE:
			TODRV_HSE_command_data[param->offset] =
				(char)(long)param->data;
			break;
		case CMD_PARAM_RANGE:
			TO_secure_memset(TODRV_HSE_command_data + param->offset,
					(char)(long)param->data,
					param->size);
			break;
		}
	}
}

static TO_lib_ret_t _send_command(
		const uint16_t cmd, uint16_t cmd_data_len,
		uint16_t *resp_data_len, TO_se_ret_t *resp_status)
{
	uint16_t data_len;
	unsigned int status;
	uint16_t _cmd;
	uint16_t _cmd_data_len;
	uint16_t *_resp_data_len;

	if (_pre_command_hook)
		_pre_command_hook(cmd, cmd_data_len);

	/*
	 * Prepare inputs
	 */
	*resp_status = (TO_se_ret_t)0;
	_cmd = htobe16(cmd);
	_cmd_data_len = htobe16(cmd_data_len);
	_prepare_command_data_buffer();

	/*
	 * Command headers:
	 *  CMD: 2
	 *  Lc: 2, to encode number of bytes of data
	 *  RES: 1, reserved
	 *  Data: Lc
	 * Read the Secure Element Datasheet, 7.2 - Command fields
	 */
	data_len = TODRV_HSE_CMDHEAD_SIZE + cmd_data_len;
	TO_secure_memcpy(TODRV_HSE_io_buffer, (uint8_t*)&_cmd, sizeof(cmd));
	TO_secure_memcpy(TODRV_HSE_io_buffer + 2, (uint8_t*)&_cmd_data_len,
			sizeof(_cmd_data_len));
	TODRV_HSE_io_buffer[4] = 0x0; /* RESERVED */
	TOH_LOG_DBG("write:");
	TOH_LOG_DBG_BUF(TODRV_HSE_io_buffer, data_len);

	/* Write command and data */
	status = _write_command(data_len);
	if (TO_OK != status) {
		TOH_LOG_ERR("(cmd=%04X) write error %04X",
				cmd, status);
		if (TO_MEMORY_ERROR == status)
			return TO_MEMORY_ERROR;
		else
			return TO_DEVICE_WRITE_ERROR;
	}

	if (_post_write_hook)
		_post_write_hook(cmd, cmd_data_len);

	/*
	 * Response headers:
	 *  Lr: 2, length of response data
	 *  ST: 1, status of the command (success, failed ...)
	 *  RES: 1, reserved
	 *  Data: Lr
	 * Read the Secure Element Datasheet, 7.3 - Response fields
	 */
	data_len = TODRV_HSE_RSPHEAD_SIZE + *resp_data_len;

	/* Size overflow */
	if (data_len < *resp_data_len) {
		TOH_LOG_ERR("cmd=%04X) response length overflow",
				cmd);
		return TO_MEMORY_ERROR;
	}
	/* Don't let the status uninitialized in case of read error */
	TODRV_HSE_io_buffer[2] = 0;

	/* Receive response */
	status = _read_response(data_len);

	/* If read error, it may have occured after status transmission */
	*resp_status = (TO_se_ret_t)TODRV_HSE_io_buffer[2];
	_resp_data_len = (uint16_t*)TODRV_HSE_io_buffer;
	*resp_data_len = be16toh(*_resp_data_len);
	TOH_LOG_DBG("read:");
	TOH_LOG_DBG_BUF(TODRV_HSE_io_buffer, (*resp_data_len) + TODRV_HSE_RSPHEAD_SIZE);

	if (TO_OK != status) {
		TOH_LOG_ERR("(cmd=%04X) read error %04X\n",
				cmd, status);
		if (TO_MEMORY_ERROR == status)
			return TO_MEMORY_ERROR;
		else
			return TO_DEVICE_READ_ERROR;
	}

	/* On command success, check size validity */
	if (*resp_status == TORSP_SUCCESS
			&& *resp_data_len > data_len - TODRV_HSE_RSPHEAD_SIZE) {
		TOH_LOG_ERR("(cmd=%04X) read error, response length "
				"(%uB) overflows buffer (%luB)",
				cmd,
				*resp_data_len, data_len - TODRV_HSE_RSPHEAD_SIZE);
		return TO_INVALID_RESPONSE_LENGTH;
	}

	if (_post_command_hook)
		_post_command_hook(cmd, cmd_data_len,
				*resp_data_len, *resp_status);

	return TO_OK;
}

TO_lib_ret_t TODRV_HSE_send_command(const uint16_t cmd,
		uint16_t cmd_data_len,
		uint16_t *resp_data_len,
		TO_se_ret_t *resp_status)
{
	TO_lib_ret_t ret;
	int renew_retries = 0;
	ret = _send_command(cmd, cmd_data_len, resp_data_len, resp_status);

	/* Secure link requests keys renewal ? */
	if ((ret != TO_OK) && (*resp_status == TORSP_SECLINK_RENEW_KEY)) {

		/* Renew the keys and redo the command */
		while (TODRV_HSE_seclink_renew_keys() == TO_SECLINK_ERROR) {

			/* Retrying, just in case a communication error occured
			 * while getting the new key */
			TOH_LOG_ERR("retry secure link key renewal");
			if (++renew_retries >= 3) {
				TOH_LOG_ERR("secure link key renewal "
						"failed %d retries, abort",
						renew_retries);
				return TO_SECLINK_ERROR;
			}
		}
		ret = _send_command(cmd, cmd_data_len,
				resp_data_len, resp_status);
	} else {
		if (ret != TO_OK) {
			/* Any communication error, maybe secure link state data are
			* desynchronised between libTO and SE, then force secure link
			* initialisation next time to resynchronise. */
			_seclink_ready = 0;
		}
	}
	TODRV_HSE_reset_command_data();

	return ret;
}

uint16_t TODRV_HSE_get_msg_data_size_max(enum msg_type type)
{
	/* FIXME retrieve buffer_size from Secure Elements config */
	uint16_t buffer_size = MIN(TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE, TODRV_HSE_MAXSIZE);
	uint16_t overhead_size;
	uint16_t header_size = (type == MSG_TYPE_COMMAND)
					? TODRV_HSE_CMDHEAD_SIZE
					: TODRV_HSE_RSPHEAD_SIZE;

	overhead_size = TODRV_HSE_seclink_compute_cmd_size(header_size);
	
	return buffer_size - overhead_size;
}

void TODRV_HSE_set_lib_hook_pre_command(TODRV_HSE_pre_command_hook hook)
{
	_pre_command_hook = hook;
}

void TODRV_HSE_set_lib_hook_post_write(TODRV_HSE_post_write_hook hook)
{
	_post_write_hook = hook;
}

void TODRV_HSE_set_lib_hook_post_command(TODRV_HSE_post_command_hook hook)
{
	_post_command_hook = hook;
}

#endif /* TODRV_HSE_DRIVER_DISABLE */


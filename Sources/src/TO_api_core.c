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
	TOH_LOG_DBG_HEX((const unsigned char*)data, length);

	return TO_data_write(data, length);
}

TO_lib_ret_t TODRV_HSE_trp_read(void *data, unsigned int length)
{
	TO_lib_ret_t ret;
	ret = TO_data_read(data, length);
	TOH_LOG_DBG_HEX((const unsigned char*)data, length);

	return ret;
}

TO_lib_ret_t TODRV_HSE_trp_last_command_duration(unsigned int *duration)
{
#ifdef TODRV_HSE_I2C_WRAPPER_LAST_COMMAND_DURATION
	TO_lib_ret_t ret = 0x9999;
	ret = TO_data_last_command_duration(duration);
	if (ret == TO_OK) {
		TOH_LOG_DBG("%d µs", *duration);
	} else {
		TOH_LOG_DBG("%x ", ret);
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
		TOH_LOG_ERR("error: command max parameters exceeded", 0);
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
			       " I/O buffer size", 0);
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
				" I/O buffer size", 0);
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
				" I/O buffer size", 0);
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
		TOH_LOG_ERR("data length overflow", 0);

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
	TOH_LOG_DBG("write:", 0);
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

	if (TO_OK != status) {
		TOH_LOG_ERR("(cmd=%04X) read error %04X\n",
				cmd, status);
		if (TO_MEMORY_ERROR == status)
			return TO_MEMORY_ERROR;
		else
			return TO_DEVICE_READ_ERROR;
	}

	/* If read error, it may have occured after status transmission */
	*resp_status = (TO_se_ret_t)TODRV_HSE_io_buffer[2];
	_resp_data_len = (uint16_t*)TODRV_HSE_io_buffer;
	*resp_data_len = be16toh(*_resp_data_len);
	TOH_LOG_DBG("read:", 0);
	TOH_LOG_DBG_BUF(TODRV_HSE_io_buffer, (*resp_data_len) + TODRV_HSE_RSPHEAD_SIZE);

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
			TOH_LOG_ERR("retry secure link key renewal", 0);
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

void TODRV_HSE_cmd_name_from_number(int number, char *name)
{
	switch (number) {
		case TODRV_HSE_CMD_INIT:
			strcpy(name, "INIT");
			break;

		case TODRV_HSE_CMD_GET_SN:
			strcpy(name, "GET_SN");
			break;

		case TODRV_HSE_CMD_GET_HW_SN:
			strcpy(name, "GET_HW_SN");
			break;

		case TODRV_HSE_CMD_RES:
			strcpy(name, "RES");
			break;

		case TODRV_HSE_CMD_GET_PN:
			strcpy(name, "GET_PN");
			break;

		case TODRV_HSE_CMD_GET_HW_VERSION:
			strcpy(name, "GET_HW_VERSION");
			break;

		case TODRV_HSE_CMD_GET_SW_VERSION:
			strcpy(name, "GET_SW_VERSION");
			break;

		case TODRV_HSE_CMD_GET_PRODUCT_ID:
			strcpy(name, "GET_PRODUCT_ID");
			break;

		case TODRV_HSE_CMD_GET_RANDOM:
			strcpy(name, "GET_RANDOM");
			break;

		case TODRV_HSE_CMD_ECHO:
			strcpy(name, "ECHO");
			break;

		case TODRV_HSE_CMD_SLEEP:
			strcpy(name, "SLEEP");
			break;

		case TODRV_HSE_CMD_READ_NVM:
			strcpy(name, "READ_NVM");
			break;

		case TODRV_HSE_CMD_WRITE_NVM:
			strcpy(name, "WRITE_NVM");
			break;

		case TODRV_HSE_CMD_GET_NVM_SIZE:
			strcpy(name, "GET_NVM_SIZE");
			break;

		case TODRV_HSE_CMD_SET_STATUS_PIO_CONFIG:
			strcpy(name, "SET_STATUS_PIO_CONFIG");
			break;

		case TODRV_HSE_CMD_GET_STATUS_PIO_CONFIG:
			strcpy(name, "GET_STATUS_PIO_CONFIG");
			break;

		case TODRV_HSE_CMD_SET_CERTIFICATE_SIGNING_REQUEST_DN:
			strcpy(name, "SET_CERTIFICATE_SIGNING_REQUEST_DN");
			break;

		case TODRV_HSE_CMD_GET_CERTIFICATE_SIGNING_REQUEST:
			strcpy(name, "GET_CERTIFICATE_SIGNING_REQUEST");
			break;

		case TODRV_HSE_CMD_GET_CERTIFICATE_SUBJECT_CN:
			strcpy(name, "GET_CERTIFICATE_SUBJECT_CN");
			break;

		case TODRV_HSE_CMD_GET_CERTIFICATE:
			strcpy(name, "GET_CERTIFICATE");
			break;

		case TODRV_HSE_CMD_SET_CERTIFICATE:
			strcpy(name, "SET_CERTIFICATE");
			break;

		case TODRV_HSE_CMD_SET_CERTIFICATE_INIT:
			strcpy(name, "SET_CERTIFICATE_INIT");
			break;

		case TODRV_HSE_CMD_SET_CERTIFICATE_UPDATE:
			strcpy(name, "SET_CERTIFICATE_UPDATE");
			break;

		case TODRV_HSE_CMD_SET_CERTIFICATE_FINAL:
			strcpy(name, "SET_CERTIFICATE_FINAL");
			break;

		case TODRV_HSE_CMD_GET_CERTIFICATE_INIT:
			strcpy(name, "GET_CERTIFICATE_INIT");
			break;

		case TODRV_HSE_CMD_GET_CERTIFICATE_UPDATE:
			strcpy(name, "GET_CERTIFICATE_UPDATE");
			break;

		case TODRV_HSE_CMD_GET_CERTIFICATE_FINAL:
			strcpy(name, "GET_CERTIFICATE_FINAL");
			break;

		case TODRV_HSE_CMD_SIGN:
			strcpy(name, "SIGN");
			break;

		case TODRV_HSE_CMD_VERIFY:
			strcpy(name, "VERIFY");
			break;

		case TODRV_HSE_CMD_SIGN_HASH:
			strcpy(name, "SIGN_HASH");
			break;

		case TODRV_HSE_CMD_VERIFY_HASH_SIGNATURE:
			strcpy(name, "VERIFY_HASH_SIGNATURE");
			break;

		case TODRV_HSE_CMD_GET_CERTIFICATE_AND_SIGN:
			strcpy(name, "GET_CERTIFICATE_AND_SIGN");
			break;

		case TODRV_HSE_CMD_VERIFY_CERTIFICATE_AND_STORE:
			strcpy(name, "VERIFY_CERTIFICATE_AND_STORE");
			break;

		case TODRV_HSE_CMD_VERIFY_CA_CERTIFICATE_AND_STORE:
			strcpy(name, "VERIFY_CA_CERTIFICATE_AND_STORE");
			break;

		case TODRV_HSE_CMD_GET_CHALLENGE_AND_STORE:
			strcpy(name, "GET_CHALLENGE_AND_STORE");
			break;

		case TODRV_HSE_CMD_VERIFY_CHALLENGE_SIGNATURE:
			strcpy(name, "VERIFY_CHALLENGE_SIGNATURE");
			break;

		case TODRV_HSE_CMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_INIT:
			strcpy(name, "VERIFY_CHAIN_CERTIFICATE_AND_STORE_INIT");
			break;

		case TODRV_HSE_CMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_UPDATE:
			strcpy(name, "VERIFY_CHAIN_CERTIFICATE_AND_STORE_UPDATE");
			break;

		case TODRV_HSE_CMD_VERIFY_CHAIN_CERTIFICATE_AND_STORE_FINAL:
			strcpy(name, "VERIFY_CHAIN_CERTIFICATE_AND_STORE_FINAL");
			break;

		case TODRV_HSE_CMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_INIT:
			strcpy(name, "VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_INIT");
			break;

		case TODRV_HSE_CMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_UPDATE:
			strcpy(name, "VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_UPDATE");
			break;

		case TODRV_HSE_CMD_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_FINAL:
			strcpy(name, "VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE_FINAL");
			break;

		case TODRV_HSE_CMD_COMPUTE_HMAC:
			strcpy(name, "COMPUTE_HMAC");
			break;

		case TODRV_HSE_CMD_COMPUTE_HMAC_INIT:
			strcpy(name, "COMPUTE_HMAC_INIT");
			break;

		case TODRV_HSE_CMD_COMPUTE_HMAC_UPDATE:
			strcpy(name, "COMPUTE_HMAC_UPDATE");
			break;

		case TODRV_HSE_CMD_COMPUTE_HMAC_FINAL:
			strcpy(name, "COMPUTE_HMAC_FINAL");
			break;

		case TODRV_HSE_CMD_VERIFY_HMAC:
			strcpy(name, "VERIFY_HMAC");
			break;

		case TODRV_HSE_CMD_VERIFY_HMAC_INIT:
			strcpy(name, "VERIFY_HMAC_INIT");
			break;

		case TODRV_HSE_CMD_VERIFY_HMAC_UPDATE:
			strcpy(name, "VERIFY_HMAC_UPDATE");
			break;

		case TODRV_HSE_CMD_VERIFY_HMAC_FINAL:
			strcpy(name, "VERIFY_HMAC_FINAL");
			break;

		case TODRV_HSE_CMD_AES128CBC_ENCRYPT:
			strcpy(name, "AES128CBC_ENCRYPT");
			break;

		case TODRV_HSE_CMD_AES128CBC_DECRYPT:
			strcpy(name, "AES128CBC_DECRYPT");
			break;

		case TODRV_HSE_CMD_AES128CBC_IV_ENCRYPT:
			strcpy(name, "AES128CBC_IV_ENCRYPT");
			break;

		case TODRV_HSE_CMD_AES128GCM_ENCRYPT:
			strcpy(name, "AES128GCM_ENCRYPT");
			break;

		case TODRV_HSE_CMD_AES128GCM_DECRYPT:
			strcpy(name, "AES128GCM_DECRYPT");
			break;

		case TODRV_HSE_CMD_AES128CCM_ENCRYPT:
			strcpy(name, "AES128CCM_ENCRYPT");
			break;

		case TODRV_HSE_CMD_AES128CCM_DECRYPT:
			strcpy(name, "AES128CCM_DECRYPT");
			break;

		case TODRV_HSE_CMD_AES128ECB_ENCRYPT:
			strcpy(name, "AES128ECB_ENCRYPT");
			break;

		case TODRV_HSE_CMD_AES128ECB_DECRYPT:
			strcpy(name, "AES128ECB_DECRYPT");
			break;

		case TODRV_HSE_CMD_COMPUTE_CMAC:
			strcpy(name, "COMPUTE_CMAC");
			break;

		case TODRV_HSE_CMD_VERIFY_CMAC:
			strcpy(name, "VERIFY_CMAC");
			break;

		case TODRV_HSE_CMD_SHA256:
			strcpy(name, "SHA256");
			break;

		case TODRV_HSE_CMD_SHA256_INIT:
			strcpy(name, "SHA256_INIT");
			break;

		case TODRV_HSE_CMD_SHA256_UPDATE:
			strcpy(name, "SHA256_UPDATE");
			break;

		case TODRV_HSE_CMD_SHA256_FINAL:
			strcpy(name, "SHA256_FINAL");
			break;

		case TODRV_HSE_CMD_AES128CBC_HMAC_SECURE_MESSAGE:
			strcpy(name, "AES128CBC_HMAC_SECURE_MESSAGE");
			break;

		case TODRV_HSE_CMD_AES128CBC_HMAC_UNSECURE_MESSAGE:
			strcpy(name, "AES128CBC_HMAC_UNSECURE_MESSAGE");
			break;

		case TODRV_HSE_CMD_AES128CBC_CMAC_SECURE_MESSAGE:
			strcpy(name, "AES128CBC_CMAC_SECURE_MESSAGE");
			break;

		case TODRV_HSE_CMD_AES128CBC_CMAC_UNSECURE_MESSAGE:
			strcpy(name, "AES128CBC_CMAC_UNSECURE_MESSAGE");
			break;

		case TODRV_HSE_CMD_SET_REMOTE_PUBLIC_KEY:
			strcpy(name, "SET_REMOTE_PUBLIC_KEY");
			break;

		case TODRV_HSE_CMD_RENEW_ECC_KEYS:
			strcpy(name, "RENEW_ECC_KEYS");
			break;

		case TODRV_HSE_CMD_GET_PUBLIC_KEY:
			strcpy(name, "GET_PUBLIC_KEY");
			break;

		case TODRV_HSE_CMD_GET_UNSIGNED_PUBLIC_KEY:
			strcpy(name, "GET_UNSIGNED_PUBLIC_KEY");
			break;

		case TODRV_HSE_CMD_RENEW_SHARED_KEYS:
			strcpy(name, "RENEW_SHARED_KEYS");
			break;

		case TODRV_HSE_CMD_GET_KEY_FINGERPRINT:
			strcpy(name, "GET_KEY_FINGERPRINT");
			break;

		case TODRV_HSE_CMD_TLS_GET_RANDOM_AND_STORE:
			strcpy(name, "TLS_GET_RANDOM_AND_STORE");
			break;

		case TODRV_HSE_CMD_TLS_RENEW_KEYS:
			strcpy(name, "TLS_RENEW_KEYS");
			break;

		case TODRV_HSE_CMD_TLS_GET_MASTER_SECRET:
			strcpy(name, "TLS_GET_MASTER_SECRET");
			break;

		case TODRV_HSE_CMD_TLS_GET_MASTER_SECRET_DERIVED_KEYS:
			strcpy(name, "TLS_GET_MASTER_SECRET_DERIVED_KEYS");
			break;

		case TODRV_HSE_CMD_TLS_SET_SERVER_RANDOM:
			strcpy(name, "TLS_SET_SERVER_RANDOM");
			break;

		case TODRV_HSE_CMD_TLS_SET_SERVER_EPUBLIC_KEY:
			strcpy(name, "TLS_SET_SERVER_EPUBLIC_KEY");
			break;

		case TODRV_HSE_CMD_TLS_RENEW_KEYS_ECDHE:
			strcpy(name, "TLS_RENEW_KEYS_ECDHE");
			break;

		case TODRV_HSE_CMD_TLS_CALCULATE_FINISHED:
			strcpy(name, "TLS_CALCULATE_FINISHED");
			break;

		case TODRV_HSE_CMD_TLS_RESET:
			strcpy(name, "TLS_RESET");
			break;

		case TODRV_HSE_CMD_TLS_SET_MODE:
			strcpy(name, "TLS_SET_MODE");
			break;

		case TODRV_HSE_CMD_TLS_SET_CONFIG:
			strcpy(name, "TLS_SET_CONFIG");
			break;

		case TODRV_HSE_CMD_TLS_SET_SESSION:
			strcpy(name, "TLS_SET_SESSION");
			break;

		case TODRV_HSE_CMD_TLS_SET_CONNECTION_ID_EXT_ID:
			strcpy(name, "TLS_SET_CONNECTION_ID_EXT_ID");
			break;

		case TODRV_HSE_CMD_TLS_GET_CLIENT_HELLO:
			strcpy(name, "TLS_GET_CLIENT_HELLO");
			break;

		case TODRV_HSE_CMD_TLS_GET_CLIENT_HELLO_INIT:
			strcpy(name, "TLS_GET_CLIENT_HELLO_INIT");
			break;

		case TODRV_HSE_CMD_TLS_GET_CLIENT_HELLO_UPDATE:
			strcpy(name, "TLS_GET_CLIENT_HELLO_UPDATE");
			break;

		case TODRV_HSE_CMD_TLS_GET_CLIENT_HELLO_FINAL:
			strcpy(name, "TLS_GET_CLIENT_HELLO_FINAL");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_HELLO_VERIFY_REQUEST:
			strcpy(name, "TLS_HANDLE_HELLO_VERIFY_REQUEST");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO:
			strcpy(name, "TLS_HANDLE_SERVER_HELLO");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO_INIT:
			strcpy(name, "TLS_HANDLE_SERVER_HELLO_INIT");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO_UPDATE:
			strcpy(name, "TLS_HANDLE_SERVER_HELLO_UPDATE");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO_FINAL:
			strcpy(name, "TLS_HANDLE_SERVER_HELLO_FINAL");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_SERVER_CERTIFICATE:
			strcpy(name, "TLS_HANDLE_SERVER_CERTIFICATE");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_SERVER_CERTIFICATE_INIT:
			strcpy(name, "TLS_HANDLE_SERVER_CERTIFICATE_INIT");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_SERVER_CERTIFICATE_UPDATE:
			strcpy(name, "TLS_HANDLE_SERVER_CERTIFICATE_UPDATE");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_SERVER_CERTIFICATE_FINAL:
			strcpy(name, "TLS_HANDLE_SERVER_CERTIFICATE_FINAL");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_SERVER_KEY_EXCHANGE:
			strcpy(name, "TLS_HANDLE_SERVER_KEY_EXCHANGE");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_SERVER_KEY_EXCHANGE_INIT:
			strcpy(name, "TLS_HANDLE_SERVER_KEY_EXCHANGE_INIT");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_SERVER_KEY_EXCHANGE_UPDATE:
			strcpy(name, "TLS_HANDLE_SERVER_KEY_EXCHANGE_UPDATE");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_SERVER_KEY_EXCHANGE_FINAL:
			strcpy(name, "TLS_HANDLE_SERVER_KEY_EXCHANGE_FINAL");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_CERTIFICATE_REQUEST:
			strcpy(name, "TLS_HANDLE_CERTIFICATE_REQUEST");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO_DONE:
			strcpy(name, "TLS_HANDLE_SERVER_HELLO_DONE");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_MEDIATOR_CERTIFICATE:
			strcpy(name, "TLS_HANDLE_MEDIATOR_CERTIFICATE");
			break;

		case TODRV_HSE_CMD_TLS_GET_CERTIFICATE:
			strcpy(name, "TLS_GET_CERTIFICATE");
			break;

		case TODRV_HSE_CMD_TLS_GET_CERTIFICATE_INIT:
			strcpy(name, "TLS_GET_CERTIFICATE_INIT");
			break;

		case TODRV_HSE_CMD_TLS_GET_CERTIFICATE_UPDATE:
			strcpy(name, "TLS_GET_CERTIFICATE_UPDATE");
			break;

		case TODRV_HSE_CMD_TLS_GET_CERTIFICATE_FINAL:
			strcpy(name, "TLS_GET_CERTIFICATE_FINAL");
			break;

		case TODRV_HSE_CMD_TLS_GET_CLIENT_KEY_EXCHANGE:
			strcpy(name, "TLS_GET_CLIENT_KEY_EXCHANGE");
			break;

		case TODRV_HSE_CMD_TLS_GET_CERTIFICATE_VERIFY:
			strcpy(name, "TLS_GET_CERTIFICATE_VERIFY");
			break;

		case TODRV_HSE_CMD_TLS_GET_CHANGE_CIPHER_SPEC:
			strcpy(name, "TLS_GET_CHANGE_CIPHER_SPEC");
			break;

		case TODRV_HSE_CMD_TLS_GET_FINISHED:
			strcpy(name, "TLS_GET_FINISHED");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_CHANGE_CIPHER_SPEC:
			strcpy(name, "TLS_HANDLE_CHANGE_CIPHER_SPEC");
			break;

		case TODRV_HSE_CMD_TLS_HANDLE_FINISHED:
			strcpy(name, "TLS_HANDLE_FINISHED");
			break;

		case TODRV_HSE_CMD_TLS_GET_CERTIFICATE_SLOT:
			strcpy(name, "TLS_GET_CERTIFICATE_SLOT");
			break;

		case TODRV_HSE_CMD_TLS_SECURE_MESSAGE:
			strcpy(name, "TLS_SECURE_MESSAGE");
			break;

		case TODRV_HSE_CMD_TLS_SECURE_MESSAGE_INIT:
			strcpy(name, "TLS_SECURE_MESSAGE_INIT");
			break;

		case TODRV_HSE_CMD_TLS_SECURE_MESSAGE_UPDATE:
			strcpy(name, "TLS_SECURE_MESSAGE_UPDATE");
			break;

		case TODRV_HSE_CMD_TLS_SECURE_MESSAGE_FINAL:
			strcpy(name, "TLS_SECURE_MESSAGE_FINAL");
			break;

		case TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE:
			strcpy(name, "TLS_UNSECURE_MESSAGE");
			break;

		case TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE_INIT:
			strcpy(name, "TLS_UNSECURE_MESSAGE_INIT");
			break;

		case TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE_UPDATE:
			strcpy(name, "TLS_UNSECURE_MESSAGE_UPDATE");
			break;

		case TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE_FINAL:
			strcpy(name, "TLS_UNSECURE_MESSAGE_FINAL");
			break;

		case TODRV_HSE_CMD_SECURE_MESSAGE:
			strcpy(name, "SECURE_MESSAGE");
			break;

		case TODRV_HSE_CMD_SECURE_MESSAGE_INIT:
			strcpy(name, "SECURE_MESSAGE_INIT");
			break;

		case TODRV_HSE_CMD_SECURE_MESSAGE_UPDATE:
			strcpy(name, "SECURE_MESSAGE_UPDATE");
			break;

		case TODRV_HSE_CMD_SECURE_MESSAGE_FINAL:
			strcpy(name, "SECURE_MESSAGE_FINAL");
			break;

		case TODRV_HSE_CMD_UNSECURE_MESSAGE:
			strcpy(name, "UNSECURE_MESSAGE");
			break;

		case TODRV_HSE_CMD_UNSECURE_MESSAGE_INIT:
			strcpy(name, "UNSECURE_MESSAGE_INIT");
			break;

		case TODRV_HSE_CMD_UNSECURE_MESSAGE_UPDATE:
			strcpy(name, "UNSECURE_MESSAGE_UPDATE");
			break;

		case TODRV_HSE_CMD_UNSECURE_MESSAGE_FINAL:
			strcpy(name, "UNSECURE_MESSAGE_FINAL");
			break;

		case TODRV_HSE_CMD_LORA_GET_APPEUI:
			strcpy(name, "LORA_GET_APPEUI");
			break;

		case TODRV_HSE_CMD_LORA_GET_DEVEUI:
			strcpy(name, "LORA_GET_DEVEUI");
			break;

		case TODRV_HSE_CMD_LORA_COMPUTE_MIC:
			strcpy(name, "LORA_COMPUTE_MIC");
			break;

		case TODRV_HSE_CMD_LORA_ENCRYPT_PAYLOAD:
			strcpy(name, "LORA_ENCRYPT_PAYLOAD");
			break;

		case TODRV_HSE_CMD_LORA_DECRYPT_JOIN:
			strcpy(name, "LORA_DECRYPT_JOIN");
			break;

		case TODRV_HSE_CMD_LORA_COMPUTE_SHARED_KEYS:
			strcpy(name, "LORA_COMPUTE_SHARED_KEYS");
			break;

		case TODRV_HSE_CMD_LORA_GET_DEVADDR:
			strcpy(name, "LORA_GET_DEVADDR");
			break;

		case TODRV_HSE_CMD_LORA_GET_JOIN_REQUEST:
			strcpy(name, "LORA_GET_JOIN_REQUEST");
			break;

		case TODRV_HSE_CMD_LORA_HANDLE_JOIN_ACCEPT:
			strcpy(name, "LORA_HANDLE_JOIN_ACCEPT");
			break;

		case TODRV_HSE_CMD_LORA_SECURE_PHYPAYLOAD:
			strcpy(name, "LORA_SECURE_PHYPAYLOAD");
			break;

		case TODRV_HSE_CMD_LORA_UNSECURE_PHYPAYLOAD:
			strcpy(name, "LORA_UNSECURE_PHYPAYLOAD");
			break;

		case TODRV_HSE_CMD_SET_PRE_PERSONALIZATION_DATA:
			strcpy(name, "SET_PRE_PERSONALIZATION_DATA");
			break;

		case TODRV_HSE_CMD_SET_NEXT_STATE:
			strcpy(name, "SET_NEXT_STATE");
			break;

		case TODRV_HSE_CMD_GET_STATE:
			strcpy(name, "GET_STATE");
			break;

		case TODRV_HSE_CMD_ADMIN_SET_SLOT:
			strcpy(name, "ADMIN_SET_SLOT");
			break;

		case TODRV_HSE_CMD_INIT_ADMIN_SESSION:
			strcpy(name, "INIT_ADMIN_SESSION");
			break;

		case TODRV_HSE_CMD_AUTH_ADMIN_SESSION:
			strcpy(name, "AUTH_ADMIN_SESSION");
			break;

		case TODRV_HSE_CMD_FINI_ADMIN_SESSION:
			strcpy(name, "FINI_ADMIN_SESSION");
			break;

		case TODRV_HSE_CMD_ADMIN_COMMAND:
			strcpy(name, "ADMIN_COMMAND");
			break;

		case TODRV_HSE_CMD_ADMIN_COMMAND_WITH_RESPONSE:
			strcpy(name, "ADMIN_COMMAND_WITH_RESPONSE");
			break;

		case TODRV_HSE_CMD_LOCK:
			strcpy(name, "LOCK");
			break;

		case TODRV_HSE_CMD_UNLOCK:
			strcpy(name, "UNLOCK");
			break;

		case TODRV_HSE_CMD_SET_AES_KEY:
			strcpy(name, "SET_AES_KEY");
			break;

		case TODRV_HSE_CMD_SET_HMAC_KEY:
			strcpy(name, "SET_HMAC_KEY");
			break;

		case TODRV_HSE_CMD_SET_CMAC_KEY:
			strcpy(name, "SET_CMAC_KEY");
			break;

		case TODRV_HSE_CMD_SECLINK_ARC4:
			strcpy(name, "SECLINK_ARC4");
			break;

		case TODRV_HSE_CMD_SECLINK_ARC4_GET_IV:
			strcpy(name, "SECLINK_ARC4_GET_IV");
			break;

		case TODRV_HSE_CMD_SECLINK_ARC4_GET_NEW_KEY:
			strcpy(name, "SECLINK_ARC4_GET_NEW_KEY");
			break;

		case TODRV_HSE_CMD_SECLINK_AESHMAC:
			strcpy(name, "SECLINK_AESHMAC");
			break;

		case TODRV_HSE_CMD_SECLINK_AESHMAC_GET_IV:
			strcpy(name, "SECLINK_AESHMAC_GET_IV");
			break;

		case TODRV_HSE_CMD_SECLINK_AESHMAC_GET_NEW_KEYS:
			strcpy(name, "SECLINK_AESHMAC_GET_NEW_KEYS");
			break;

		case TODRV_HSE_CMD_LOADER_BCAST_GET_INFO:
			strcpy(name, "LOADER_BCAST_GET_INFO");
			break;

		case TODRV_HSE_CMD_LOADER_BCAST_RESTORE:
			strcpy(name, "LOADER_BCAST_RESTORE");
			break;

		case TODRV_HSE_CMD_LOADER_BCAST_INITIALIZE_UPGRADE:
			strcpy(name, "LOADER_BCAST_INITIALIZE_UPGRADE");
			break;

		case TODRV_HSE_CMD_LOADER_BCAST_WRITE_DATA:
			strcpy(name, "LOADER_BCAST_WRITE_DATA");
			break;

		case TODRV_HSE_CMD_LOADER_BCAST_COMMIT_RELEASE:
			strcpy(name, "LOADER_BCAST_COMMIT_RELEASE");
			break;

		case TODRV_HSE_CMD_DATA_MIGRATION:
			strcpy(name, "DATA_MIGRATION");
			break;

		case TODRV_HSE_CMD_SET_MEASURE_BOOT         :
			strcpy(name, "SET_MEASURE_BOOT         ");
			break;

		case TODRV_HSE_CMD_VALIDATE_NEW_FW_HASH     :
			strcpy(name, "VALIDATE_NEW_FW_HASH     ");
			break;

		case TODRV_HSE_CMD_COMMIT_NEW_FW_HASH       :
			strcpy(name, "COMMIT_NEW_FW_HASH       ");
			break;

		case TODRV_HSE_CMD_STORE_NEW_TRUSTED_FW_HASH:
			strcpy(name, "STORE_NEW_TRUSTED_FW_HASH");
			break;

		case TODRV_HSE_CMD_GET_BOOT_MEASUREMENT     :
			strcpy(name, "GET_BOOT_MEASUREMENT     ");
			break;

		case TODRV_HSE_CMD_GET_SE_MEASUREMENT     :
			strcpy(name, "GET_SE_MEASUREMENT     ");
			break;

		case TODRV_HSE_CMD_INVALIDATE_NEW_HASH      :
			strcpy(name, "INVALIDATE_NEW_HASH      ");
			break;

		default:
			strcpy(name,"**UNK**");
			break;
	}

}

#endif /* TODRV_HSE_DRIVER_DISABLE */

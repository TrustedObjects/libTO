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
 * @file api_nvm.c
 * @brief Secure Element NVM functions.
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
#include "TODRV_HSE_nvm.h"
#include "TOH_log.h"

#ifndef TO_DISABLE_NVM
#ifndef TO_DISABLE_API_WRITE_NVM
TODRV_HSE_NVM_API TO_ret_t TODRV_HSE_write_nvm(TODRV_HSE_ctx_t *ctx, const uint16_t offset, const void *data,
		unsigned int length, const uint8_t key[TO_AES_KEYSIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;
	const uint16_t _offset = htobe16(offset);
	uint16_t data_length = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(data_length, (uint8_t*)&_offset, sizeof(_offset));
	data_length += sizeof(_offset);
	ret |= TODRV_HSE_prepare_command_data(data_length, key, TO_AES_KEYSIZE);
	data_length += TO_AES_KEYSIZE;
	ret |= TODRV_HSE_prepare_command_data(data_length, data, length);
	data_length += length;
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_WRITE_NVM, data_length,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif

#ifndef TO_DISABLE_API_READ_NVM
TODRV_HSE_NVM_API TO_ret_t TODRV_HSE_read_nvm(TODRV_HSE_ctx_t *ctx, const uint16_t offset, void *data,
		unsigned int length, const uint8_t key[TO_AES_KEYSIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	const uint16_t _offset = htobe16(offset);
	const uint16_t _length = htobe16(length);
	uint16_t data_length = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(data_length, (uint8_t*)&_offset, sizeof(_offset));
	data_length += sizeof(_offset);
	ret |= TODRV_HSE_prepare_command_data(data_length, (uint8_t*)&_length, sizeof(_length));
	data_length += sizeof(_length);
	ret |= TODRV_HSE_prepare_command_data(data_length, key, TO_AES_KEYSIZE);
	data_length += TO_AES_KEYSIZE;
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_READ_NVM, data_length,
			(uint16_t*)&length, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(data, TODRV_HSE_response_data, length);
	return resp_status;
}
#endif

#if !defined TO_DISABLE_API_WRITE_NVM || !defined TO_DISABLE_API_READ_NVM
TODRV_HSE_NVM_API TO_ret_t TODRV_HSE_get_nvm_size(TODRV_HSE_ctx_t *ctx, uint16_t *size)
{
	TO_lib_ret_t ret;
	uint16_t resp_data_len = sizeof(uint16_t);
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_GET_NVM_SIZE, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(size, TODRV_HSE_response_data, sizeof(*size));
	*size = be16toh(*size);
	return resp_status;
}
#endif
#endif // TO_DISABLE_NVM


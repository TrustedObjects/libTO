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
 * @file api_lora.c
 * @brief Secure Element LoRa functions.
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
#include "TODRV_HSE_lora.h"
#include "TOH_log.h"

#ifndef TO_DISABLE_LORA
TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_compute_mic(TODRV_HSE_ctx_t *ctx, const uint8_t *data, uint16_t data_length,
		uint32_t address, uint8_t direction, uint32_t seq_counter,
		uint8_t mic[TO_LORA_MIC_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = TO_AES_BLOCK_SIZE + data_length + 1;
	uint16_t resp_data_len = TO_LORA_MIC_SIZE;
	static uint8_t mic_block_b0[] = {
		0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	const uint32_t _address = htole32(address);
	const uint32_t _seq_counter = htole32(seq_counter);

	(void)ctx;

	/* fills the block B0 according to lora specification */
	mic_block_b0[5] = direction;
	TO_secure_memcpy(mic_block_b0 + 6, (uint8_t*)&_address, sizeof(_address));
	TO_secure_memcpy(mic_block_b0 + 10, (uint8_t*)&_seq_counter, sizeof(_seq_counter));
	mic_block_b0[15] = data_length % (1 << 8);

	ret = TODRV_HSE_prepare_command_data_byte(0, 0x01); /* for a non join-request
						      mic, this field
						      shouldn't be null */
	ret |= TODRV_HSE_prepare_command_data(1, mic_block_b0, sizeof(mic_block_b0));
	ret |= TODRV_HSE_prepare_command_data(1 + sizeof(mic_block_b0),
			data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LORA_COMPUTE_MIC, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(mic, TODRV_HSE_response_data, TO_LORA_MIC_SIZE);
	return resp_status;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_encrypt_payload(TODRV_HSE_ctx_t *ctx, const uint8_t *data,
		uint16_t data_length, const uint8_t *fport,
		uint32_t address, uint8_t direction, uint32_t seq_counter,
		uint8_t *enc_buffer)
{
	int i, ret;
	TO_se_ret_t resp_status;
	uint8_t block_count = (data_length + (TO_AES_BLOCK_SIZE
				- (data_length % TO_AES_BLOCK_SIZE)))
		/ TO_AES_BLOCK_SIZE; /* ceil data length / AES block size
					   to compute the block count with
					   padding for AES encryption
					   according to LoRa specification */
	uint16_t cmd_len = block_count * TO_AES_BLOCK_SIZE + 1;
	uint16_t resp_data_len = block_count * TO_AES_BLOCK_SIZE;
	const uint32_t _address = htole32(address);
	const uint32_t _seq_counter = htole32(seq_counter);

	(void)ctx;

	ret = TODRV_HSE_set_command_data(0, 0x00, cmd_len);
	ret |= TODRV_HSE_prepare_command_data_byte(0, *fport);
	for (i = 0; i < block_count; i++) {
		ret |= TODRV_HSE_prepare_command_data_byte(
				1 + i * TO_AES_BLOCK_SIZE,
				0x01);
		ret |= TODRV_HSE_prepare_command_data_byte(
				1 + i * TO_AES_BLOCK_SIZE + 5,
				direction);
		ret |= TODRV_HSE_prepare_command_data(
				1 + i * TO_AES_BLOCK_SIZE + 6,
				(uint8_t*)&_address, sizeof(_address));
		ret |= TODRV_HSE_prepare_command_data(
				1 + i * TO_AES_BLOCK_SIZE + 10,
				(uint8_t*)&_seq_counter, sizeof(_seq_counter));
		ret |= TODRV_HSE_prepare_command_data_byte(
				1 + i * TO_AES_BLOCK_SIZE + 15,
				(uint8_t)(i + 1));
	}
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LORA_ENCRYPT_PAYLOAD,
			cmd_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	/* Applies xor function to finalize the encryption */
	for (i = 0; i < data_length; i++)
		enc_buffer[i] = data[i] ^ TODRV_HSE_response_data[i];
	return resp_status;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_join_compute_mic(TODRV_HSE_ctx_t *ctx, const uint8_t *data,
		uint16_t data_length, uint8_t mic[TO_LORA_MIC_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = data_length + 1;
	uint16_t resp_data_len = TO_LORA_MIC_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, 0x00); /* for a join-request
						      message, this field
						      should be null to inform
						      the secure element that it
						      has to use the application
						      key */
	ret |= TODRV_HSE_prepare_command_data(1, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LORA_COMPUTE_MIC, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(mic, TODRV_HSE_response_data, TO_LORA_MIC_SIZE);
	return resp_status;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_decrypt_join(TODRV_HSE_ctx_t *ctx, const uint8_t *data, uint16_t data_length,
		uint8_t *dec_buffer)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LORA_DECRYPT_JOIN, data_length,
			&data_length, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(dec_buffer, TODRV_HSE_response_data, data_length);
	return resp_status;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_compute_shared_keys(TODRV_HSE_ctx_t *ctx, const uint8_t *app_nonce,
		const uint8_t *net_id, uint16_t dev_nonce)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	/* Send the block to derive the network shared key (only 1 byte
	differs from the block needed to derive application shared key) */
	ret = TODRV_HSE_set_command_data(0, 0x00, TO_AES_BLOCK_SIZE);
	ret |= TODRV_HSE_prepare_command_data_byte(0, 0x01);
	ret |= TODRV_HSE_prepare_command_data(1, app_nonce,
			TO_LORA_APPNONCE_SIZE);
	ret |= TODRV_HSE_prepare_command_data(1 + TO_LORA_APPNONCE_SIZE, net_id,
			TO_LORA_NETID_SIZE);
	ret |= TODRV_HSE_prepare_command_data(1 + TO_LORA_APPNONCE_SIZE
			+ TO_LORA_NETID_SIZE, (unsigned char *)&dev_nonce,
			TO_LORA_DEVNONCE_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LORA_COMPUTE_SHARED_KEYS,
			TO_AES_BLOCK_SIZE, &resp_data_len, &resp_status);

	return ret | resp_status;
}
#endif /* TO_DISABLE_LORA */

#if !defined(TO_DISABLE_LORA) || !defined(TO_DISABLE_LORA_OPTIMIZED)
TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_set_app_eui(TODRV_HSE_ctx_t *ctx, const uint8_t app_eui[TO_LORA_APPEUI_SIZE] __attribute__((unused)))
{
	(void)ctx;

	return TO_NOT_IMPLEMENTED;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_get_app_eui(TODRV_HSE_ctx_t *ctx, uint8_t app_eui[TO_LORA_APPEUI_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_LORA_APPEUI_SIZE;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LORA_GET_APPEUI, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(app_eui, TODRV_HSE_response_data, TO_LORA_APPEUI_SIZE);
	return resp_status;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_set_dev_eui(TODRV_HSE_ctx_t *ctx, const uint8_t dev_eui[TO_LORA_DEVEUI_SIZE] __attribute__((unused)))
{
	(void)ctx;

	return TO_NOT_IMPLEMENTED;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_get_dev_eui(TODRV_HSE_ctx_t *ctx, uint8_t dev_eui[TO_LORA_DEVEUI_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_LORA_DEVEUI_SIZE;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LORA_GET_DEVEUI, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(dev_eui, TODRV_HSE_response_data, TO_LORA_DEVEUI_SIZE);
	return resp_status;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_get_dev_addr(TODRV_HSE_ctx_t *ctx, uint8_t dev_addr[TO_LORA_DEVADDR_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_LORA_DEVADDR_SIZE;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LORA_GET_DEVADDR, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(dev_addr, TODRV_HSE_response_data, TO_LORA_DEVADDR_SIZE);
	return resp_status;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_set_dev_addr(TODRV_HSE_ctx_t *ctx, const uint8_t dev_addr[TO_LORA_DEVADDR_SIZE] __attribute__((unused)))
{
	(void)ctx;

	return TO_NOT_IMPLEMENTED;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_set_appkey(TODRV_HSE_ctx_t *ctx, const uint8_t appkey[TO_LORA_APPKEY_SIZE] __attribute__((unused)))
{
	(void)ctx;

	return TO_NOT_IMPLEMENTED;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_set_appskey(TODRV_HSE_ctx_t *ctx, const uint8_t appskey[TO_LORA_APPSKEY_SIZE] __attribute__((unused)))
{
	(void)ctx;

	return TO_NOT_IMPLEMENTED;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_set_nwkskey(TODRV_HSE_ctx_t *ctx, const uint8_t nwkskey[TO_LORA_NWKSKEY_SIZE] __attribute__((unused)))
{
	(void)ctx;

	return TO_NOT_IMPLEMENTED;
}
#endif /* !defined(TO_DISABLE_LORA) || !defined(TO_DISABLE_LORA_OPTIMIZED) */

#ifndef TO_DISABLE_LORA_OPTIMIZED
TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_get_join_request_phypayload(TODRV_HSE_ctx_t *ctx, 
		uint8_t data[TO_LORA_JOINREQUEST_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_LORA_JOINREQUEST_SIZE;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LORA_GET_JOIN_REQUEST, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(data, TODRV_HSE_response_data, TO_LORA_JOINREQUEST_SIZE);
	return resp_status;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_handle_join_accept_phypayload(TODRV_HSE_ctx_t *ctx, const uint8_t *data,
		const uint16_t data_length,
		uint8_t dec_buffer[TO_LORA_JOINACCEPT_CLEAR_MAXSIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = data_length - TO_LORA_MIC_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LORA_HANDLE_JOIN_ACCEPT, data_length,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	if (resp_data_len > TO_LORA_JOINACCEPT_CLEAR_MAXSIZE)
		return TORSP_INVALID_LEN;

	TO_secure_memcpy(dec_buffer, TODRV_HSE_response_data, resp_data_len);
	return resp_status;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_secure_phypayload(TODRV_HSE_ctx_t *ctx, const uint8_t mhdr,
		const uint8_t fctrl, const uint8_t *fopts, const uint8_t fport,
		const uint8_t *payload, const int payload_size,
		uint8_t *enc_buffer)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t data_length = 0;
	uint16_t resp_data_len;
	uint8_t fopts_len = fctrl & 0xf;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(data_length++, mhdr);
	ret |= TODRV_HSE_prepare_command_data_byte(data_length++, fctrl);

	/* FOpts is optional */
	if (fopts_len > 0) {
		if (fopts == NULL) {
			TOH_LOG_ERR("%s: Missing frame options\n", __func__);
			return TO_ERROR;
		}
		ret |= TODRV_HSE_prepare_command_data(data_length, fopts,
				fopts_len);
		data_length += fopts_len;
	}

	/* Payload is optional, no FPort if missing */
	if (payload_size > 0) {
		if (payload == NULL) {
			TOH_LOG_ERR("%s: Missing payload\n", __func__);
			return TO_ERROR;
		}
		ret |= TODRV_HSE_prepare_command_data_byte(data_length++, fport);
		ret |= TODRV_HSE_prepare_command_data(data_length, payload,
				payload_size);
		data_length += payload_size;
	}

	if (TO_OK != ret)
		return ret;
	resp_data_len = data_length + TO_LORA_DEVADDR_SIZE
		+ TO_LORA_FCNT_SIZE / 2 + TO_LORA_MIC_SIZE;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LORA_SECURE_PHYPAYLOAD, data_length,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(enc_buffer, TODRV_HSE_response_data, resp_data_len);
	return resp_status;
}

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_unsecure_phypayload(TODRV_HSE_ctx_t *ctx, const uint8_t *data,
		const uint16_t data_length, uint8_t *dec_buffer)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = data_length - TO_LORA_MIC_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, data_length);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_LORA_UNSECURE_PHYPAYLOAD, data_length,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(dec_buffer, TODRV_HSE_response_data, resp_data_len);
	return resp_status;
}
#endif /* TO_DISABLE_LORA_OPTIMIZED */

#endif /* TODRV_HSE_DRIVER_DISABLE */


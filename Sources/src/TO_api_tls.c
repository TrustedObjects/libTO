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
 * @file api_tls.c
 * @brief Secure Element TLS functions.
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
#include "TODRV_HSE_tls.h"
#include "TOH_log.h"

#ifndef TO_DISABLE_TLS
TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_set_tls_server_random(TODRV_HSE_ctx_t *ctx,  uint8_t random[TO_TLS_RANDOM_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, random, TO_TLS_RANDOM_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SET_SERVER_RANDOM,
			TO_TLS_RANDOM_SIZE, &resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_set_tls_server_eph_pub_key(TODRV_HSE_ctx_t *ctx, uint8_t key_index,
		uint8_t ecc_params[TO_TLS_SERVER_PARAMS_SIZE],
		uint8_t signature[TO_SIGNATURE_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t cmd_len = TO_INDEX_SIZE + TO_TLS_SERVER_PARAMS_SIZE +
		TO_SIGNATURE_SIZE;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_prepare_command_data(TO_INDEX_SIZE, ecc_params,
			TO_TLS_SERVER_PARAMS_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_prepare_command_data(
			TO_INDEX_SIZE + TO_TLS_SERVER_PARAMS_SIZE,
			signature, TO_SIGNATURE_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SET_SERVER_EPUBLIC_KEY, cmd_len,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_get_tls_random_and_store(TODRV_HSE_ctx_t *ctx,
		uint8_t timestamp[TO_TIMESTAMP_SIZE],
		uint8_t random[TO_TLS_RANDOM_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_TLS_RANDOM_SIZE - TO_TIMESTAMP_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, timestamp, TO_TIMESTAMP_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_RANDOM_AND_STORE,
			TO_TIMESTAMP_SIZE, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(random, timestamp, TO_TIMESTAMP_SIZE);
	TO_secure_memcpy(random + TO_TIMESTAMP_SIZE, TODRV_HSE_response_data,
			TO_TLS_RANDOM_SIZE - TO_TIMESTAMP_SIZE);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_get_tls_master_secret(TODRV_HSE_ctx_t *ctx,
		uint8_t master_secret[TO_TLS_MASTER_SECRET_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_TLS_MASTER_SECRET_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, 0x00);
	if (ret != TO_OK)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_MASTER_SECRET, 1,
			&resp_data_len, &resp_status);
	if ((ret != TO_OK) || (TORSP_SUCCESS != resp_status))
		return ret | resp_status;

	TO_secure_memcpy(master_secret, TODRV_HSE_response_data,
			TO_TLS_MASTER_SECRET_SIZE);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_renew_tls_keys_ecdhe(TODRV_HSE_ctx_t *ctx, const uint8_t kpriv_index,
		const uint8_t kpub_index, const uint8_t enc_key_index,
		const uint8_t dec_key_index)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, kpriv_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_prepare_command_data_byte(1, kpub_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_prepare_command_data_byte(2, enc_key_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_prepare_command_data_byte(3, dec_key_index);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_RENEW_KEYS_ECDHE, 4,
			&resp_data_len, &resp_status);

	return ret | resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_calculate_finished(TODRV_HSE_ctx_t *ctx, const int from,
		const uint8_t handshake_hash[TO_HASH_SIZE],
		uint8_t finished[TO_TLS_FINISHED_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_TLS_FINISHED_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, from);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_prepare_command_data(1, handshake_hash, TO_HASH_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_CALCULATE_FINISHED,
			1 + TO_HASH_SIZE, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(finished, TODRV_HSE_response_data, TO_TLS_FINISHED_SIZE);
	return resp_status;
}
#endif

#ifndef TO_DISABLE_TLS_OPTIMIZED
TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_reset(TODRV_HSE_ctx_t *ctx)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_RESET, 0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_set_mode(TODRV_HSE_ctx_t *ctx, const TO_tls_mode_t mode)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, mode);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SET_MODE,
			sizeof(uint8_t), &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_set_config(TODRV_HSE_ctx_t *ctx, const TO_tls_config_id_t config_id,
		const uint8_t *config, const uint16_t config_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;
	uint16_t _config_id = htobe16(config_id);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, (uint8_t*)&_config_id, sizeof(uint16_t));
	ret |= TODRV_HSE_prepare_command_data(sizeof(uint16_t), config, config_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SET_CONFIG,
			sizeof(uint16_t) + config_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_set_session(TODRV_HSE_ctx_t *ctx, const uint8_t session)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, session);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SET_SESSION,
			sizeof(uint8_t), &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_set_cid_ext_id(TODRV_HSE_ctx_t *ctx, const TO_tls_extension_t cid_ext_id)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;
	TO_tls_extension_t _cid_ext_id = htobe16(cid_ext_id);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, (uint8_t*)&_cid_ext_id, sizeof(_cid_ext_id));
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SET_CONNECTION_ID_EXT_ID,
			sizeof(_cid_ext_id), &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_client_hello(TODRV_HSE_ctx_t *ctx, const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		uint8_t *client_hello, uint16_t *client_hello_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TODRV_HSE_RSP_MAXSIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, timestamp, TO_TIMESTAMP_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_CLIENT_HELLO,
			TO_TIMESTAMP_SIZE, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(client_hello, TODRV_HSE_response_data, resp_data_len);
	*client_hello_len = resp_data_len;
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_client_hello_ext(TODRV_HSE_ctx_t *ctx, const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		const uint8_t *ext_data, uint8_t ext_length,
		uint8_t *client_hello, uint16_t *client_hello_len)
{
	uint16_t offset = 0;
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TODRV_HSE_RSP_MAXSIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(offset, timestamp, TO_TIMESTAMP_SIZE);
	if (TO_OK != ret)
		return ret;
	offset += TO_TIMESTAMP_SIZE;

	if (ext_length) {
		ret = TODRV_HSE_prepare_command_data(offset, &ext_length, sizeof ext_length);
		if (TO_OK != ret)
			return ret;
		offset += sizeof ext_length;

		ret = TODRV_HSE_prepare_command_data(offset, ext_data, ext_length);
		if (TO_OK != ret)
			return ret;
		offset += ext_length;
	}

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_CLIENT_HELLO,
			offset, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(client_hello, TODRV_HSE_response_data, resp_data_len);
	*client_hello_len = resp_data_len;
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_client_hello_init(TODRV_HSE_ctx_t *ctx,
		const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		const uint8_t *ext_data, uint8_t ext_length,
		uint16_t *client_hello_len, uint8_t *final_flag)
{
	uint16_t offset = 0;
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = sizeof *client_hello_len + sizeof *final_flag;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(offset, timestamp, TO_TIMESTAMP_SIZE);
	if (TO_OK != ret)
		return ret;
	offset += TO_TIMESTAMP_SIZE;
	ret = TODRV_HSE_prepare_command_data(offset, &ext_length, sizeof ext_length);
	if (TO_OK != ret)
		return ret;
	offset += sizeof ext_length;
	ret = TODRV_HSE_prepare_command_data(offset, ext_data, ext_length);
	if (TO_OK != ret)
		return ret;
	offset += ext_length;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_CLIENT_HELLO_INIT,
			offset, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	offset = 0;
	*final_flag = TODRV_HSE_response_data[0];
	offset++;

	uint16_t be16_val;
	TO_secure_memcpy(&be16_val, TODRV_HSE_response_data + offset, sizeof be16_val);
	*client_hello_len = be16toh(be16_val);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_client_hello_update(TODRV_HSE_ctx_t *ctx,
		uint8_t *data, uint16_t *part_len, uint8_t *final_flag)
{
	uint16_t offset = 0;
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	*part_len = TODRV_HSE_RSP_MAXSIZE;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_CLIENT_HELLO_UPDATE,
			offset, part_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*final_flag = TODRV_HSE_response_data[0];
	offset = 1;
	*part_len -= offset;
	TO_secure_memcpy(data, TODRV_HSE_response_data + offset, *part_len);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_client_hello_final(TODRV_HSE_ctx_t *ctx,
		uint8_t *data)
{
	uint16_t offset = 0;
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t last_len = TODRV_HSE_RSP_MAXSIZE;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_CLIENT_HELLO_FINAL,
			offset, &last_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(data, TODRV_HSE_response_data, last_len);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_hello_verify_request(TODRV_HSE_ctx_t *ctx, const uint8_t *hello_verify_request,
		const uint32_t hello_verify_request_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, hello_verify_request,
			hello_verify_request_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_HELLO_VERIFY_REQUEST,
			hello_verify_request_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_hello(TODRV_HSE_ctx_t *ctx, const uint8_t *server_hello,
		const uint32_t server_hello_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, server_hello, server_hello_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO,
			server_hello_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_hello_init(TODRV_HSE_ctx_t *ctx,
		const uint16_t server_hello_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	uint16_t be16_val = htobe16(server_hello_len);
	ret = TODRV_HSE_prepare_command_data(0, (unsigned char*)&be16_val, sizeof be16_val);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO_INIT,
			sizeof server_hello_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_hello_update(TODRV_HSE_ctx_t *ctx,
		const uint8_t *data, const uint16_t part_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, part_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO_UPDATE,
			part_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_hello_final(TODRV_HSE_ctx_t *ctx,
		const uint8_t *data, const uint16_t last_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, last_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO_FINAL,
			last_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_certificate(TODRV_HSE_ctx_t *ctx, const uint8_t *server_certificate,
		const uint32_t server_certificate_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, server_certificate,
			server_certificate_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_SERVER_CERTIFICATE,
			server_certificate_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_certificate_init(TODRV_HSE_ctx_t *ctx,
		const uint8_t *server_certificate_init,
		const uint32_t server_certificate_init_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, server_certificate_init,
			server_certificate_init_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_SERVER_CERTIFICATE_INIT,
			server_certificate_init_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_certificate_update(TODRV_HSE_ctx_t *ctx,
		const uint8_t *server_certificate_update,
		const uint32_t server_certificate_update_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, server_certificate_update,
			server_certificate_update_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_SERVER_CERTIFICATE_UPDATE,
			server_certificate_update_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_certificate_final(TODRV_HSE_ctx_t *ctx)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_SERVER_CERTIFICATE_FINAL,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_key_exchange(TODRV_HSE_ctx_t *ctx, const uint8_t *server_key_exchange,
		const uint32_t server_key_exchange_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, server_key_exchange,
			server_key_exchange_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_SERVER_KEY_EXCHANGE,
			server_key_exchange_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_key_exchange_init(TODRV_HSE_ctx_t *ctx,
		const uint8_t *server_key_exchange_init,
		const uint32_t server_key_exchange_init_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, server_key_exchange_init,
			server_key_exchange_init_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_SERVER_KEY_EXCHANGE_INIT,
			server_key_exchange_init_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_key_exchange_update(TODRV_HSE_ctx_t *ctx,
		const uint8_t *server_key_exchange_update,
		const uint32_t server_key_exchange_update_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, server_key_exchange_update,
			server_key_exchange_update_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_SERVER_KEY_EXCHANGE_UPDATE,
			server_key_exchange_update_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_key_exchange_final(TODRV_HSE_ctx_t *ctx)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_SERVER_KEY_EXCHANGE_FINAL,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_certificate_request(TODRV_HSE_ctx_t *ctx, const uint8_t *certificate_request,
		const uint32_t certificate_request_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, certificate_request,
			certificate_request_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_CERTIFICATE_REQUEST,
			certificate_request_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_server_hello_done(TODRV_HSE_ctx_t *ctx,
		const uint8_t *server_hello_done,
		const uint32_t server_hello_done_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, server_hello_done, server_hello_done_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_SERVER_HELLO_DONE,
			server_hello_done_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_mediator_certificate(TODRV_HSE_ctx_t *ctx,
		const uint8_t *mediator_certificate,
		const uint32_t mediator_certificate_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, mediator_certificate, mediator_certificate_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_MEDIATOR_CERTIFICATE,
			mediator_certificate_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_certificate(TODRV_HSE_ctx_t *ctx,
		uint8_t *certificate, uint16_t *certificate_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TODRV_HSE_RSP_MAXSIZE;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_CERTIFICATE,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(certificate, TODRV_HSE_response_data, resp_data_len);
	*certificate_len = resp_data_len;
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_certificate_init(TODRV_HSE_ctx_t *ctx,
		uint8_t *certificate, uint16_t *certificate_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TODRV_HSE_RSP_MAXSIZE;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_CERTIFICATE_INIT,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(certificate, TODRV_HSE_response_data, resp_data_len);
	if (certificate_len) {
		*certificate_len = resp_data_len;
	}
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_certificate_update(TODRV_HSE_ctx_t *ctx,
		uint8_t *certificate, uint16_t *certificate_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TODRV_HSE_LIB_INTERNAL_IO_BUFFER_SIZE - TO_DTLS_HANDSHAKE_HEADER_MAXSIZE;
	uint16_t len = htobe16(resp_data_len);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, (unsigned char*)&len, sizeof(uint16_t));
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_CERTIFICATE_UPDATE,
			sizeof(uint16_t), &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(certificate, TODRV_HSE_response_data, resp_data_len);
	*certificate_len = resp_data_len;
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_certificate_final(TODRV_HSE_ctx_t *ctx)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_CERTIFICATE_FINAL,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_client_key_exchange(TODRV_HSE_ctx_t *ctx,
		uint8_t *client_key_exchange, uint16_t *client_key_exchange_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TODRV_HSE_RSP_MAXSIZE;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_CLIENT_KEY_EXCHANGE,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(client_key_exchange, TODRV_HSE_response_data, resp_data_len);
	*client_key_exchange_len = resp_data_len;
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_certificate_verify(TODRV_HSE_ctx_t *ctx,
		uint8_t *certificate_verify,
		uint16_t *certificate_verify_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TODRV_HSE_RSP_MAXSIZE;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_CERTIFICATE_VERIFY,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(certificate_verify, TODRV_HSE_response_data, resp_data_len);
	*certificate_verify_len = resp_data_len;
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_change_cipher_spec(TODRV_HSE_ctx_t *ctx,
		uint8_t *change_cipher_spec,
		uint16_t *change_cipher_spec_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_TLS_CHANGE_CIPHER_SPEC_SIZE;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_CHANGE_CIPHER_SPEC,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	if (resp_data_len != TO_TLS_CHANGE_CIPHER_SPEC_SIZE)
		return TORSP_INVALID_LEN;

	TO_secure_memcpy(change_cipher_spec, TODRV_HSE_response_data, resp_data_len);
	if (change_cipher_spec_len) {
		*change_cipher_spec_len = resp_data_len;
	}
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_finished(TODRV_HSE_ctx_t *ctx,
		uint8_t *finished,
		uint16_t *finished_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TODRV_HSE_RSP_MAXSIZE;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_FINISHED,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(finished, TODRV_HSE_response_data, resp_data_len);
	if (finished_len) {
		*finished_len = resp_data_len;
	}
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_change_cipher_spec(TODRV_HSE_ctx_t *ctx,
		const uint8_t *change_cipher_spec,
		const uint32_t change_cipher_spec_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, change_cipher_spec,
			TO_TLS_CHANGE_CIPHER_SPEC_SIZE);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_CHANGE_CIPHER_SPEC,
			change_cipher_spec_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_handle_finished(TODRV_HSE_ctx_t *ctx,
		const uint8_t *finished,
		const uint32_t finished_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, finished, finished_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_HANDLE_FINISHED,
			finished_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_get_certificate_slot(
		TODRV_HSE_ctx_t *ctx,
		uint8_t *slot)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = sizeof(*slot);

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_CERTIFICATE_SLOT,
			0, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(slot, TODRV_HSE_response_data, resp_data_len);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_message(TODRV_HSE_ctx_t *ctx,
		const uint8_t *header, const uint16_t header_len,
		const uint8_t* data, const uint16_t data_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t *cryptogram, uint16_t *cryptogram_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len;
	uint16_t padding_len;

	(void)ctx;

	padding_len = TO_AES_BLOCK_SIZE - ((data_len + 1) % TO_AES_BLOCK_SIZE);
	if (padding_len == TO_AES_BLOCK_SIZE) {
		padding_len = 0;
	}
	resp_data_len = TO_INITIALVECTOR_SIZE + data_len + TO_HMAC_SIZE
		+ padding_len + 1;

	ret = TODRV_HSE_prepare_command_data(0, header, header_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_prepare_command_data(header_len, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SECURE_MESSAGE,
			header_len + data_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(initial_vector, TODRV_HSE_response_data, TO_INITIALVECTOR_SIZE);
	*cryptogram_len = resp_data_len - TO_INITIALVECTOR_SIZE;
	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data + TO_INITIALVECTOR_SIZE,
			*cryptogram_len);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_message_init(TODRV_HSE_ctx_t *ctx,
		const uint8_t *header, const uint16_t header_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_INITIALVECTOR_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, header, header_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SECURE_MESSAGE_INIT, header_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	if (resp_data_len != TO_INITIALVECTOR_SIZE)
		return TORSP_INVALID_LEN;

	TO_secure_memcpy(initial_vector, TODRV_HSE_response_data, TO_INITIALVECTOR_SIZE);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_message_update(TODRV_HSE_ctx_t *ctx, const uint8_t* data, const uint16_t data_len,
		uint8_t *cryptogram)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = data_len;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SECURE_MESSAGE_UPDATE, data_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	if (resp_data_len != data_len)
		return TORSP_INVALID_LEN;

	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data, data_len);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_message_final(TODRV_HSE_ctx_t *ctx, const uint8_t* data, const uint16_t data_len,
		uint8_t *cryptogram, uint16_t *cryptogram_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_AES_BLOCK_SIZE + TO_HMAC_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SECURE_MESSAGE_FINAL, data_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*cryptogram_len = resp_data_len;
	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data, *cryptogram_len);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_message(TODRV_HSE_ctx_t *ctx,
		const uint8_t *header, const uint16_t header_len,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram, const uint16_t cryptogram_len,
		uint8_t *data, uint16_t *data_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = cryptogram_len - TO_HMAC_MINSIZE - 1;
	uint16_t cmd_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(cmd_len, header, header_len);
	if (TO_OK != ret)
		return ret;
	cmd_len += header_len;
	ret = TODRV_HSE_prepare_command_data(cmd_len, initial_vector,
			TO_INITIALVECTOR_SIZE);
	if (TO_OK != ret)
		return ret;
	cmd_len += TO_INITIALVECTOR_SIZE;
	ret = TODRV_HSE_prepare_command_data(cmd_len, cryptogram, cryptogram_len);
	if (TO_OK != ret)
		return ret;
	cmd_len += cryptogram_len;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE,
			cmd_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*data_len = resp_data_len;
	TO_secure_memcpy(data, TODRV_HSE_response_data, *data_len);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_message_init(TODRV_HSE_ctx_t *ctx, const uint16_t cryptogram_len,
		const uint8_t *header, const uint16_t header_len,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;
	uint16_t cmd_len = 0;
	uint16_t _cryptogram_len = htobe16(cryptogram_len);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(cmd_len, (uint8_t*)&_cryptogram_len, sizeof(uint16_t));
	if (TO_OK != ret)
		return ret;
	cmd_len += sizeof(uint16_t);
	ret = TODRV_HSE_prepare_command_data(cmd_len, header, header_len);
	if (TO_OK != ret)
		return ret;
	cmd_len += header_len;
	ret = TODRV_HSE_prepare_command_data(cmd_len, initial_vector, TO_INITIALVECTOR_SIZE);
	if (TO_OK != ret)
		return ret;
	cmd_len += TO_INITIALVECTOR_SIZE;
	ret = TODRV_HSE_prepare_command_data(cmd_len, last_block_iv, TO_INITIALVECTOR_SIZE);
	if (TO_OK != ret)
		return ret;
	cmd_len += TO_INITIALVECTOR_SIZE;
	ret = TODRV_HSE_prepare_command_data(cmd_len, last_block, TO_AES_BLOCK_SIZE);
	if (TO_OK != ret)
		return ret;
	cmd_len += TO_AES_BLOCK_SIZE;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE_INIT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_message_update(TODRV_HSE_ctx_t *ctx, const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t *data, uint16_t *data_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = cryptogram_len;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, cryptogram, cryptogram_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE_UPDATE, cryptogram_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*data_len = resp_data_len;
	TO_secure_memcpy(data, TODRV_HSE_response_data, *data_len);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_message_final(TODRV_HSE_ctx_t *ctx)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE_FINAL, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_payload(TODRV_HSE_ctx_t *ctx,
		const uint8_t *header, const uint16_t header_len,
		const uint8_t* data, const uint16_t data_len,
		uint8_t *payload, uint16_t *payload_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len;
	uint16_t padding_len;

	(void)ctx;

	padding_len = TO_AES_BLOCK_SIZE - ((data_len + 1) % TO_AES_BLOCK_SIZE);
	if (padding_len == TO_AES_BLOCK_SIZE) {
		padding_len = 0;
	}
	resp_data_len = TO_INITIALVECTOR_SIZE + data_len + TO_HMAC_SIZE
		+ padding_len + 1;

	ret = TODRV_HSE_prepare_command_data(0, header, header_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_prepare_command_data(header_len, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SECURE_MESSAGE,
			header_len + data_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*payload_len = resp_data_len;
	TO_secure_memcpy(payload, TODRV_HSE_response_data, *payload_len);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_payload_init_cbc(TODRV_HSE_ctx_t *ctx,
		const uint8_t *header, const uint16_t header_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_INITIALVECTOR_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, header, header_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SECURE_MESSAGE_INIT, header_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	if (resp_data_len != TO_INITIALVECTOR_SIZE)
		return TORSP_INVALID_LEN;

	TO_secure_memcpy(initial_vector, TODRV_HSE_response_data, TO_INITIALVECTOR_SIZE);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_payload_init_aead(TODRV_HSE_ctx_t *ctx,
		const uint8_t *header, const uint16_t header_len,
		uint8_t initial_vector[TO_TLS_AEAD_EXPLICIT_NONCE_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_INITIALVECTOR_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, header, header_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SECURE_MESSAGE_INIT, header_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	if (resp_data_len != TO_TLS_AEAD_EXPLICIT_NONCE_SIZE)
		return TORSP_INVALID_LEN;

	TO_secure_memcpy(initial_vector, TODRV_HSE_response_data,
			TO_TLS_AEAD_EXPLICIT_NONCE_SIZE);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_payload_update(TODRV_HSE_ctx_t *ctx, const uint8_t* data, const uint16_t data_len,
		uint8_t *cryptogram)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = data_len;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SECURE_MESSAGE_UPDATE, data_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;
	if (resp_data_len != data_len)
		return TORSP_INVALID_LEN;

	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data, data_len);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_secure_payload_final(TODRV_HSE_ctx_t *ctx, const uint8_t* data, const uint16_t data_len,
		uint8_t *cryptogram, uint16_t *cryptogram_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = TO_AES_BLOCK_SIZE + TO_HMAC_SIZE;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, data, data_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_SECURE_MESSAGE_FINAL, data_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*cryptogram_len = resp_data_len;
	TO_secure_memcpy(cryptogram, TODRV_HSE_response_data, *cryptogram_len);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_payload(TODRV_HSE_ctx_t *ctx,
		const uint8_t *header, const uint16_t header_len,
		const uint8_t* payload, const uint16_t payload_len,
		uint8_t *data, uint16_t *data_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = payload_len - TO_HMAC_MINSIZE - 1;
	uint16_t cmd_len = 0;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(cmd_len, header, header_len);
	if (TO_OK != ret)
		return ret;
	cmd_len += header_len;
	ret = TODRV_HSE_prepare_command_data(cmd_len, payload, payload_len);
	if (TO_OK != ret)
		return ret;
	cmd_len += payload_len;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE,
			cmd_len, &resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*data_len = resp_data_len;
	TO_secure_memcpy(data, TODRV_HSE_response_data, *data_len);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_payload_init_cbc(TODRV_HSE_ctx_t *ctx, const uint16_t cryptogram_len,
		const uint8_t *header, const uint16_t header_len,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;
	uint16_t cmd_len = 0;
	uint16_t _cryptogram_len = htobe16(cryptogram_len);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(cmd_len, (uint8_t*)&_cryptogram_len, sizeof(uint16_t));
	if (TO_OK != ret)
		return ret;
	cmd_len += sizeof(uint16_t);
	ret = TODRV_HSE_prepare_command_data(cmd_len, header, header_len);
	if (TO_OK != ret)
		return ret;
	cmd_len += header_len;
	ret = TODRV_HSE_prepare_command_data(cmd_len, initial_vector, TO_INITIALVECTOR_SIZE);
	if (TO_OK != ret)
		return ret;
	cmd_len += TO_INITIALVECTOR_SIZE;
	ret = TODRV_HSE_prepare_command_data(cmd_len, last_block_iv, TO_INITIALVECTOR_SIZE);
	if (TO_OK != ret)
		return ret;
	cmd_len += TO_INITIALVECTOR_SIZE;
	ret = TODRV_HSE_prepare_command_data(cmd_len, last_block, TO_AES_BLOCK_SIZE);
	if (TO_OK != ret)
		return ret;
	cmd_len += TO_AES_BLOCK_SIZE;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE_INIT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_payload_init_aead(TODRV_HSE_ctx_t *ctx, const uint16_t cryptogram_len,
		const uint8_t *header, const uint16_t header_len,
		const uint8_t initial_vector[TO_TLS_AEAD_EXPLICIT_NONCE_SIZE])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;
	uint16_t cmd_len = 0;
	uint16_t _cryptogram_len = htobe16(cryptogram_len);

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(cmd_len, (uint8_t*)&_cryptogram_len,
			sizeof(uint16_t));
	if (TO_OK != ret)
		return ret;
	cmd_len += sizeof(uint16_t);
	ret = TODRV_HSE_prepare_command_data(cmd_len, header, header_len);
	if (TO_OK != ret)
		return ret;
	cmd_len += header_len;
	ret = TODRV_HSE_prepare_command_data(cmd_len, initial_vector,
			TO_TLS_AEAD_EXPLICIT_NONCE_SIZE);
	if (TO_OK != ret)
		return ret;
	cmd_len += TO_TLS_AEAD_EXPLICIT_NONCE_SIZE;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE_INIT, cmd_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_payload_update(TODRV_HSE_ctx_t *ctx, const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t *data, uint16_t *data_len)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = cryptogram_len;

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data(0, cryptogram, cryptogram_len);
	if (TO_OK != ret)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE_UPDATE, cryptogram_len,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	*data_len = resp_data_len;
	TO_secure_memcpy(data, TODRV_HSE_response_data, *data_len);
	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_tls_unsecure_payload_final(TODRV_HSE_ctx_t *ctx)
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = 0;

	(void)ctx;

	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_UNSECURE_MESSAGE_FINAL, 0,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	return resp_status;
}

TODRV_HSE_TLS_API TO_ret_t TODRV_HSE_get_tls_master_secret_derived_keys(
		TODRV_HSE_ctx_t *ctx,
		uint8_t key_block_length,
		uint8_t key_block[])
{
	TO_lib_ret_t ret;
	TO_se_ret_t resp_status;
	uint16_t resp_data_len = key_block_length;
	if (!resp_data_len) {
		resp_data_len = 256;
	}

	(void)ctx;

	ret = TODRV_HSE_prepare_command_data_byte(0, key_block_length);
	if (ret != TO_OK)
		return ret;
	ret = TODRV_HSE_send_command(TODRV_HSE_CMD_TLS_GET_MASTER_SECRET_DERIVED_KEYS, 1,
			&resp_data_len, &resp_status);
	if (TO_OK != ret || TORSP_SUCCESS != resp_status)
		return ret | resp_status;

	TO_secure_memcpy(key_block, TODRV_HSE_response_data,
			resp_data_len);
	return resp_status;
}

#endif

#endif /* TODRV_HSE_DRIVER_DISABLE */


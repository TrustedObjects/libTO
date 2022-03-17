/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2019 Trusted Objects. All rights reserved.
 */

/**
 * @file TODRV_HSE_lora.h
 * @brief
 */

#ifndef _TODRV_HSE_LORA_H_
#define _TODRV_HSE_LORA_H_

#ifndef TODRV_HSE_LORA_API
#ifdef __linux__
#define TODRV_HSE_LORA_API
#elif _WIN32
#define TODRV_HSE_LORA_API __declspec(dllexport)
#else
#define TODRV_HSE_LORA_API
#endif /* __LINUX__ */
#endif

#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_compute_mic(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *data,
		uint16_t data_length,
		uint32_t address,
		uint8_t direction,
		uint32_t seq_counter,
		uint8_t mic[TO_LORA_MIC_SIZE]);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_encrypt_payload(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *data,
		uint16_t data_length,
		const uint8_t *fport,
		uint32_t address,
		uint8_t direction,
		uint32_t seq_counter,
		uint8_t *enc_buffer);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_join_compute_mic(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *data,
		uint16_t data_length,
		uint8_t mic[TO_LORA_MIC_SIZE]);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_decrypt_join(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *data,
		uint16_t data_length,
		uint8_t *dec_buffer);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_compute_shared_keys(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *app_nonce,
		const uint8_t *net_id,
		uint16_t dev_nonce);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_set_app_eui(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t app_eui[TO_LORA_APPEUI_SIZE]);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_get_app_eui(
		TODRV_HSE_ctx_t *ctx,
		uint8_t app_eui[TO_LORA_APPEUI_SIZE]);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_set_dev_eui(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t dev_eui[TO_LORA_DEVEUI_SIZE]);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_get_dev_eui(
		TODRV_HSE_ctx_t *ctx,
		uint8_t dev_eui[TO_LORA_DEVEUI_SIZE]);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_get_dev_addr(
		TODRV_HSE_ctx_t *ctx,
		uint8_t dev_addr[TO_LORA_DEVADDR_SIZE]);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_set_dev_addr(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t dev_addr[TO_LORA_DEVADDR_SIZE]);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_set_appkey(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t appkey[TO_LORA_APPKEY_SIZE]);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_set_appskey(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t appskey[TO_LORA_APPSKEY_SIZE]);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_set_nwkskey(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t nwkskey[TO_LORA_NWKSKEY_SIZE]);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_get_join_request_phypayload(
		TODRV_HSE_ctx_t *ctx,
		uint8_t data[TO_LORA_JOINREQUEST_SIZE]);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_handle_join_accept_phypayload(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *data,
		const uint16_t data_length,
		uint8_t dec_buffer[TO_LORA_JOINACCEPT_CLEAR_MAXSIZE]);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_secure_phypayload(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t mhdr,
		const uint8_t fctrl,
		const uint8_t *fopts,
		const uint8_t fport,
		const uint8_t *payload,
		const int payload_size,
		uint8_t *enc_buffer);

TODRV_HSE_LORA_API TO_ret_t TODRV_HSE_lora_unsecure_phypayload(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *data,
		const uint16_t data_length,
		uint8_t *dec_buffer);

#ifdef __cplusplus
}
#endif

#endif /* _TODRV_HSE_LORA_H_ */


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
 * @file TODRV_HSE_mac.h
 * @brief
 */

#ifndef _TODRV_HSE_MAC_H_
#define _TODRV_HSE_MAC_H_

#ifndef TODRV_HSE_MAC_API
#ifdef __linux__
#define TODRV_HSE_MAC_API
#elif _WIN32
#define TODRV_HSE_MAC_API __declspec(dllexport)
#else
#define TODRV_HSE_MAC_API
#endif /* __LINUX__ */
#endif

#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_compute_hmac(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t hmac_data[TO_HMAC_SIZE]);

TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_compute_hmac_init(
		TODRV_HSE_ctx_t *ctx,
		uint8_t key_index);

TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_compute_hmac_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* data,
		uint16_t length);

TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_compute_hmac_final(
		TODRV_HSE_ctx_t *ctx,
		uint8_t hmac[TO_HMAC_SIZE]);

TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_verify_hmac(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		const uint8_t hmac_data[TO_HMAC_SIZE]);

TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_verify_hmac_init(
		TODRV_HSE_ctx_t *ctx,
		uint8_t key_index);

TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_verify_hmac_update(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t* data,
		uint16_t length);

TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_verify_hmac_final(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t hmac[TO_HMAC_SIZE]);

TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_compute_cmac(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t cmac_data[TO_CMAC_SIZE]);

TODRV_HSE_MAC_API TO_ret_t TODRV_HSE_verify_cmac(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t cmac_data[TO_CMAC_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* _TODRV_HSE_MAC_H_ */


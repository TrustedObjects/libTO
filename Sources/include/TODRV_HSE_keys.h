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
 * @file TODRV_HSE_keys.h
 * @brief
 */

#ifndef _TODRV_HSE_KEYS_H_
#define _TODRV_HSE_KEYS_H_

#ifndef TODRV_HSE_KEYS_API
#ifdef __linux__
#define TODRV_HSE_KEYS_API
#elif _WIN32
#define TODRV_HSE_KEYS_API __declspec(dllexport)
#else
#define TODRV_HSE_KEYS_API
#endif /* __LINUX__ */
#endif

#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

TODRV_HSE_KEYS_API TO_ret_t TODRV_HSE_set_remote_public_key(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t public_key[TO_ECC_PUB_KEYSIZE],
		const uint8_t signature[TO_SIGNATURE_SIZE]);

TODRV_HSE_KEYS_API TO_ret_t TODRV_HSE_renew_ecc_keys(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index);

TODRV_HSE_KEYS_API TO_ret_t TODRV_HSE_get_public_key(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		uint8_t public_key[TO_ECC_PUB_KEYSIZE],
		uint8_t signature[TO_SIGNATURE_SIZE]);

TODRV_HSE_KEYS_API TO_ret_t TODRV_HSE_get_unsigned_public_key(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		uint8_t public_key[TO_ECC_PUB_KEYSIZE]);

TODRV_HSE_KEYS_API TO_ret_t TODRV_HSE_renew_shared_keys(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t public_key_index);

TODRV_HSE_KEYS_API TO_ret_t TODRV_HSE_get_key_fingerprint(
		TODRV_HSE_ctx_t *ctx,
		TO_key_type_t key_type,
		uint8_t key_index,
		uint8_t* fingerprint[TO_KEY_FINGERPRINT_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* _TODRV_HSE_KEYS_H_ */


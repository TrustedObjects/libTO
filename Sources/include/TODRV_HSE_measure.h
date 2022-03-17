/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2021 Trusted Objects. All rights reserved.
 */

/**
 * @file TODRV_HSE_measure.h
 * @brief
 */

#ifndef _TODRV_HSE_MEASURE_H_
#define _TODRV_HSE_MEASURE_H_

#ifndef TODRV_HSE_MEASURE_API
#ifdef __linux__
#define TODRV_HSE_MEASURE_API
#elif _WIN32
#define TODRV_HSE_MEASURE_API __declspec(dllexport)
#else
#define TODRV_HSE_MEASURE_API
#endif /* __LINUX__ */
#endif

#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

TODRV_HSE_MEASURE_API TO_ret_t TODRV_HSE_measured_boot(TODRV_HSE_ctx_t *ctx,
		const uint8_t *hash, uint16_t hash_length);

TODRV_HSE_MEASURE_API TO_ret_t TODRV_HSE_validate_new_fw_hash(TODRV_HSE_ctx_t *ctx,
		const uint8_t* hash, uint16_t hash_length);

TODRV_HSE_MEASURE_API TO_ret_t TODRV_HSE_commit_new_fw_hash(TODRV_HSE_ctx_t *ctx,
		const uint8_t signed_challenge[TO_HMAC_SIZE]);

TODRV_HSE_MEASURE_API TO_ret_t TODRV_HSE_store_new_trusted_fw_hash(TODRV_HSE_ctx_t *ctx,
		const uint8_t* fw_hash, uint16_t fw_hash_length,
		const uint8_t  mac[TO_HMAC_SIZE]);

TODRV_HSE_MEASURE_API TO_ret_t TODRV_HSE_get_boot_measurement(TODRV_HSE_ctx_t *ctx,
		uint8_t* fw_hash, uint16_t fw_hash_length,
		const uint8_t* challenge, uint16_t challenge_length,
		measure_outcome_t* outcome, uint8_t mac[TO_HMAC_SIZE]);

TODRV_HSE_MEASURE_API TO_ret_t TODRV_HSE_get_se_measurement(TODRV_HSE_ctx_t *ctx,
		uint8_t* hash, uint16_t hash_length,
		const uint8_t* challenge, uint16_t challenge_length,
		measure_outcome_t* outcome, uint8_t mac[TO_HMAC_SIZE]);

TODRV_HSE_MEASURE_API TO_ret_t TODRV_HSE_invalidate_new_hash(TODRV_HSE_ctx_t *ctx,
		const uint8_t password_challenge_hash[TO_SHA256_HASHSIZE]);

#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_TODRV_HSE_MEASURE_H_ */

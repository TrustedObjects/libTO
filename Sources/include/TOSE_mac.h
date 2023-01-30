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
 * @file TOSE_mac.h
 * @brief
 */

#ifndef _TOSE_MAC_H_
#define _TOSE_MAC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"

/** @addtogroup mac
 * @{ */

/**
 * @brief Computes a 256-bit HMAC tag based on SHA256 hash
 * function.
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use for HMAC calculation, starting
 * from 0
 * @param[in] data Data to compute HMAC on
 * @param[in] data_length
 * @param[out] hmac_data Computed HMAC
 *
 * If you need to compute HMAC on more than 512 bytes, please use the sequence
 * TOSE_compute_hmac_init(), TOSE_compute_hmac_update(), ...,
 * TOSE_compute_hmac_final().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
extern TO_ret_t TOSE_compute_hmac(TOSE_ctx_t *ctx, const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, uint8_t hmac_data[TO_HMAC_SIZE]);

/**
 * @brief Compute HMAC on more than 512 bytes of data
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use for HMAC calculation, starting
 * from 0
 *
 * This is the first command of the sequence TOSE_compute_hmac_init(),
 * TOSE_compute_hmac_update(), ..., TOSE_compute_hmac_final().
 * It is used to Secure Element send Key_index.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
extern TO_ret_t TOSE_compute_hmac_init(TOSE_ctx_t *ctx, uint8_t key_index);

/**
 * @brief Used to send data to compute HMAC on.
 * @param[in] ctx Pointer to the SE context
 * @param[in] data Data to compute HMAC on
 * @param[in] length Data length
 *
 * This command can be called several times, new data are added to the data
 * previously sent.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_COND_OF_USE_NOT_SATISFIED: need to call TOSE_compute_hmac_init() first
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
extern TO_ret_t TOSE_compute_hmac_update(TOSE_ctx_t *ctx, const uint8_t* data, uint16_t length);

/**
 * @brief Returns computed HMAC
 * @param[in] ctx Pointer to the SE context
 * @param[out] hmac Returned computed HMAC
 *
 * This is the last command of the sequence TOSE_compute_hmac_init(),
 * TOSE_compute_hmac_update(), ..., TOSE_compute_hmac_final().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_COND_OF_USE_NOT_SATISFIED: need to call TOSE_compute_hmac_init() and
 * TOSE_compute_hmac_update() first
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
extern TO_ret_t TOSE_compute_hmac_final(TOSE_ctx_t *ctx, uint8_t hmac[TO_HMAC_SIZE]);

/**
 * @brief Verifies if the HMAC tag is correct for the given data
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use for HMAC calculation, starting
 * from 0
 * @param[in] data Data to verify HMAC on
 * @param[in] data_length
 * @param[in] hmac_data expected HMAC value
 *
 * If you need to verify HMAC of more than 512 bytes, please use the
 * combination of TOSE_verify_hmac_init(), TOSE_verify_hmac_update(), ...,
 * TOSE_verify_hmac_final()
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: verification failed
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
extern TO_ret_t TOSE_verify_hmac(TOSE_ctx_t *ctx, const uint8_t key_index, const uint8_t* data,
		const uint16_t data_length, const uint8_t hmac_data[TO_HMAC_SIZE]);

/**
 * @brief Verify HMAC on more than 512 bytes of data
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use for HMAC calculation, starting
 * from 0
 *
 * When you need to verify HMAC of more than 512 bytes you need to call this
 * function first with the key index - as sent to verify_hmac().
 * Data will be sent with verify_hmac_update() and HMAC will be sent with
 * verify_hmac_final().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
extern TO_ret_t TOSE_verify_hmac_init(TOSE_ctx_t *ctx, uint8_t key_index);

/**
 * @brief Used to send data to verify HMAC on.
 * @param[in] ctx Pointer to the SE context
 * @param[in] data Data to verify HMAC on
 * @param[in] length Data length
 *
 * After calling TOSE_verify_hmac_init() to provide key index, you can call
 * TOSE_verify_hmac_update() to send the data to verify HMAC on.
 * This command can be called several times, and new data are added to the
 * previous one for HMAC verification.
 * Last command to use is TOSE_verify_hmac_final().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_COND_OF_USE_NOT_SATISFIED: need to call VERIFY_HMAC_INIT first
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
extern TO_ret_t TOSE_verify_hmac_update(TOSE_ctx_t *ctx, const uint8_t* data, uint16_t length);

/**
 * @brief This command is used to send HMAC to verify
 * @param[in] ctx Pointer to the SE context
 * @param[in] hmac HMAC to verify
 *
 * Data was previously sent by the sequence TOSE_verify_hmac_init(),
 * TOSE_verify_hmac_update(), ..., TOSE_verify_hmac_final().
 * This command succeeds if the HMAC is correct for the given data.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: verification failed
 * - TORSP_COND_OF_USE_NOT_SATISFIED: TOSE_verify_hmac_init() or
 *      TOSE_verify_hmac_update() were not called before this command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
extern TO_ret_t TOSE_verify_hmac_final(TOSE_ctx_t *ctx, const uint8_t hmac[TO_HMAC_SIZE]);

/**
 * @brief Compute CMAC
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use for CMAC calculation, starting
 * from 0
 * @param[in] data Data to compute CMAC on
 * @param[in] data_length Length of the data which signature has to be verified
 * @param[out] cmac_data Returned computed CMAC
 *
 * Compute a 128-bit CMAC tag based on AES128 algorithm.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
extern TO_ret_t TOSE_compute_cmac(TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t cmac_data[TO_CMAC_SIZE]);

/**
 * @brief Verify the CMAC signature of a given block of data
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the key to use to compute the CMAC tag, starting
 * from 0
 * @param[in] data Data to verify CMAC on
 * @param[in] data_length Length of the data which signature has to be verified
 * @param[in] cmac_data expected CMAC
 *
 * Verify if the CMAC tag is correct for the given data.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: verification failed
 * - TORSP_ARG_OUT_OF_RANGE: invalid key index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
extern TO_ret_t TOSE_verify_cmac(TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		const uint8_t cmac_data[TO_CMAC_SIZE]);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_MAC_H_ */


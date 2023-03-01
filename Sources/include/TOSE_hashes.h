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
 * @file TOSE_hashes.h
 * @brief
 */

#ifndef _TOSE_HAHSHES_H_
#define _TOSE_HAHSHES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"

/** @addtogroup hashes
 * @{ */

/**
 * @brief SHA256 computation
 * @param[in] ctx Pointer to the SE context
 * @param[in] data Data to compute SHA256 on
 * @param[in] data_length Data length, max. 512 bytes
 * @param[out] sha256 returned computed SHA256
 *
 * Compute SHA256 hash on the given data.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_INTERNAL_ERROR if a fault has been detected
 * - TORSP_INVALID_LEN if the data_length is too large (> 512)
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
extern TO_ret_t TOSE_sha256(TOSE_ctx_t *ctx, const uint8_t* data, const uint16_t data_length,
		uint8_t sha256[TO_SHA256_HASHSIZE]);

/**
 * @brief Compute SHA256 on more than 512 bytes of data
 * @param[in] ctx Pointer to the SE context
 *
 * This function must be followed by calls to TOSE_sha256_update() and
 * TOSE_sha256_final().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_INTERNAL_ERROR if a fault has been detected
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
extern TO_ret_t TOSE_sha256_init(TOSE_ctx_t *ctx);

/**
 * @brief Update SHA256 computation with new data
 * @param[in] ctx Pointer to the SE context
 * @param[in] data Data to compute SHA256 on
 * @param[in] length Data length, max. 512 bytes
 *
 * This function can be called several times to provide data to compute SHA256
 * on, and must be called after TOSE_sha256_init().
 *
 * This command is used to transmit data. It can be called several times,
 * typically splitting the data into several blocks of 512 bytes.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_INTERNAL_ERROR if a fault has been detected
 * - TORSP_INVALID_LEN if the data_length is too large (> 512)
 * - TORSP_COND_OF_USE_NOT_SATISFIED if not called after TOSE_sha256_init()
 * or TOSE_sha256_update()
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
extern TO_ret_t TOSE_sha256_update(TOSE_ctx_t *ctx, const uint8_t* data, const uint16_t length);

/**
 * @brief Returns the SHA256 hash of the data previously given
 * @param[in] ctx Pointer to the SE context
 * @param[out] sha256 returned computed SHA256
 *
 * This function must be called after TOSE_sha256_init() and
 * TOSE_sha256_update().
 *
 * This command finalizes the process and returns the SHA256 hash of the given
 * data.
 * This command handles the padding computation.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_INTERNAL_ERROR if a fault has been detected
 * - TORSP_COND_OF_USE_NOT_SATISFIED: if not called after TOSE_sha256_update()
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
extern TO_ret_t TOSE_sha256_final(TOSE_ctx_t *ctx,
		uint8_t sha256[TO_SHA256_HASHSIZE]);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_HAHSHES_H_ */


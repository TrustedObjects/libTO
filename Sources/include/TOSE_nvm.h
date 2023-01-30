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
 * @file TOSE_nvm.h
 * @brief
 */

#ifndef _TOSE_NVM_H_
#define _TOSE_NVM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"

/** @addtogroup nvm
 * @{ */

/**
 * @brief Write data to Secure Element NVM reserved zone.
 * @param[in] ctx Pointer to the SE context
 * @param[in] offset Offset in NVM reserved zone to write data
 * @param[in] data Buffer containing data to write
 * @param[in] length Amount of data to write in bytes (512 bytes max.)
 * @param[in] key Key used to write data
 *
 * @return TO_OK if data has been written successfully
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR if an internal error has occurred
 */
extern TO_ret_t TOSE_write_nvm(TOSE_ctx_t *ctx, const uint16_t offset, const void *data,
		unsigned int length, const uint8_t key[TO_AES_KEYSIZE]);

/**
 * @brief Read data from Secure Element NVM reserved zone.
 * @param[in] ctx Pointer to the SE context
 * @param[in] offset Offset in NVM reserved zone to read data
 * @param[out] data Buffer to store data
 * @param[in] length Amount of data to read in bytes (512 bytes max.)
 * @param[in] key Key used to read data
 *
 * @return TO_OK if data has been read successfully
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR if an internal error has occurred
 */
extern TO_ret_t TOSE_read_nvm(TOSE_ctx_t *ctx, const uint16_t offset, void *data,
		unsigned int length, const uint8_t key[TO_AES_KEYSIZE]);

/**
 * @brief Get NVM reserved zone available size.
 * @param[in] ctx Pointer to the SE context
 * @param[in] size NVM size
 *
 * @return TO_OK if size has been retrieved successfully
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR if an internal error has occurred
 */
extern TO_ret_t TOSE_get_nvm_size(TOSE_ctx_t *ctx, uint16_t *size);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_NVM_H_ */


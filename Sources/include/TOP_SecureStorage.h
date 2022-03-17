/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2021 Trusted Objects. All rights reserved.
 */

/**
 * @file TOP_SecureStorage.h
 * @brief TO-Protect Secure Storage API
 */

#ifndef _TOP_SECURE_STORAGE_H_
#define _TOP_SECURE_STORAGE_H_

#include "TO_retcodes.h"
#include "TO_log.h"

/** @addtogroup secure_storage_defs
 * @{ */

/**
 * @brief Secure storage read function.
 * @param[in] address Address to read, related to Secure Storage base address
 * @param[out] data Data destination
 * @param[in] size Data length
 *
 * This function is used by TO-Protect to read data from NVM. You have
 * to implement this function with read NVM function of your platform.
 *
 * @return TO_OK if data has been read successfully, else TO_ERROR
 */
typedef TO_lib_ret_t TOP_secure_storage_read_func_t(uint8_t *data,
		const void *address, uint32_t size);

/**
 * @brief Secure storage write function.
 * @param[in] address Address to write, related to Secure Storage base address
 * @param[in] data Data source
 * @param[in] size Data length (always equal to block size)
 *
 * This function is used by TO-Protect to write a block to NVM. You
 * have to implement this function with write NVM function of your platform.
 * This function must NOT perform any erase, as it is handled by secure storage
 * implementation directly.
 *
 * @return TO_OK if data has been written successfully, else TO_ERROR
 */
typedef TO_lib_ret_t TOP_secure_storage_write_func_t(void *address,
		const uint8_t *data, uint32_t size);

/**
 * @brief Secure storage erase function.
 * @param[in] address Address of block to erase, related to Secure Storage base
 * address
 *
 * This function is used by TO-Protect to erase NVM blocks. You have
 * to implement this function with erase NVM function of your platform.
 *
 * @return TO_OK if data has been erased successfully, else TO_ERROR
 */
typedef TO_lib_ret_t TOP_secure_storage_erase_func_t(void *address,
		uint32_t size);

/**
 * Secure Storage data type
 */
enum TOP_secure_storage_type_e {
	SECURE_STORAGE_INVALID,
	SECURE_STORAGE_CLEAR_DATA, /**< Data is stored clear */
	SECURE_STORAGE_SECRET_DATA /**< Data is stored obfuscated */
};
typedef enum TOP_secure_storage_type_e TOP_secure_storage_type_t;

/**
 * External secure storage context
 *
 * This structure is used by initialization function to configure secure storage
 * behavior.
 */
typedef struct TOP_secure_storage_ctx_s {
	TOP_secure_storage_type_t type;
	void *address; /**< Secure storage memory address */
	uint32_t size; /**< Size of this Secure Storage */
	uint8_t *rambuff; /**< Working buffer */
	TOP_secure_storage_read_func_t *read_func;
	TOP_secure_storage_write_func_t *write_func;
	TOP_secure_storage_erase_func_t *erase_func;
	uint8_t is_reset; /**< 1 after storage open if a reset has been performed */
	uint32_t rng_seed; /**< LFSR RNG seed */
	struct {
		uint32_t polyv; /**< LFSR value polynom */
		uint32_t seedv; /**< LFSR value seed */
		uint32_t polyr; /**< LFSR random seed */
	} lfsr;
	TO_log_ctx_t *log_ctx;
} TOP_secure_storage_ctx_t;

/**
 * @} */

/** @addtogroup secure_storage_api
 * @{ */

/**
 * @brief Configure Secure Storage context before opening
 * @param[in] ctx Secure Storage context
 * @param[in] type SECURE_STORAGE_CLEAR_DATA or SECURE_STORAGE_SECRET_DATA
 * @param[in] address NVM secure storage address
 * @param[in] size Stored data size
 * @param[in] rambuff RAM working buffer, used internally by Secure Storage
 * @param[in] read_func NVM read function pointer
 * @param[in] write_func NVM write function pointer
 * @param[in] erase_func NVM erase function pointer
 *
 * Secure Storage required NVM space has to be calculated by the
 * SECURE_STORAGE_SIZE macro.
 * RAM working buffer size has to be calculated by the
 * SECURE_STORAGE_RAMBUFF_SIZE macro.
 *
 * @return TO_OK on success
 */
extern TO_ret_t TOP_secure_storage_config(
		TOP_secure_storage_ctx_t *ctx,
		TOP_secure_storage_type_t type,
		void *address, uint32_t size, uint8_t *rambuff,
		TOP_secure_storage_read_func_t *read_func,
		TOP_secure_storage_write_func_t *write_func,
		TOP_secure_storage_erase_func_t *erase_func);

/**
 * @brief Open Secure Storage instance
 * @param[in] ctx Secure Storage context
 * @return TO_OK on success
 */
extern  TO_ret_t TOP_secure_storage_open(TOP_secure_storage_ctx_t *ctx);

/**
 * @brief Close Secure Storage instance
 * @param[in] ctx Secure Storage context
 * @return TO_OK on success
 */
extern  TO_ret_t TOP_secure_storage_close(TOP_secure_storage_ctx_t *ctx);

/**
 * @brief Flushes the secure storage to NVM
 * @param[in] ctx Secure Storage context
 * @return TO_OK on success
 */
extern  TO_ret_t TOP_secure_storage_flush(TOP_secure_storage_ctx_t *ctx);

/**
 * @brief Read data from secure storage
 * @param[in] ctx Secure Storage context
 * @param[in] offset Offset to read from
 * @param[out] data Output data
 * @param[in] size Size to read
 * @return TO_OK on success
 */
extern  TO_ret_t TOP_secure_storage_read(
		TOP_secure_storage_ctx_t *ctx,
		uint32_t offset, uint8_t *data, uint32_t size);

/**
 * @brief Write clear RO data to secure storage
 * @param[in] ctx Secure Storage context
 * @param[in] offset Offset to write to
 * @param[in] data Input data
 * @param[in] size Size to write
 * @return TO_OK on success
 */
extern  TO_ret_t TOP_secure_storage_write(
		TOP_secure_storage_ctx_t *ctx,
		uint32_t offset, const uint8_t *data, uint32_t size);

/**
 * @} */

#endif /* _TOP_SECURE_STORAGE_H_ */

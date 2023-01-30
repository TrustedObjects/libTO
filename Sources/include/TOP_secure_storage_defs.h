/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2022 Trusted Objects. All rights reserved.
 */

/**
 * @file TOP_secure_storage_defs.h
 * @brief TO-Protect Secure Storage types and definitions
 */

#ifndef _TOP_SECURE_STORAGE_DEFS_H_
#define _TOP_SECURE_STORAGE_DEFS_H_

#include "TO_retcodes.h"
#include "TO_log.h"

/** @addtogroup secure_storage_defs
 * @{ */

/**
 * @brief Secure storage read function.
 * @param[out] data Data destination
 * @param[in] address Address to read, related to Secure Storage base address
 * @param[in] size Data length
 *
 * This function is used by TO-Protect to read data from NVM. You have
 * to implement this function with read NVM function of your platform.
 *
 * @return TO_OK if data has been read successfully, else TO_ERROR
 */
typedef TO_lib_ret_t TOX_read_func_t(uint8_t *data,
		const void *address, uint32_t size);

/**
 * @brief Secure storage write function.
 * @param[in] address Address to write, related to Secure Storage base address
 * @param[in] data Data source
 * @param[in] size Data length
 *
 * This function is used by TO-Protect to write to NVM. You have to implement
 * this function with write NVM function of your platform.
 * This function must NOT perform any erase, as it is handled by secure storage
 * implementation directly.
 *
 * @return TO_OK if data has been written successfully, else TO_ERROR
 */
typedef TO_lib_ret_t TOX_write_func_t(void *address,
		const uint8_t *data, uint32_t size);

/**
 * @brief Secure storage erase function.
 * @param[in] address Address to erase from, related to Secure Storage base
 * address
 * @param[in] size Data length
 *
 * This function is used by TO-Protect to erase NVM. You have to implement this
 * function with erase NVM function of your platform.
 *
 * @return TO_OK if data has been erased successfully, else TO_ERROR
 */
typedef TO_lib_ret_t TOX_erase_func_t(void *address,
		uint32_t size);

/**
 * Secure Storage data type
 */
enum TOX_type_e {
	SECURE_STORAGE_INVALID,
	SECURE_STORAGE_CLEAR_DATA, /**< Data is stored clear */
	SECURE_STORAGE_SECRET_DATA /**< Data is stored obfuscated */
};
typedef enum TOX_type_e TOX_type_t;

/**
 * External secure storage context
 *
 * This structure is used by initialization function to configure secure storage
 * behavior.
 */
typedef struct TOX_ctx_s {
	TOX_type_t type;
	void *address; /**< Secure storage memory address */
	uint32_t size; /**< Size of this Secure Storage */
	uint8_t *rambuff; /**< Working buffer, this is a copy of NVM storage,
				synchronized with NVM just after open or flush */
	uint8_t *secret_rambuff; /**< Secret data (unobfuscated) RAM buffer */
	TOX_read_func_t *read_func;
	TOX_write_func_t *write_func;
	TOX_erase_func_t *erase_func;
	uint8_t is_reset; /**< 1 after storage open if a reset has been performed */
	uint8_t data_changed; /**< 1 if data has changed since last open or flush */
	uint32_t rng_seed; /**< LFSR RNG seed */
	struct {
		uint32_t polyv; /**< LFSR value polynom */
		uint32_t seedv; /**< LFSR value seed */
		uint32_t polyr; /**< LFSR random seed */
	} lfsr;
	TO_log_ctx_t *log_ctx;
	uint32_t data_version; /**< Data structure version */
} TOX_ctx_t;

/**
 * @} */

#endif /* _TOP_SECURE_STORAGE_DEFS_H_ */


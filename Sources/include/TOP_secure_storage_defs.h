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

typedef enum data_dalidity_e {
	TOX_BOTH_STORAGES_ARE_INVALID = 0x7d,
	TOX_PLAIN_STORAGE_IS_VALID    = 0xed,
	TOX_SECRET_STORAGE_IS_VALID   = 0x41,
	TOX_BOTH_STORAGES_ARE_VALID   = (TOX_BOTH_STORAGES_ARE_INVALID ^ TOX_PLAIN_STORAGE_IS_VALID ^ TOX_SECRET_STORAGE_IS_VALID)
} data_validity_t;

/**
 * External secure storage context
 *
 * This structure is used by initialization function to configure secure storage
 * behavior.
 */
typedef struct TOX_ctx_s {
	uint8_t *raw_ram_buffer;	/**< Buffer provided by the user application to read the whole nvm area */
	uint8_t *ram_buffer;		/**< Buffer without the tearing header */
	TO_log_ctx_t *log_ctx;		/**< Pointer to a log structure */
	void *rng;			/**< Pointer to a RNG structure */
	uint16_t plain_storage_size;	/**< Current plain storage size */
	uint16_t secret_storage_size;	/**< Current secret storage size */
	uint16_t raw_ram_buffer_size;	/**< Raw buffer size */
	uint16_t ram_buffer_size;	/**< Raw buffer size without the tearing */
	uint8_t is_reset; 		/**< 1 after storage open if a reset has been performed */
	uint8_t data_changed; 		/**< 1 if data has changed since last open or flush */
	data_validity_t data_are_valid;	/**< Indicates that both plain and secret storages are valid (or not) */
} TOX_ctx_t;

/**
 * @} */

#endif /* _TOP_SECURE_STORAGE_DEFS_H_ */


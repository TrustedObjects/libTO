/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2019-2022 Trusted Objects. All rights reserved.
 */

#ifndef _TOP_STORAGE_H_
#define _TOP_STORAGE_H_

#include <TOP_secure_storage_defs.h>

/** @addtogroup secure_storage_defs
 * @{ */

typedef enum zone_id_e {
	TEARING_ZONE_0 = 0,
	TEARING_ZONE_1,
	TEARING_ZONE_NONE
} zone_id_t;

/**
 * @brief Data loading function
 *
 * @param zone_id Zone identifier
 * @param dst destination buffer
 * @return TO_lib_ret_t return code
 * @retval TO_OK If data has been read successfuly
 * @retval TO_ERROR If something went wrong, resulting in the data read not
 * to be reliable.
 */
typedef TO_lib_ret_t TOP_data_load_func_t(zone_id_t zone_id,
		const void *dst);

/**
 * @brief Data storing function
 *
 * @param zone_id Zone identifier
 * @param dst destination buffer
 * @return TO_lib_ret_t return code
 * @retval TO_OK If data has been written successfuly
 * @retval TO_ERROR If something went wrong, resulting in the data read not
 * to be reliable.
 */
typedef TO_lib_ret_t TOP_data_store_func_t(zone_id_t zone_id,
		const void *src);

/**
 * External secure storage configuration
 *
 * This structure is used by initialization function to configure secure storage
 * behavior.
 */
typedef struct TOP_secure_data_ctx_s {
	TOX_ctx_t storage;
	TOP_data_load_func_t *load_func;
	TOP_data_store_func_t *store_func;
	uint32_t current_version;
	zone_id_t current_zone_ID;  // 1 ou 2
} TOP_secure_data_ctx_t;

/**
 * @} */

#endif // _TOP_STORAGE_H_

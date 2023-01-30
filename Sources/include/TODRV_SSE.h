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

#ifndef _TODRV_SSE_H_
#define _TODRV_SSE_H_

#ifndef TODRV_SSE_DRIVER_DISABLE

#include "TODRV_SSE_cfg.h"
#include "TO_retcodes.h"
#include "TO_defs.h"
#include "TOP_info.h"
#include "TO_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

// Defines the number of bytes lost at the end of a secure storage bank
#define SECTOR_LOST_BYTES (TODRV_SSE_NVM_SECTOR_SIZE - (TOP_SECURE_STORAGE_NVM_FOOTPRINT % TODRV_SSE_NVM_SECTOR_SIZE))

// Defines the total Size of the secure storage (including the 2 tearing zones)
#define TOP_SECURE_TOTAL_NVM_SIZE (2 * (TOP_SECURE_STORAGE_NVM_FOOTPRINT) + SECTOR_LOST_BYTES)

/**
 * @brief Customer-side NVM load callback function
 * @param dst Destination buffer (located in RAM) receiving the read data
 * @param src_offset Offset from the beginning of the secure-storage area to read the data from.
 * This offset will always be a multiple of a sector size.
 * @param size The number of bytes to be read
 * @details This function is responsible for performing the read of the memory (supposingly NVM)
 * used to store TO-Protect secure storage.
 * It should act as follows :
 * - Compute the address (called source) corresponding to the Offset
 * - Copy the data from the source to the dst over size bytes
 * - If anything is wrong, return TO_ERROR, else return TO_OK
 * @return TO_lib_ret_t return code
 * @retval TO_ERROR If anything goes wrong
 * @retval TO_OK If the data requested to be loaded have correctly been processed
 */
extern TO_lib_ret_t TODRV_SSE_secure_storage_load(uint8_t *dst, uint32_t src_offset, uint32_t size);

/**
 * @brief Customer-side NVM store callback function
 * @param dst_offset Offset from the beginning of the secure-storage area to read the data from.
 * This offset will always be a multiple of a sector size.
 * All the data, located at the end of a sector won't have to be written. Whatever their value,
 * they are considered unused.
 * @param src Source pointer (located in RAM) containing the data to be written
 * @param size The number of bytes to be written
 * @details This function is responsible for performing the write of the memory (supposingly NVM)
 * used to store TO-Protect secure storage. Depending on the interface used to perform the write,
 * you may need to perform a preliminary erase (eg. Flash).
 * It should act as follows :
 * - Compute the address (called destination) corresponding to the Offset
 * - Depending on your platform, all related sectors that will receive the data
 * - Program & verify the memory at address destination with the bytes taken from source over size bytes
 * - If anything is wrong, return TO_ERROR, else return TO_OK
 * @return TO_lib_ret_t return code
 * @retval TO_ERROR If anything goes wrong
 * @retval TO_OK If the data requested to be stored have correctly been processed
 */
extern TO_lib_ret_t TODRV_SSE_secure_storage_store(uint32_t dst_offset, const uint8_t *src, uint32_t size);

/** @addtogroup context_api
 * @{ */

/**
 * @brief Get SSE context
 *
 * @return SSE context pointer
 */
extern TOSE_ctx_t* TODRV_SSE_get_ctx(void);

/** @} */

/** @addtogroup drv_test_api
 * @{ */

/**
 * @brief Self-test for NVM load/store functions with driver configuration.
 * @details In order to verify your implementation, we recommend to call this function
 * (only in development, not in production, as it wears down the Flash memory and
 * will write test data over the secure storage).
 * @return TO_lib_ret_t return code
 * @retval TO_OK If the selftest has been passed successfully
 * @retval TO_ERROR If an error has been detected during the test
 */
extern TO_lib_ret_t TODRV_SSE_nvm_self_test(void);

/**
 * @brief Self-test TO-Protect.
 *
 * In order to verify that TO-Protect is correctly flashed and not corrupted,
 * we recommend to call this function while in development mode.
 *
 * @return TO_OK in case of success, error otherwise
 */
extern TO_lib_ret_t TODRV_SSE_top_self_test(void);

/**
 * @brief Enables providing the base address of TO-Protect when it's obtained
 * dynamically.
 *
 * @param sse_top_address TOP Address of TO-Protect
 * @return TO_lib_ret_t return code
 * @retval TO_OK If data has been read successfully
 */
extern TO_lib_ret_t TODRV_SSE_set_top_address(void *sse_top_address);

/** @} */

#ifdef __cplusplus
}
#endif

#endif // TODRV_SSE_DRIVER_DISABLE

#endif // _TODRV_SSE_H_

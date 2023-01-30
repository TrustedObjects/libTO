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

#ifndef _TODRV_SSE_DRIVER_H_
#define _TODRV_SSE_DRIVER_H_

#include "TODRV_SSE_cfg.h"
#include "TOP_vt.h"

#ifdef TODRV_SSE_TOP_ADDRESS
#define TODRV_SSE_TOP_API_ADDRESS TODRV_SSE_TOP_ADDRESS
#define TODRV_SSE_TOP_OFFSET_ADDRESS TODRV_SSE_TOP_ADDRESS
#else
#define TODRV_SSE_TOP_API_ADDRESS &TOP_vt
#define TODRV_SSE_TOP_OFFSET_ADDRESS 0
#endif

/**
 * @brief NVM load function for accessing the secure storage.
 * @param[out] dst Data destination
 * @param[in] src Address to read, related to Secure Storage base address.
 * @param[in] size Data length
 * @details
 * This function is used by TO-Protect to read data from NVM. You have
 * to implement this function with read NVM function of your platform.
 * It is supposed performing :
 * - Check the address/length validity
 * - If they are not both correct, return TO_ERROR
 * - Perform the read operation from (*src) to (*dst) over size bytes
 * - If anything went wrong, return TO_ERROR
 * - Return TO_OK
 * @warning
 * @return TO_lib_ret_t return code
 * @retval TO_OK If data has been read successfully
 * @retval TO_ERROR If something went wrong, resulting in the data read not
 * to be reliable.
 * TO_lib_ret_t TODRV_SSE_secure_storage_load(uint8_t *data, const void *offset, uint32_t size)
 */
typedef TO_lib_ret_t TOP_secure_storage_load_func_t(void *dst,
		const void *src,
		uint32_t size);

/**
 * @brief NVM store function for accessing the secure storage.
 * @param[out] dst Address to write, related to Secure Storage base address
 * This address will always be the first address of a sector, if correctly
 * defined. TO-Protect will never perform partial write operations, only
 * write operations involving a full set of sectors write.
 * @param[in] src Data source. This pointer is always located in RAM.
 * @param[in] size Data length, corresponds to the full data set to be written in
 * NVM, TO-Protect will never write portions of the secure storage located in NVM.
 * @details
 * This function is always called with offset on beginning of a sector.
 * This function must prepare the NVM support for writing, typically by erasing sectors before write on Flash devices
 * There is no need to save a sector before writing (erasing) it, even if size is not a multiple of a sector.
 * The rest of the sector is considered as lost.
 * It is supposed performing :
 * - Check the address/length validity
 * - If they are not both correct, return TO_ERROR
 * - Perform the write operation from (*src) to (*dst) over size bytes
 * - If anything went wrong, return TO_ERROR
 * - Return TO_OK
 * @warning The caller of this function makes the assumption that returning
 * TO_OK means :
 * - That the received destination address/size was correct
 * - That the received source address/size was correct
 * - That after the write operation is complete, the NVM contains the new bytes,
 * pointed by (*src), over size bytes.
 * @return TO_lib_ret_t return code
 * @retval TO_OK If data has been read successfully
 * @retval TO_ERROR If something went wrong, resulting in the write read not
 * to be reliable.
 * TO_lib_ret_t TODRV_SSE_secure_storage_store(void *offset, const uint8_t *data, uint32_t size)
 */
typedef TO_lib_ret_t TOP_secure_storage_store_func_t(void *dst,
		const void *src,
		uint32_t size);

#endif /* _TODRV_SSE_DRIVER_H_ */

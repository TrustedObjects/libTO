/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2022 Trusted Objects. All rights reserved.
 */

/**
 * @file hal_nvm_lx6.c
 * @brief Exemple of HAL NVM implementation for LX6
 * using ESP-IDF (Espressif IoT Development Framework)
 */

/*
 * USAGE:
 *
 * Typically in your main(),  call in this order
 *
 *   - HAL_nvm_secure_storage_init();
 *   - TOSE_init(&se_ctx);
 *   - ... { Run your application }  ...
 *   - HAL_nvm_secure_storage_deinit();  { OPTIONAL, when exiting main() }
 *
 * Then, when required, the two following callback functions will be called by
 * TO-PROTECT to manage the Secure Storage
 *
 *   - TODRV_SSE_secure_storage_load(dst_ptr, src_offset, size);
 *   - TODRV_SSE_secure_storage_store(dst_offset, src_ptr, size);
 *
 * At the beginning of a project, we recommend using the HAL NVM Self-Tests
 * to validate your implementation
 */

/******************************************************************************/
/* Includes                                                                   */
/******************************************************************************/

#include "TO.h"
#include "TOP.h"
#include "TODRV_SSE_cfg.h"

#include "TOP_info.h"

#include "esp_log.h"
#include "esp_partition.h"

/******************************************************************************/
/* Customer settings (NVM base address, NVM sector size, ...)                 */
/******************************************************************************/

/* See TOP_info.h/TOP_SECURE_STORAGE_NVM_FOOTPRINT; align value to a number of sectors */
/* This value must be consistent with your partition table (partitions.csv) */
#define SECURE_STORAGE_NVM_SIZE (2 * (((TOP_SECURE_STORAGE_NVM_FOOTPRINT + TODRV_SSE_NVM_SECTOR_SIZE -1) / TODRV_SSE_NVM_SECTOR_SIZE) * TODRV_SSE_NVM_SECTOR_SIZE))

/******************************************************************************/
/* NVM HAL implementation options (expert mode: do NOT modify)                */
/******************************************************************************/

#define SECURE_STORAGE_DBG_CHECK_WRITTEN_DATA 1

/******************************************************************************/
/* Debug / Logging options                                                    */
/******************************************************************************/

static const char *TAG = "hal_nvm";

#define FLASH_LOG_ERR(format, ...)     ESP_LOGE(TAG, format, ##__VA_ARGS__)
#define FLASH_LOG_WRN(format, ...)     ESP_LOGW(TAG, format, ##__VA_ARGS__)
#define FLASH_LOG_DBG(format, ...)     ESP_LOGD(TAG, format, ##__VA_ARGS__)
#define FLASH_LOG_INF(format, ...)     ESP_LOGI(TAG, format, ##__VA_ARGS__)
#define FLASH_LOG_VB(format, ...)      ESP_LOGV(TAG, format, ##__VA_ARGS__)
#define FLASH_LOG_FUNC(format, ...)    //ESP_LOGD(TAG, format, ##__VA_ARGS__)
// TODO: over 64 bytes, that's the mess, thus the "MIN" usage
#define FLASH_LOG_INF_BUF(dst, size)   ESP_LOG_BUFFER_HEXDUMP(TAG, dst, MIN(size, 64), LOG_LOCAL_LEVEL  )
#define FLASH_LOG_DBG_BUF(dst, size)   //ESP_LOG_BUFFER_HEXDUMP(TAG, dst, MIN(size, 64), LOG_LOCAL_LEVEL  )

/******************************************************************************/
/* HAL NVM Private functions                                                  */
/******************************************************************************/

#define STRING_TO_PROTECT_PARTITION "to-protect"
#define STRING_SECURE_STORAGE_PARTITION "secure-storage"

typedef struct lx6_to_protect_context {
	const esp_partition_t *partition_securestorage;
	const void *map_ptr_securestorage;
	spi_flash_mmap_handle_t map_handle_securestorage;

} lx6_top_context_t;

static lx6_top_context_t _ctx;

static void mmu_setup(void)
{
	// Map the secure storage
	_ctx.partition_securestorage = esp_partition_find_first(ESP_PARTITION_TYPE_ANY,
			ESP_PARTITION_SUBTYPE_ANY,
			"secure-storage");
	assert(_ctx.partition_securestorage != NULL);
	esp_partition_mmap(_ctx.partition_securestorage,
			0,
			_ctx.partition_securestorage->size,
			SPI_FLASH_MMAP_DATA,
			&_ctx.map_ptr_securestorage,
			&_ctx.map_handle_securestorage);

	ESP_LOGI(TAG, "SecureStorage is at address 0x%p!", _ctx.map_ptr_securestorage);
	FLASH_LOG_DBG_BUF(_ctx.map_ptr_securestorage,48);
}

void mmu_deinit(void)
{
		// Unmap the Secure Storage
	spi_flash_munmap(_ctx.map_handle_securestorage);
}

/******************************************************************************/
/* HAL NVM public functions                                                   */
/******************************************************************************/

/**
 * @brief Initialize the Secure Storage driver
 *
 * @warning MUST be called before TOSE_init() is called.
 * Typically call in beginning of main()
 */
TO_lib_ret_t HAL_nvm_secure_storage_init(void)
{
	mmu_setup();

	return TO_OK;
}

/**
 * @brief Uninitialize the Secure Storage driver
 *
 * @warning MUST be called before TOSE_init() is called.
 * Typically call when exiting main()
 */
TO_lib_ret_t HAL_nvm_secure_storage_deinit(void)
{
	mmu_deinit();

	return TO_OK;
}

/******************************************************************************/
/* HAL NVM interface, called by TO-Protect                                    */
/******************************************************************************/

/**
 * @brief Secure storage loading function.
 * (see to-protect User Manual / TOP_secure_storage_load_func_t)
 *
 * @param dst Destination buffer (located in RAM) receiving the read data
 * @param src_offset Offset from the beginning of the secure-storage area to read the data from.
 * This offset will always be a multiple of a sector size.
 * @param size The number of bytes to be read
 *
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
TO_lib_ret_t TODRV_SSE_secure_storage_load(uint8_t *dst, uint32_t src_offset, uint32_t size)
{
	esp_err_t ret;

	FLASH_LOG_FUNC ("  >>> TODRV_SSE_secure_storage_load (dst=%p, address=%p, size=%d)\n", dst, _ctx.map_ptr_securestorage + src_offset, size);

	if ((src_offset + size) > SECURE_STORAGE_NVM_SIZE) {
		FLASH_LOG_ERR("Bad offset %08x or size %d\n", src_offset, (int)size);
		return TO_ERROR;
	}

	ret = esp_partition_read(_ctx.partition_securestorage, src_offset, dst, size);

	if (ret != ESP_OK) {
		FLASH_LOG_ERR("Failed to read %d bytes at offset 0x%08x with error %d\n", size, src_offset, ret);
		goto memory_error;
	} else {
		FLASH_LOG_DBG(">>> Load OK from 0x%08x\n", src_offset);
	}

	FLASH_LOG_DBG_BUF(dst, size);

	FLASH_LOG_FUNC ("  <<< TODRV_SSE_secure_storage_load ()\n");
	return TO_OK;

memory_error:
	FLASH_LOG_FUNC("<<< TODRV_SSE_secure_storage_store() MEMORY ERROR\n");
	return TO_ERROR;
}

/**
 * @brief Secure storage storing function.
 * (see to-protect User Manual / TOP_secure_storage_store_func_t)
 *
 * @param dst_offset Offset from the beginning of the secure-storage area to read the data from.
 * This offset will always be a multiple of a sector size.
 * All the data, located at the end of a sector won't have to be written. Whatever their value,
 * they are considered unused.
 * @param src Source pointer (located in RAM) containing the data to be written
 * @param size The number of bytes to be written
 *
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
TO_lib_ret_t TODRV_SSE_secure_storage_store(uint32_t dst_offset, const uint8_t *src, uint32_t size)
{
	esp_err_t ret;
	int erase_size;

	FLASH_LOG_FUNC(">>> TODRV_SSE_secure_storage_store(dst_offset=%08x, src=%p, size=%d\n", dst_offset, src, size);

	if ((dst_offset + size) > SECURE_STORAGE_NVM_SIZE) {
		FLASH_LOG_ERR("Bad offset %x or size %d\n", dst_offset, (int)size);
		return TO_ERROR;
	}

	/* Data needs to be erased first */

	/* esp_partition_erase_range:
		size – Size of the range which should be erased, in bytes.
		       Must be divisible by 4 kilobytes.
	*/
	erase_size = ((size + TODRV_SSE_NVM_SECTOR_SIZE -1) / TODRV_SSE_NVM_SECTOR_SIZE) * TODRV_SSE_NVM_SECTOR_SIZE;

	ret = esp_partition_erase_range(_ctx.partition_securestorage, dst_offset, erase_size);

	if (ret != ESP_OK) {
		FLASH_LOG_ERR("Failed to erase %d bytes at offset 0x%08x with error %d\n", erase_size, dst_offset, ret);
		goto memory_error;
	} else {
		FLASH_LOG_DBG(">>> Erase (size %d) OK at 0x%08x\n", erase_size, dst_offset);
	}

	/* write data in the partion */

	ret = esp_partition_write(_ctx.partition_securestorage, dst_offset, src, size);

	if (ret != ESP_OK) {
		FLASH_LOG_ERR("Failed to write %d bytes at offset 0x%08x with error %d\n", size, dst_offset, ret);
		goto memory_error;
	} else {
		FLASH_LOG_DBG(">>> Store OK at 0x%08x\n", dst_offset);
	}

#if SECURE_STORAGE_DBG_CHECK_WRITTEN_DATA == 1

	/* Double-check written data */
	if ((ret = memcmp((char *)_ctx.map_ptr_securestorage + dst_offset, src, size)) != 0) {
		FLASH_LOG_ERR("memcmp returns %d - Wrote data differs (in size=%d)\n", ret, size);
		FLASH_LOG_DBG("Data to write:\n");
		FLASH_LOG_DBG_BUF(src, size);
		FLASH_LOG_DBG("Data written:\n");
		FLASH_LOG_DBG_BUF((char *)_ctx.map_ptr_securestorage + dst_offset, size);
		goto memory_error;
	} else {
		FLASH_LOG_DBG("Write double-checked OK\n");
	}

#endif /* SECURE_STORAGE_DBG_CHECK_WRITTEN_DATA */

	FLASH_LOG_FUNC("<<< TODRV_SSE_secure_storage_store()\n");
	return TO_OK;

memory_error:
	FLASH_LOG_FUNC("<<< TODRV_SSE_secure_storage_store() MEMORY ERROR\n");
	return TO_ERROR;
}


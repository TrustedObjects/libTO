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
 * @file hal_nvm_mbed.cpp
 * @brief Exemple of HAL NVM implementation for LX6 (uses FlashIAP interface).
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
#include "mbed.h"

/******************************************************************************/
/* Customer settings (NVM base address, NVM sector size, ...)                 */
/******************************************************************************/

/* Customer choice: Base Address of Reserved NVM for Secure Storage */
#define SECURE_STORAGE_NVM_ADDRESS 0x8080000

/* See TOP_info.h/TOP_SECURE_STORAGE_NVM_FOOTPRINT; align value to a number of sectors */
#define SECURE_STORAGE_NVM_SIZE (32*2048)

/* TODRV_SSE_NVM_SECTOR_SIZE. Platform dependant
   for example:
	- NXP K66F: 4096
	- STM32L152RE: 4096
	- STM32L072CZ (flash_secure_storage): 4096
	- STM32L072CZ (EEPROM): 4
	- STM32L475: 2048
   Should be defined e.g. in TO_user_config.h if you defined TO_USER_CONFIG
   or you can update TODRV_SSE_cfg.h
   or you can define on compiler command line, e.g -DTODRV_SSE_NVM_SECTOR_SIZE=2048
*/

#if !defined(TODRV_SSE_NVM_SECTOR_SIZE)
#error "You must define TODRV_SSE_NVM_SECTOR_SIZE with your MCU NVM \n"
#endif

/******************************************************************************/
/* NVM HAL implementation options (expert mode: do NOT modify)                */
/******************************************************************************/

#define SECURE_STORAGE_DBG_CHECK_WRITTEN_DATA 1

/******************************************************************************/
/* NVM HAL is called by "C" code to-protect and called by project C/C++ files */
/* => Indicate C/C++ conversion                                               */
/******************************************************************************/

extern "C" {

	/* called by customer firmware */
	TO_lib_ret_t HAL_nvm_secure_storage_init(void);
	TO_lib_ret_t HAL_nvm_secure_storage_deinit(void);

	/* called by TO-Protect C code */
	TO_lib_ret_t TODRV_SSE_secure_storage_load(uint8_t *dst, uint32_t src_offset, uint32_t size);
	TO_lib_ret_t TODRV_SSE_secure_storage_store(uint32_t dst_offset, const uint8_t *src, uint32_t size);
}

/******************************************************************************/
/* NVM HAL's FlashIAP implementation with MBed OS                             */
/******************************************************************************/

static FlashIAP flash_secure_storage;

/******************************************************************************/
/* Debug / Logging options                                                    */
/******************************************************************************/

#define FLASH_LOG_ERR(...)     TO_LOG_ERR(__VA_ARGS__)
#define FLASH_LOG_DBG(...)     TO_LOG_DBG(__VA_ARGS__)
#define FLASH_LOG_INF(...)     TO_LOG_INF(__VA_ARGS__)
#define FLASH_LOG_FUNC(...)    TO_LOG_INF(__VA_ARGS__)
#define FLASH_LOG_INF_BUF(...) TO_LOG_DBG_BUF(__VA_ARGS__)
#define FLASH_LOG_DBG_BUF(...) TO_LOG_DBG_BUF(__VA_ARGS__)

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
	int ret;

	ret = flash_secure_storage.init();

	if (ret == 0) {
		FLASH_LOG_INF("flash_secure_storage.init() done\n");
	} else {
		FLASH_LOG_ERR("flash_secure_storage.init() returned %x\n", (unsigned int)ret);
		return TO_ERROR;
	}

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
	int ret;

	ret = flash_secure_storage.deinit();

	if (ret == 0) {
		FLASH_LOG_INF("flash_secure_storage.deinit() done\n");
	} else {
		FLASH_LOG_ERR("flash_secure_storage.deinit() returned %x\n", (unsigned int)ret);
		return TO_ERROR;
	}

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
	int ret;

	FLASH_LOG_FUNC ("  >>> TODRV_SSE_secure_storage_load (src_offset=%08x, size=%d\n", src_offset, size);

	if ((src_offset + size) > SECURE_STORAGE_NVM_SIZE) {
		FLASH_LOG_ERR("Bad offset 0x%x or size %u\n", (unsigned)src_offset, (unsigned)size);
		return TO_ERROR;
	}

	if ((ret = flash_secure_storage.read(dst, SECURE_STORAGE_NVM_ADDRESS + src_offset, size)) != 0) {
		return TO_ERROR;
	}

	FLASH_LOG_DBG_BUF(dst, size);
	FLASH_LOG_FUNC ("  <<< TODRV_SSE_secure_storage_load ()\n");

	return TO_OK;
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
	int ret;
	int program_size;
	uint32_t sector_size;
	uint32_t addr_flash_secure_storage;

#if SECURE_STORAGE_DBG_CHECK_WRITTEN_DATA == 1
	uint32_t in_address = SECURE_STORAGE_NVM_ADDRESS + dst_offset;
	const uint8_t *in_data = src;
	uint32_t in_size = size;
#endif /* SECURE_STORAGE_DBG_CHECK_WRITTEN_DATA */

	FLASH_LOG_FUNC(">>> TODRV_SSE_secure_storage_store(dst_offset=%08x, size=%u\n", (unsigned)dst_offset, (unsigned)size);

	if ((dst_offset + size) > SECURE_STORAGE_NVM_SIZE) {
		FLASH_LOG_ERR("Bad offset 0x%x or size %u\n", (unsigned)dst_offset, (unsigned)size);
		return TO_ERROR;
	}

	addr_flash_secure_storage = SECURE_STORAGE_NVM_ADDRESS + dst_offset;

	/* 1) calculate number of sectors involved */
	sector_size = flash_secure_storage.get_sector_size(addr_flash_secure_storage);
	if (sector_size != TODRV_SSE_NVM_SECTOR_SIZE) {
		FLASH_LOG_ERR("Error in your NVM HAL platform configuration.\n");
		FLASH_LOG_ERR("TODRV_SSE_NVM_SECTOR_SIZE=%d; flash_secure_storage.get_sector_size() says: %d\n", TODRV_SSE_NVM_SECTOR_SIZE, (int)sector_size);
		return TO_MEMORY_ERROR;
	}
	FLASH_LOG_DBG("sector_size=%d\n", sector_size);

	/* 2) erase all required sectors */
	/* 3) write all required sectors */

	/* FlashIAP interface requests "a multiple of the sector size" */
	program_size = ((size + sector_size -1)/sector_size) * sector_size;

	if ((ret = flash_secure_storage.erase((uint32_t)addr_flash_secure_storage, program_size)) != 0) {
		FLASH_LOG_ERR("Failed to erase sector at offset 0x%p with error %d\n", addr_flash_secure_storage, ret);
		goto memory_error;
	}

	if ((ret = flash_secure_storage.program(src, addr_flash_secure_storage, program_size)) != 0) {
		FLASH_LOG_ERR("Failed to write %d bytes at offset 0x%08x with error %d\n", (int)sector_size, addr_flash_secure_storage, ret);
		goto memory_error;
	} else {
		FLASH_LOG_DBG(">>> One sector written OK at 0x%08x\n", addr_flash_secure_storage);
	}

#if SECURE_STORAGE_DBG_CHECK_WRITTEN_DATA == 1
	/* Double-check written data */
	if ((ret = memcmp((void *)in_address, in_data, in_size)) != 0) {
		FLASH_LOG_ERR("memcmp returns %d - Wrote data differs (in size=%d)\n", ret, size);
		FLASH_LOG_ERR("Data to write:\n");
		FLASH_LOG_DBG_BUF(in_data, in_size);
		FLASH_LOG_ERR("Data written:\n");
		FLASH_LOG_DBG_BUF(in_address, in_size);
		return TO_ERROR;
	} else {
		FLASH_LOG_DBG("Write double-checked OK\n");
	}

#endif /* SECURE_STORAGE_DBG_CHECK_WRITTEN_DATA */

	FLASH_LOG_FUNC("<<< TODRV_SSE_secure_storage_store()\n");
	return TO_OK;

memory_error:
	FLASH_LOG_FUNC("<<< TODRV_SSE_secure_storage_store() MEMORY ERROR\n");
	return TO_MEMORY_ERROR;
}

#pragma GCC diagnostic ignored "-Wpedantic"

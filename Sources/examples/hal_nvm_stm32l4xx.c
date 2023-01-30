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
 * @file nvm_hal_stm32l4xx.c
 * @brief Secure storage example on STM32L4.
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

#include "stm32l4xx_hal.h"
#include "stm32l4xx_hal_flash_ex.h"

/******************************************************************************/
/* Definitions                                                                */
/******************************************************************************/

#if !defined(TODRV_SSE_TOP_ADDRESS)
#error "You must define TODRV_SSE_TOP_ADDRESS with TO-Protect address\n"
#endif

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

#define FLASH_START_ADDRESS FLASH_BASE  /* FLASH_BASE: see stm32l475xx.h */

/******************************************************************************/
/* Customer settings (NVM base address, NVM sector size, ...)                 */
/******************************************************************************/

/* Customer choice: Base Address of Reserved NVM for Secure Storage */
#define SECURE_STORAGE_NVM_ADDRESS 0x80A0000  // TODO: For tests , put far away !!!

/* See TOP_info.h/TOP_SECURE_STORAGE_NVM_FOOTPRINT; align value to a number of sectors */
#define SECURE_STORAGE_NVM_SIZE (32*2048)

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
/* HAL NVM private functions declarations                                     */
/******************************************************************************/

static TO_lib_ret_t _secure_storage_erase(const uint32_t flash_address, uint32_t size);
static TO_lib_ret_t _secure_storage_program(const uint32_t flash_address, const uint8_t *src, uint32_t size);

/******************************************************************************/
/* HAL NVM public functions                                                   */
/******************************************************************************/

/**
 * @brief Initialize the Secure Storage driver
 *
 * @warning MUST be called before TOSE_init() is called
 * Typically call in beginning of main()
 */

TO_lib_ret_t HAL_nvm_secure_storage_init(void)
{
	// TODO: something to do with STM32 HAL ?
	return TO_OK;
}

/**
 * @brief Uninitialize the Secure Storage driver
 *
 * @warning MUST be called before TOSE_init() is called
 * Typically call when exiting main()
 */

TO_lib_ret_t HAL_nvm_secure_storage_deinit(void)
{
	// TODO: something to do with STM32 HAL ?
	return TO_OK;
}

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
	const void *address;

	FLASH_LOG_FUNC ("  >>> TODRV_SSE_secure_storage_load (address=%08x, size=%d\n", (uint32_t)src_offset, size);

	if ((src_offset + size) > SECURE_STORAGE_NVM_SIZE) {
		printf("Bad address %x or size %u\n", (unsigned)src_offset, (unsigned)size);
		return TO_ERROR;
	}

	address = (const void *)(SECURE_STORAGE_NVM_ADDRESS + src_offset);
	memcpy(dst, address, size);

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
	uint32_t flash_address;

	FLASH_LOG_FUNC(">>> TODRV_SSE_secure_storage_store(address=%08x, size=%d\n", dst_offset, size);

	if ((dst_offset + size) > (uint32_t)SECURE_STORAGE_NVM_SIZE) {
		FLASH_LOG_ERR("Bad offset 0x%x or size %d\n", dst_offset, (int)size);
		return TO_ERROR;
	}

	flash_address = SECURE_STORAGE_NVM_ADDRESS + dst_offset;

	/* 1) erase all required sectors */
	if ((ret = _secure_storage_erase((uint32_t)flash_address, size)) != TO_OK) {
		FLASH_LOG_ERR("Failed to erase flash at offset 0x%x with error %d\n", flash_address, ret);
		goto memory_error;
	}

	/* 3) program */
	if ((ret = _secure_storage_program((uint32_t)flash_address, src, size)) != TO_OK) {
		FLASH_LOG_ERR("Failed to program flash at offset 0x%x with error %d\n", flash_address, ret);
		goto memory_error;
	}

	FLASH_LOG_FUNC("<<< TODRV_SSE_secure_storage_store()\n");
	return TO_OK;

memory_error:
	FLASH_LOG_FUNC("<<< TODRV_SSE_secure_storage_store() MEMORY ERROR\n");
	return TO_MEMORY_ERROR;
}

/******************************************************************************/
/* HAL NVM private functions                                                   */
/******************************************************************************/

/**
 * @brief NVM erase function.
 *
 * @param[in] flash_address Address to erase
 * @param[in] nb_sectors number of sectors to erase
 *
 * @return TO_OK if data has been erased successfully, else TO_MEMORY_ERROR
 */
static TO_lib_ret_t _secure_storage_erase(const uint32_t flash_address, uint32_t size)
{
	uint32_t nb_sectors;
	HAL_StatusTypeDef ret;
	uint32_t PAGEError = 0;

	/* 1) calculate number of sectors involved */
	nb_sectors = (size + (TODRV_SSE_NVM_SECTOR_SIZE-1)) / TODRV_SSE_NVM_SECTOR_SIZE;
	FLASH_LOG_FUNC(">>> _secure_storage_erase(address=0x%x, nb_sectors=%d\n", flash_address, nb_sectors);

	HAL_FLASH_Unlock();

	FLASH_EraseInitTypeDef EraseInitStruct;
	EraseInitStruct.TypeErase = FLASH_TYPEERASE_PAGES;
	EraseInitStruct.Banks = FLASH_BANK_1;
	EraseInitStruct.Page = (flash_address - FLASH_START_ADDRESS) / TODRV_SSE_NVM_SECTOR_SIZE ;
	EraseInitStruct.NbPages = nb_sectors;

	printf ("EraseInitStruct.Page = %d ; EraseInitStruct.NbPages = %d \n", (int)EraseInitStruct.Page, (int)EraseInitStruct.NbPages);

 	__HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP|FLASH_FLAG_OPERR|FLASH_FLAG_WRPERR|FLASH_FLAG_PGAERR|FLASH_FLAG_PGSERR);
    	ret = HAL_FLASHEx_Erase(&EraseInitStruct, &PAGEError); //returns HAL_OK if success
	HAL_FLASH_Lock();

	if (ret != HAL_OK) {
		printf("Failed to erase word at offset 0x%x with error %u\n", (unsigned)flash_address, (unsigned)HAL_FLASH_GetError());
		FLASH_LOG_FUNC("<<< _secure_storage_erase() MEMORY ERROR\n");
		return TO_MEMORY_ERROR;
	}

	FLASH_LOG_FUNC("<<< _secure_storage_erase()\n");
	return TO_OK;
}

/**
 * @brief NVM program function.
 *
 * @param[in] flash_address Address to erase
 * @param[in] nb_sectors number of sectors to erase
 * @param[in] src source address in RAM
 *
 * @return TO_OK if data has been stored successfully, else TO_MEMORY_ERROR
 */
static TO_lib_ret_t _secure_storage_program(const uint32_t flash_address, const uint8_t *src, uint32_t size)
{
#if SECURE_STORAGE_DBG_CHECK_WRITTEN_DATA == 1
	const uint8_t *in_data = src;
	uint32_t in_size = size;
#endif /* SECURE_STORAGE_DBG_CHECK_WRITTEN_DATA */

	HAL_StatusTypeDef ret;
	uint64_t u64;
	uint32_t dst_address;

	// Ensure address is WORD-aligned, to avoid fault "Non-word aligned"
	if ((flash_address &0x03) != 0x00) {
		FLASH_LOG_ERR("address 0x%08x is not WORD aligned\n", flash_address);
		return TO_ERROR;
	}

	FLASH_LOG_INF("Write %d from src = %p to flash address %p\n", size, src, flash_address);

	dst_address = flash_address;

	HAL_FLASH_Unlock();

	// TODO: Add optimized version with FLASH_TYPEPROGRAM_FAST

	while (size) {

		u64 = *(uint64_t *)src;

		ret = HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, dst_address, u64);

		if (ret != HAL_OK) {
			FLASH_LOG_ERR("Failed to write at address 0x%08x with error %d\n", dst_address, ret);
			break;
		} else {
			FLASH_LOG_DBG(">>> One word written OK at 0x%08x\n", dst_address);
		}

		dst_address+= sizeof(u64);
		src += sizeof(u64);
		size -= sizeof(u64);
	}

	HAL_FLASH_Lock();

	if (ret != HAL_OK) {
		FLASH_LOG_FUNC("<<< _secure_storage_program() MEMORY ERROR \n");
		return TO_ERROR;
	}

	FLASH_LOG_INF("Write done up to 0x%p\n", (void *)dst_address);

#if SECURE_STORAGE_DBG_CHECK_WRITTEN_DATA == 1
	/* Double-check written data */
	if ((ret = memcmp((void *)flash_address, in_data, in_size)) != 0) {
		FLASH_LOG_ERR("memcmp returns %d - Wrote data differs (in size=%d)\n", ret, size);
		FLASH_LOG_ERR("Data to write:\n");
		FLASH_LOG_DBG_BUF(in_data, in_size);
		FLASH_LOG_ERR("Data written:\n");
		FLASH_LOG_DBG_BUF(flash_address, in_size);
		return TO_ERROR;
	} else {
		FLASH_LOG_DBG("Write double-checked OK\n");
	}

#endif /* SECURE_STORAGE_DBG_CHECK_WRITTEN_DATA */

	FLASH_LOG_FUNC("<<< _secure_storage_program()\n");
	return TO_OK;
}


/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2018 Trusted Objects. All rights reserved.
 */

/**
 * @file stm32_secure_storage.c
 * @brief Secure storage example on STM32.
 */

#if (defined(STM32L072xx) && !defined(STM32L0))
#define STM32L0
#endif

#if (defined (STM32L0) || defined(USE_STM32L0XX_NUCLEO))
#include "stm32l0xx_hal.h"
#include "stm32l0xx_hal_flash_ex.h"
#elif (defined (STM32L1) || defined(USE_STM32L1XX_NUCLEO))
#include "stm32l1xx_hal.h"
#include "stm32l1xx_hal_flash_ex.h"
#elif (defined (STM32L4) || defined(USE_STM32L4XX_NUCLEO))
#include "stm32l4xx_hal.h"
#include "stm32l4xx_hal_flash_ex.h"
#elif (defined (STM32F4) || defined(USE_STM32F4XX_NUCLEO))
#include "stm32f4xx_hal.h"
#include "stm32f4xx_hal_flash_ex.h"
#else
#define PLATFORM_NOT_SUPPORTED
#endif

#include "TO.h"

#if !defined(PLATFORM_NOT_SUPPORTED) && defined(TOSE_DRIVER_SSE)

#include "TOP.h"
#include "TODRV_SSE_cfg.h"

#include <string.h>

#if !defined(TODRV_SSE_TOP_ADDRESS)
#error "You must define TODRV_SSE_TOP_ADDRESS with TO-Protect address, for \n" \
	   "example:\n"
	   " - statically: -DTODRV_SSE_TOP_ADDRESS=0x8020000\n"
	   " - dynamically from linkerscript: -DTODRV_SSE_TOP_ADDRESS=__to_protect"
#endif

#if !defined(TODRV_SSE_NVM_ADDRESS)
#error "You must define TODRV_SSE_NVM_ADDRESS with secure storage NVM \n"
	   "reserved area address, for example:\n"
	   " - statically: -DTODRV_SSE_NVM_ADDRESS=0x8080000\n"
	   " - dynamically from HAL: -DTODRV_SSE_NVM_ADDRESS=FLASH_EEPROM_BASE\n"
	   " - dynamically from linkerscript: -DTODRV_SSE_NVM_ADDRESS=__secure_storage_start"
#endif

#if !defined(TODRV_SSE_NVM_BLOCK_SIZE)
#error "You must define TODRV_SSE_NVM_BLOCK_SIZE with your MCU NVM \n" \
	   "block size, for example:\n"
	   " - NXP K66F: -DTODRV_SSE_NVM_BLOCK_SIZE=4096\n"
	   " - STM32L152RE: -DTODRV_SSE_NVM_MAX_BLOCK_SIZE=4096\n"
	   " - STM32L072CZ (flash): -DTODRV_SSE_NVM_MAX_BLOCK_SIZE=4096\n"
	   " - STM32L072CZ (EEPROM): -DTODRV_SSE_NVM_MAX_BLOCK_SIZE=4"
#endif

#if !defined(TODRV_SSE_NVM_MAX_CYCLES)
#error "You must define TODRV_SSE_NVM_MAX_CYCLES with your MCU NVM \n" \
	   "properties, for example:\n"
	   " - NXP K66F: -DTODRV_SSE_NVM_MAX_CYCLES=50000\n"
	   " - STM32L152RE: -DTODRV_SSE_NVM_MAX_CYCLES=10000\n"
	   " - STM32L072CZ: -DTODRV_SSE_NVM_MAX_CYCLES=10000"
#endif

#define NVM_END_ADDRESS (TODRV_SSE_NVM_ADDRESS + TOP_NVM_SIZE(TODRV_SSE_NVM_BLOCK_SIZE))

TO_lib_ret_t TOP_secure_storage_read(const uint32_t address, uint8_t *data, const uint32_t size)
{
    if (address < (uint32_t)TODRV_SSE_NVM_ADDRESS || address + size > (uint32_t)NVM_END_ADDRESS) {
        printf("Bad address %p\n", (void*)address);
        return TO_ERROR;
    }

    memcpy(data, (uint8_t*)address, size);

    return TO_OK;
}

TO_lib_ret_t TOP_secure_storage_write(const uint32_t address, const uint8_t *data, const uint32_t size)
{
    HAL_StatusTypeDef ret;
    uint32_t u32;

    if (address < (uint32_t)TODRV_SSE_NVM_ADDRESS || address + size > (uint32_t)NVM_END_ADDRESS) {
        printf("Bad address %p\n", (void*)address);
        return TO_ERROR;
    }

    if (size != TODRV_SSE_NVM_BLOCK_SIZE) {
        printf("Bad size %lu\n", size);
        return TO_ERROR;
    }

    memcpy((uint8_t*)&u32, data, size);

    HAL_FLASHEx_DATAEEPROM_Unlock();
    ret = HAL_FLASHEx_DATAEEPROM_Program(FLASH_TYPEPROGRAMDATA_WORD, address, u32);
    HAL_FLASHEx_DATAEEPROM_Lock();

    if (ret != HAL_OK) {
        printf("Failed to write word at address %p with error %lx\n", (void*)address, HAL_FLASH_GetError());
        return TO_ERROR;
    }

    /* Check wrote data */
    if (memcmp((uint8_t*)address, data, size)) {
        printf("Wrote data differs\n");
        return TO_ERROR;
    }

    return TO_OK;
}

TO_lib_ret_t TOP_secure_storage_erase(const uint32_t address)
{
    HAL_StatusTypeDef ret;

    if (address % TODRV_SSE_NVM_BLOCK_SIZE) {
        printf("Un-aligned address %p\n", (void*)address);
        return TO_ERROR;
    }

    if (address < (uint32_t)TODRV_SSE_NVM_ADDRESS || address >= (uint32_t)NVM_END_ADDRESS) {
        printf("Bad address %p\n", (void*)address);
        return TO_ERROR;
    }

    HAL_FLASHEx_DATAEEPROM_Unlock();
#if defined(STM32L0)
    ret = HAL_FLASHEx_DATAEEPROM_Erase(address);
#elif defined(STM32L1)
    ret = HAL_FLASHEx_DATAEEPROM_Erase(FLASH_TYPEERASEDATA_WORD, address);
#endif
    HAL_FLASHEx_DATAEEPROM_Lock();

    if (ret != HAL_OK) {
        printf("Failed to erase word at address %p with error %lx\n", (void*)address, HAL_FLASH_GetError());
        return TO_ERROR;
    }

    return TO_OK;
}
#else
#error "Platform not supported or bad driver configuration"
#endif


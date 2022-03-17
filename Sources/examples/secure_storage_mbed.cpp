#ifndef DISABLE_TO

#include "TO.h"
#include "TOP.h"
#include "TODRV_SSE_cfg.h"

#include "mbed.h"

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

static FlashIAP flash;

TO_lib_ret_t TOP_secure_storage_read(const uint32_t address, uint8_t *data, const uint32_t size)
{
	int ret;

	if (address < (uint32_t)TODRV_SSE_NVM_ADDRESS || address + size > (uint32_t)NVM_END_ADDRESS) {
		printf("Bad address 0x%08lx\n", address);
		return TO_ERROR;
	}

	if ((ret = flash.read(data, address, size)) != 0) {
		return TO_MEMORY_ERROR;
	}

	return TO_OK;
}

TO_lib_ret_t TOP_secure_storage_write(const uint32_t address, const uint8_t *data, const uint32_t size)
{
	int ret;

	if (address < (uint32_t)TODRV_SSE_NVM_ADDRESS || address + size > (uint32_t)NVM_END_ADDRESS) {
		printf("Bad address 0x%08lx\n", address);
		return TO_ERROR;
	}

	if (size != flash.get_sector_size((uint32_t)TODRV_SSE_NVM_ADDRESS)) {
		printf("Bad write size %lu\n", size);
		return TO_ERROR;
	}

	if ((ret = flash.program(data, address, size)) != 0) {
		printf("Failed to write %lu bytes at address 0x%08lx with error %d\n", size, address, ret);
		return TO_MEMORY_ERROR;
	}

	/* Check wrote data */
	if (memcmp((void*)address, data, size)) {
		printf("Wrote data differs\n");
		return TO_ERROR;
	}

	return TO_OK;
}

TO_lib_ret_t TOP_secure_storage_erase(const uint32_t address)
{
	int ret;
#ifdef MBED_DEBUG
	const uint32_t sector_size = flash.get_sector_size((uint32_t)TODRV_SSE_NVM_ADDRESS);

	if (sector_size != TODRV_SSE_NVM_BLOCK_SIZE) {
		printf("Bad block size %u (detected: %lu)\n", TODRV_SSE_NVM_BLOCK_SIZE, sector_size);
		return TO_ERROR;
	}
#endif

	if (address % TODRV_SSE_NVM_BLOCK_SIZE) {
		printf("Un-aligned address %p\n", (void*)address);
		return TO_ERROR;
	}

	if (address < (uint32_t)TODRV_SSE_NVM_ADDRESS || address >= (uint32_t)NVM_END_ADDRESS) {
		printf("Bad address 0x%08lx\n", address);
		return TO_ERROR;
	}

	if ((ret = flash.erase(address, TODRV_SSE_NVM_BLOCK_SIZE)) != 0) {
		printf("Failed to erase sector at address 0x%08lx with error %d\n", address, ret);
		return TO_MEMORY_ERROR;
	}

	return TO_OK;
}
#endif /* DISABLE_TO */

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wpedantic"
#endif

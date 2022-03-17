/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2019-2021 Trusted Objects. All rights reserved.
 */

/**
 * @file secure_storage_ram.c
 * @brief Secure storage RAM based example (emulating NVM, for debug/test
 * purposes only).
 */
#include "TO.h"
#include "TOP.h"
#include "TODRV_SSE_cfg.h"

static uint8_t nvm[TOP_SECURE_STORAGE_NVM_FOOTPRINT];

#define CLEAR_BYTE 0xff

TO_lib_ret_t TODRV_SSE_secure_storage_read(uint8_t *data, const void *address,
		uint32_t size)
{
	if ((long unsigned int)address + size > sizeof(nvm)) {
		return TO_ERROR;
	}

	memcpy(data, nvm + (long unsigned int)address, size);

	return TO_OK;
}

TO_lib_ret_t TODRV_SSE_secure_storage_write(void *address, const uint8_t *data,
		uint32_t size)
{
	uint32_t i;

	if ((long unsigned int)address + size > sizeof(nvm)) {
		return TO_ERROR;
	}

	for (i = 0; i < size; ++i) {
		if (nvm[(long unsigned int)address + i] != CLEAR_BYTE) {
			return TO_ERROR;
		}
	}

	memcpy(nvm + (long unsigned int)address, data, size);

	return TO_OK;
}

TO_lib_ret_t TODRV_SSE_secure_storage_erase(void *address, uint32_t size)
{
	if ((long unsigned int)address + size > sizeof(nvm)) {
		return TO_ERROR;
	}

	memset(nvm + (long unsigned int)address, CLEAR_BYTE, size);

	return TO_OK;
}


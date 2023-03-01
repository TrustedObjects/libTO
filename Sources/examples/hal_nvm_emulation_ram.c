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

/**
 * @file secure_storage_ram.c
 * @brief Secure storage RAM based example (emulating NVM, for debug/test
 * purposes only).
 */
#include "TO.h"
#include "TOP.h"
#include "TODRV_SSE_cfg.h"


/// @brief This table has to be initialized with the actual Secure Storage content
uint8_t nvm[TOP_SECURE_STORAGE_NVM_FOOTPRINT];

TO_lib_ret_t TODRV_SSE_secure_storage_load(uint8_t *dst,
		uint32_t src_offset,
		uint32_t size)
{
	TO_LOG_ERR("\nLoad offset %d, size %d, dst %p.", src_offset, size, dst);
	if (src_offset + size > sizeof(nvm)) {
		TO_LOG_ERR("Sorry, but nvm is too short ! (offset %d, size %d, nvm is %d).", src_offset, size, sizeof(nvm));
	} else {

		memcpy(dst, nvm + src_offset, size);
	}

	return TO_OK;
}

TO_lib_ret_t TODRV_SSE_secure_storage_store(uint32_t dst_offset,
		const uint8_t *src,
		uint32_t size)
{
	TO_LOG_ERR("\nStore offset %d, size %d, src %p.", dst_offset, size, src);
	if (dst_offset + size > sizeof(nvm)) {
		TO_LOG_ERR("Sorry, but nvm is too short ! (offset %d, size %d, nvm is %d).", dst_offset, size, sizeof(nvm));
	} else {
		memcpy(nvm + dst_offset, src, size);
	}

	return TO_OK;
}

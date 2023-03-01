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

/**
 * @file TODRV_HSE_nvm.h
 * @brief
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#ifndef _TODRV_HSE_NVM_H_
#define _TODRV_HSE_NVM_H_

#ifndef TODRV_HSE_NVM_API
#ifdef __linux__
#define TODRV_HSE_NVM_API
#elif _WIN32
#define TODRV_HSE_NVM_API __declspec(dllexport)
#else
#define TODRV_HSE_NVM_API
#endif /* __LINUX__ */
#endif

#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

TODRV_HSE_NVM_API TO_ret_t TODRV_HSE_write_nvm(
		TODRV_HSE_ctx_t *ctx,
		const uint16_t offset,
		const void *data,
		unsigned int length,
		const uint8_t key[TO_AES_KEYSIZE]);

TODRV_HSE_NVM_API TO_ret_t TODRV_HSE_read_nvm(
		TODRV_HSE_ctx_t *ctx,
		const uint16_t offset,
		void *data,
		unsigned int length,
		const uint8_t key[TO_AES_KEYSIZE]);

TODRV_HSE_NVM_API TO_ret_t TODRV_HSE_get_nvm_size(
		TODRV_HSE_ctx_t *ctx,
		uint16_t *size);

#ifdef __cplusplus
}
#endif

#endif /* _TODRV_HSE_NVM_H_ */

#endif /* TODRV_HSE_DRIVER_DISABLE */


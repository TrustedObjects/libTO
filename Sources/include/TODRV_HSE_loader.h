/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2020 Trusted Objects. All rights reserved.
 */

/**
 * @file TODRV_HSE_loader.h
 * @brief Hardware Secure Element loader APIs
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#ifndef _TODRV_HSE_LOADER_H_
#define _TODRV_HSE_LOADER_H_

#ifndef TODRV_HSE_LOADER_API
#ifdef __linux__
#define TODRV_HSE_LOADER_API
#elif _WIN32
#define TODRV_HSE_LOADER_API __declspec(dllexport);
#else
#define TODRV_HSE_LOADER_API
#endif /* __LINUX__ */
#endif

#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

TODRV_HSE_LOADER_API TO_ret_t TODRV_HSE_loader_broadcast_get_info(
		TODRV_HSE_ctx_t *ctx,
		uint8_t loader_version[TO_SW_VERSION_SIZE],
		uint8_t software_version[TO_SW_VERSION_SIZE],
		uint8_t upgrade_version[TO_SW_VERSION_SIZE]);

TODRV_HSE_LOADER_API TO_ret_t TODRV_HSE_loader_broadcast_restore_loader(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t upgrade_version[TO_SW_VERSION_SIZE],
		const uint8_t minimum_version[TO_SW_VERSION_SIZE],
		const uint8_t cmac[TO_CMAC_SIZE],
		const uint8_t password[TO_LD_BCAST_RESTORE_PASSWORD_SIZE]);

TODRV_HSE_LOADER_API TO_ret_t TODRV_HSE_loader_broadcast_send_init_data(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t init_data[TO_LD_BCAST_INIT_DATA_SIZE],
		const uint8_t cmac[TO_CMAC_SIZE]);

TODRV_HSE_LOADER_API TO_ret_t TODRV_HSE_loader_broadcast_write_data(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *segment, uint16_t length);

TODRV_HSE_LOADER_API TO_ret_t TODRV_HSE_loader_broadcast_commit_release(
		TODRV_HSE_ctx_t *ctx, const uint8_t cmac[TO_CMAC_SIZE]);

TODRV_HSE_LOADER_API TO_ret_t TODRV_HSE_data_migration(TODRV_HSE_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _TODRV_HSE_LOADER_H_ */

#endif /* TODRV_HSE_DRIVER_DISABLE */


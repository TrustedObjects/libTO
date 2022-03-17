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
 * @file TOSE_loader.h
 * @brief Secure Element loader APIs
 */

#ifndef _TOSE_LOADER_H_
#define _TOSE_LOADER_H_

#ifndef TOSE_LOADER_API
#ifdef __linux__
#define TOSE_LOADER_API
#elif _WIN32
#define TOSE_LOADER_API __declspec(dllexport)
#else
#define TOSE_LOADER_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"

/** @addtogroup loader
 * @{ */

/**
 * @brief Get broadcast loader information
 * @param[in] ctx Pointer to the SE context
 * @param[out] loader_version Loader version
 * @param[out] software_version Current Secure Element firmware version
 * @param[out] upgrade_version Expected Secure Element firmware upgrade version
 *
 * If upgrade_version is not NULL, the Secure Element expected firmware upgrade
 * version is returned. The value 0.0.0 is returned if no specific version is
 * expected, as it was the case for loaders until 3.17.0.
 *
 * @return TORSP_SUCCESS on success
 */
TOSE_LOADER_API TO_ret_t TOSE_loader_broadcast_get_info(
		TOSE_ctx_t *ctx,
		uint8_t loader_version[TO_SW_VERSION_SIZE],
		uint8_t software_version[TO_SW_VERSION_SIZE],
		uint8_t upgrade_version[TO_SW_VERSION_SIZE]);

/**
 * @brief Restore loader-mode in order to install a new Secure Element
 * firmware release
 * @param[in] ctx Pointer to the SE context
 * @param[in] upgrade_version New Secure Element firmware version to be
 * installed
 * @param[in] minimum_version Minimum Secure Element firmware version required
 * to install this upgrade (set NULL for none)
 * @param[in] cmac Authentication code
 * @param[in] password Restore password
 *
 * Note: if this function succeeds, the Secure Element reboots automatically in
 * loader-mode. The Secure Element boot delay is to be respected before any
 * subsequent call to it.
 * To do this, TOSE_fini() and TOSE_init() can be called, as platform low-level
 * layers take care about this boot delay on Secure Element initialization.
 *
 * Note: if the function returns TORSP_UNKNOWN_CMD, you are probably already in
 * loader-mode, and you can continue with
 * TOSE_loader_broadcast_send_init_data().
 *
 * @return TORSP_SUCCESS on success
 */
TOSE_LOADER_API TO_ret_t TOSE_loader_broadcast_restore_loader(
		TOSE_ctx_t *ctx,
		const uint8_t upgrade_version[TO_SW_VERSION_SIZE],
		const uint8_t minimum_version[TO_SW_VERSION_SIZE],
		const uint8_t cmac[TO_CMAC_SIZE],
		const uint8_t password[TO_LD_BCAST_RESTORE_PASSWORD_SIZE]);

/**
 * @brief Initialize firmware upgrade session
 * @param[in] ctx Pointer to the SE context
 * @param[in] init_data Initialization data
 * @param[in] cmac Authentication code
 *
 * @return TORSP_SUCCESS on success
 */
TOSE_LOADER_API TO_ret_t TOSE_loader_broadcast_send_init_data(
		TOSE_ctx_t *ctx,
		const uint8_t init_data[TO_LD_BCAST_INIT_DATA_SIZE],
		const uint8_t cmac[TO_CMAC_SIZE]);

/**
 * @brief Write firmware data
 * @param[in] ctx Pointer to the SE context
 * @param[in] segment Firmware upgrade segment
 * @param[in] length Segment length
 *
 * @return TORSP_SUCCESS on success
 */
TOSE_LOADER_API TO_ret_t TOSE_loader_broadcast_write_data(
		TOSE_ctx_t *ctx,
		const uint8_t *segment, uint16_t length);

/**
 * @brief Apply new firmware upgrade
 * @param[in] ctx Pointer to the SE context
 * @param[in] cmac Authentication code
 *
 * Warning: do not power-off the Secure Element until this function returns.
 *
 * Note: if this function succeeds, the Secure Element reboots automatically in
 * firmware-mode. The Secure Element boot delay is to be respected before any
 * subsequent call to it.
 * To do this, TOSE_fini() and TOSE_init() can be called, as platform low-level
 * layers take care about this boot delay on Secure Element initialization.
 *
 * @return TORSP_SUCCESS on success
 */
TOSE_LOADER_API TO_ret_t TOSE_loader_broadcast_commit_release(
		TOSE_ctx_t *ctx, const uint8_t cmac[TO_CMAC_SIZE]);

/**
 * @brief To be called after installing a migration firmware on the Secure
 * Element
 * @param[in] ctx Pointer to the SE context
 *
 * This function, only available on a Secure Element migration firmware,
 * triggers the data migration.
 * Firmware updates may require Secure Element data to be transformed to be
 * usable by a new firmware. A migration firmware is used between the original
 * firmware and the new firmwares to ensure data is ready to be used by the new
 * firmware.
 *
 * On success, the Secure Element is automatically restored in loader-mode,
 * ready to have its new firmware installed.
 * On fail, for example due to power loss, you can retry to call this function.
 *
 * Note: this function is not callable in loader-mode, it is available only in
 * firmware-mode, on a migration firmware.
 *
 * @return TORSP_SUCCESS on success
 */
TOSE_LOADER_API TO_ret_t TOSE_data_migration(TOSE_ctx_t *ctx);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_LOADER_H_ */

/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2021 Trusted Objects. All rights reserved.
 */

/**
 * @file TOSE_helper_measured_boot.h
 * @brief
 */

#ifndef _TOSE_HELPER_MEASURED_BOOT_H_
#define _TOSE_HELPER_MEASURED_BOOT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"
#include "TO_retcodes.h"
#include "TOSE_measured_boot.h"
#include "TO_sha256.h"
#include "TO_log.h"

/**
 * @brief The goal of this function is to obtain a measure (hash) of
 * the given firmware and store this value in "Measured hash" memory slot.
 * @param[in] hash_ctx Hash_ctx SE or software context, used for hash computation
 * @param[in] se_ctx SE context
 * @param[in] fw_addr Start address of firmware
 * @param[in] fw_length Firmware length in bytes
 *
 * @return TO_OK on success
 */
extern TO_ret_t TOSE_helper_measured_boot( /* A8 */
		TOSE_ctx_t *hash_ctx, TOSE_ctx_t *hw_ctx,
		const uint8_t* fw_addr, uint32_t fw_length);

/**
 * @brief The goal of this function is to validate a firmware against a hash
 * previously validated and stored in "Trusted new hash" memory slot.
 * @param[in] hash_ctx Hash_ctx SE or software context, used for hash computation
 * @param[in] hw_ctx SE context
 * @param[in] fw_addr Start address of Firmware
 * @param[in] fw_length MCU FW length in bytes
 *
 * @return TO_OK on success
 */
extern TO_ret_t TOSE_helper_validate_update_fw_hash( /* A3 */
		TOSE_ctx_t *hash_ctx, TOSE_ctx_t *hw_ctx,
		const uint8_t* fw_addr, uint32_t fw_length);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_HELPER_MEASURED_BOOT_H_ */

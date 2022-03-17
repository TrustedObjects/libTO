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
 * @file TOSE_measured_boot.h
 * @brief APIs to provide measured boot functionalities
 * @author Trusted-Objects, Roberto Grossi <r.grossi@trusted-objects.com>
 */

#ifndef _TOSE_MEASURED_BOOT_H_
#define _TOSE_MEASURED_BOOT_H_

#ifndef TOSE_MEASURED_BOOT_API
#ifdef __linux__
#define TOSE_MEASURED_BOOT_API
#elif _WIN32
#define TOSE_MEASURED_BOOT_API __declspec(dllexport)
#else
#define TOSE_MEASURED_BOOT_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"

/** @addtogroup measured_boot
 * @{ */

/**
 * @brief The goal of this function is to store the measured (hash) of the new
 * Frimware in "Measured hash" memory slot.
 * @param[in] ctx SE context.
 * @param[in] hash Hash of the newly flashed MCU firmware
 * @param[in] hash_length Hash length in bytes
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_INVALID_PARAM: invalid firmware hash length
 * - TO_ERROR: generic error
 */
TOSE_MEASURED_BOOT_API TO_ret_t TOSE_measured_boot(TOSE_ctx_t *ctx,
		const uint8_t *hash, uint16_t hash_length); /* A1 */

/**
 * @brief Function to validate new Firmware hash (input) by comparing it with
 * hash already stored in "Trusted new hash" (by API A5).
 * @param[in] ctx SE context.
 * @param[in] hash Computed MCU firmware hash.
 * @param[in] hash_length Hash length in bytes.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_INVALID_PARAM: invalid firmware hash length
 * - TO_ERROR: generic error, including invalid new MCU FW hash
 */
TOSE_MEASURED_BOOT_API TO_ret_t TOSE_validate_new_fw_hash(TOSE_ctx_t *ctx,
		const uint8_t* hash, uint16_t hash_length); /* A4 */

/**
 * @brief Replace current Firmware hash value
 *
 * If the MAC of the challenge is verified, this function replaces current
 * firmware hash value (stored in "Trusted boot hash" location) with the value
 * of a previous measure stored in "Trusted new hash".
 * Stored challenge is erased regardless of the outcome.
 *
 * Note: if the MAC is not verified, the challenge stored in the Secure Element
 * is destroyed. You have to call TOSE_get_challenge_and_store() to generate a
 * new challenge before calling this function again.
 *
 * @param[in] ctx SE context.
 * @param[in] signed_challenge The HMAC of the challenge previously requrested
 * by TOSE_get_challenge_and_store().
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error, including invalid new MCU FW hash.
 */
TOSE_MEASURED_BOOT_API TO_ret_t TOSE_commit_new_fw_hash(TOSE_ctx_t *ctx,
		const uint8_t signed_challenge[TO_HMAC_SIZE]); /* A9 */

/**
 * @brief Function goal is to store the hash value of the new firmware.
 *
 * The MAC is computed on the concatenation of the firmware hash and the
 * challenge.
 * The challenge is to be requested using TOSE_get_challenge_and_store() API.
 * if the MAC is valid, the hash value of the new firmware is stored.
 *
 * @param[in] ctx SE context.
 * @param[in] fw_hash New firmware hash.
 * @param[in] fw_hash_length Length in bytes of fw_hash.
 * @param[in] mac MAC of the firmware hash concatenated with the challenge.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_INVALID_PARAM: invalid firmware hash length
 * - TO_ERROR: generic error, including invalid new MCU FW hash or challenge
 */
TOSE_MEASURED_BOOT_API TO_ret_t TOSE_store_new_trusted_fw_hash(TOSE_ctx_t *ctx,
		const uint8_t* fw_hash, const uint16_t fw_hash_length,
		const uint8_t  mac[TO_HMAC_SIZE]); /* A5 */

/**
 * @brief Get boot measurement
 *
 * The goal of this function is to:
 * - Return the measure of the new firmware from "FW Measured hash".
 * - Accept a challenge.
 * - Notify, through outcome parameter, if the retrieved measure matches
 *   "Trusted boot FW hash", "Trusted new FW hash" or neither of them.
 * - Return mac of the Measured hash concatenated with given challenge
 *   HMAC("Measured hash" || outcome || challenge).
 *
 * @param[in] ctx SE context.
 * @param[out] fw_hash Measure of the new firmware.
 * @param[in] fw_hash_length Expected length in bytes of fw_hash, depending
 * upon the type of hash used.
 * @param[in] challenge given challenge.
 * @param[in] challenge_length Length of the challenge, in bytes.
 * @param[out] outcome Will hold one of the following values:
 * - FAILURE_NO_NEW : hash doesn't match "Trusted boot hash" value and "Trusted
 *   new hash" is empty,
 * - FAILURE : neither new "Trusted boot FW hash" value nor "Trusted new FW
 *   hash" are matched,
 * - CURRENT : measured value is equal to "Trusted boot hash".
 * - NEW : measured value is equal to "Trusted new hash".
 * @param[out] mac MAC of the new firmware concatenated outcome and
 * concatenated with challenge.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_INVALID_PARAM: invalid hash length or challenge length
 * - TO_ERROR: generic error, including invalid new MCU FW hash
 */
TOSE_MEASURED_BOOT_API TO_ret_t TOSE_get_boot_measurement(TOSE_ctx_t *ctx,
		uint8_t* fw_hash, uint16_t fw_hash_length,
		const uint8_t* challenge, uint16_t challenge_length,
		measure_outcome_t* outcome, uint8_t mac[TO_HMAC_SIZE]); /* A6 */

/**
 * @brief Get Secure Elemeent firmware measurement
 *
 * The goal of this function is to:
 * - Return the measure of the Secure Element firmware.
 * - Accept a challenge.
 * - Always return outcome = NEW.
 * - Return mac of the Measured hash concatenated with given challenge
 *   HMAC("Measured hash" || outcome || challenge).
 *
 * @param[in] ctx SE context.
 * @param[out] hash Measure of the Secure Element firmware.
 * @param[in] hash_length Expected length in bytes of hash, depending upon the
 * type of hash used.
 * @param[in] challenge given challenge.
 * @param[in] challenge_length Length of the challenge, in bytes.
 * @param[out] outcome Will always be NEW : measured value is equal to
 * "Trusted new hash".
 * @param[out] mac MAC of the Secure Element measure.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_INVALID_PARAM: invalid hash length or challenge length
 * - TO_ERROR: generic error
 */
TOSE_MEASURED_BOOT_API TO_ret_t TOSE_get_se_measurement(TOSE_ctx_t *ctx,
		uint8_t* hash, uint16_t hash_length,
		const uint8_t* challenge, uint16_t challenge_length,
		measure_outcome_t* outcome, uint8_t mac[TO_HMAC_SIZE]); /* A6 */

/**
 * @brief The goal of this function is to invalidate / reset the content of
 * "Trusted new hash" slot.
 *
 * Caller need to concatenate the invalidation password with a SHA256 of a
 * challenge requested from the Secure Element using
 * TOSE_get_challenge_and_store(), and compute a SHA256 hash on this
 * concatenation, to provide the resulting digest to this function.
 *
 * The challenge is erased on succeess.
 *
 * @param[in] ctx SE context.
 * @param[in] password_challenge_hash SHA256(password + SHA256(challenge).
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error, including invalid new MCU FW hash
 */
TOSE_MEASURED_BOOT_API TO_ret_t TOSE_invalidate_new_hash(TOSE_ctx_t *ctx,
		const uint8_t password_challenge_hash[TO_SHA256_HASHSIZE]);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_MEASURED_BOOT_H_ */

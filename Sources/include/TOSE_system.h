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
 * @file TOSE_system.h
 * @brief
 */

#ifndef _TOSE_SYSTEM_H_
#define _TOSE_SYSTEM_H_

#ifndef TOSE_SYSTEM_API
#ifdef __linux__
#define TOSE_SYSTEM_API
#elif _WIN32
#define TOSE_SYSTEM_API __declspec(dllexport)
#else
#define TOSE_SYSTEM_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"

/** @addtogroup system
 * @{ */

/**
 * @brief Returns the unique Secure Element serial number
 * @param[in] ctx Pointer to the SE context
 * @param[out] serial_number Secure Element serial number
 *
 * The Serial Number is encoded on 8 bytes :
 * - The first 3 bytes identify the application ID.
 * - The last 5 bytes are the chip ID. Each Secure Element has an unique serial number.
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
extern TOSE_SYSTEM_API TO_ret_t TOSE_get_serial_number(TOSE_ctx_t *ctx,
		uint8_t serial_number[TO_SN_SIZE]);

/**
 * @brief Returns the hardware serial number
 * @param[in] ctx Pointer to the SE context
 * @param[out] hardware_serial_number Hardware serial number
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
extern TOSE_SYSTEM_API TO_ret_t TOSE_get_hardware_serial_number(TOSE_ctx_t *ctx,
		uint8_t hardware_serial_number[TO_HW_SN_SIZE]);

/**
 * @brief Returns the Secure Element product number
 * @param[in] ctx Pointer to the SE context
 * @param[out] product_number Secure Element product number
 *
 * Product Number is a text string encoded on 12 bytes, e.g:
 * "TOSF-IS1-001"
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
extern TOSE_SYSTEM_API TO_ret_t TOSE_get_product_number(TOSE_ctx_t *ctx,
		uint8_t product_number[TO_PN_SIZE]);

/**
 * @brief Returns the Secure Element hardware version
 * @param[in] ctx Pointer to the SE context
 * @param[out] hardware_version Secure Element hardware version
 *
 * Hardware version is encoded on 2 bytes. Available values are:
 * - 00 00: Software
 * - 00 01: SCO136i
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
extern TOSE_SYSTEM_API TO_ret_t TOSE_get_hardware_version(TOSE_ctx_t *ctx,
		uint8_t hardware_version[TO_HW_VERSION_SIZE]);

/**
 * @brief Returns the Secure Element software version
 * @param[in] ctx Pointer to the SE context
 * @param[out] major Major number. When this byte changes, API changes have occurred, incompatibility issues may be met, depending on your application.
 * @param[out] minor Minor number. This byte is incremented when changes happen without breaking the API.
 * @param[out] revision Revision number. This byte is incremented on each new build (when released).
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
extern TOSE_SYSTEM_API TO_ret_t TOSE_get_software_version(TOSE_ctx_t *ctx,
		uint8_t* major, uint8_t* minor, uint8_t* revision);

/**
 * @brief Returns the Secure Element product identifier
 * @param[in] ctx Pointer to the SE context
 * @param[out] product_id Secure Element product identifier
 *
 * The product identifier is a text string, encoded on maximum 15 ASCII bytes.
 * It identifies the personalization profile.
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
extern TOSE_SYSTEM_API TO_ret_t TOSE_get_product_id(TOSE_ctx_t *ctx,
		uint8_t product_id[TO_PRODUCT_ID_SIZE]);

/**
 * @brief Returns a random number of the given length
 * @param[in] ctx Pointer to the SE context
 * @param[in] random_length Requested random length
 * @param[out] random Returned random number
 *
 * Request a random number to Secure Element random number generator.
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_NOT_AVAILABLE: random length out of range
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
extern TOSE_SYSTEM_API TO_ret_t TOSE_get_random(TOSE_ctx_t *ctx,
		const uint16_t random_length,
		uint8_t* random);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_SYSTEM_H_ */


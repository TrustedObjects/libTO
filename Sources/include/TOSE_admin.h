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
 * @file TOSE_admin.h
 * @brief
 */

#ifndef _TOSE_ADMIN_H_
#define _TOSE_ADMIN_H_

#ifndef TOSE_ADMIN_API
#ifdef __linux__
#define TOSE_ADMIN_API
#elif _WIN32
#define TOSE_ADMIN_API __declspec(dllexport)
#else
#define TOSE_ADMIN_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"

/** @addtogroup admin
 * @{ */

/**
 * @brief Initialize administration session.
 * @param[in] ctx Pointer to the SE context
 * @param[in] server_challenge Server challenge, coming from the server
 * @param[out] se_challenge Returned Secure Element challenge
 * @param[out] se_cryptogram Returned Secure Element cryptogram
 * @param[out] diversification_data Returned diversification data
 * @param[out] protocol_info Returned protocol info
 *
 * This function initializes a new administration session between a server and
 * the Secure Element.
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_ADMIN_API TO_ret_t TOSE_admin_session_init(TOSE_ctx_t *ctx,
		const uint8_t server_challenge[TO_ADMIN_CHALLENGE_SIZE],
		uint8_t se_challenge[TO_ADMIN_CHALLENGE_SIZE],
		uint8_t se_cryptogram[TO_ADMIN_CRYPTOGRAM_SIZE],
		uint8_t diversification_data[TO_ADMIN_DIVERS_DATA_SIZE],
		uint8_t protocol_info[TO_ADMIN_PROTO_INFO_SIZE]);

/**
 * @brief Activate administration session by authenticating server.
 * @param[in] ctx Pointer to the SE context
 * @param[in] options Administration session options
 * @param[in] server_cryptogram Server cryptogram, coming from the server
 * @param[in] mac MAC computed on options and server cryptogram
 *
 * This function allows the server to authenticate against the Secure Element,
 * in order to activate authentication session.
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_ADMIN_API TO_ret_t TOSE_admin_session_auth_server(TOSE_ctx_t *ctx,
		const uint8_t options[TO_ADMIN_OPTIONS_SIZE],
		const uint8_t server_cryptogram[TO_ADMIN_CRYPTOGRAM_SIZE],
		const uint8_t mac[TO_ADMIN_MAC_SIZE]);

/**
 * @brief Executes an authenticated administrative command.
 * @param[in] ctx Pointer to the SE context
 * @param[in] command Buffer containing the MACed command to be executed.
 * This buffer length is length + 8 bytes. It contains :
 * - 8 bytes for the AES-Cmac (using the admin session KMac key)
 * - N bytes of command, encrypted using SCP03 and KMAC (using ICV and AES-CBC).
 * Once decrypted, those contain :
 *   - N-16 bytes of command, encrypted with KENC (using the following IV and AES-CBC)
 *   - 16 bytes of IV, used for the second layer of encryption
 * @param[in] length Expresses the length of the Command, excluding the 8 bytes of CMAC at the start
 *
 * @cond libTO
 * @details The command is expected to be secure (encryption, MAC) according to the pre-defined administration protocol.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_ADMIN_API TO_ret_t TOSE_admin_command(TOSE_ctx_t *ctx, const uint8_t *command, uint16_t length);

/**
 * @brief Administration command with response data.
 * @param[in] ctx Pointer to the SE context
 * @param[in] command The command
 * @param[in] length The command length
 * @param[out] response Buffer to store response
 * @param[in] response_length Expected response length
 * @cond libTO
 * @details
 * The command and the response are expected to be secured (encrypted and MACed)
 * according to the pre-defined administration protocol.
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 * @endcond
 * @deprecated This function is deprecated and may disappear in future releases, use TOSE_admin_command_with_response2() instead.

 */
TOSE_ADMIN_API TO_ret_t TOSE_admin_command_with_response(TOSE_ctx_t *ctx, const uint8_t *command, uint16_t length,
		uint8_t *response, uint16_t response_length);

/**
 * @brief Administration command with response data with variable length.
 * @param[in] ctx Pointer to the SE context
 * @param[in] command The command
 * @param[in] length The command length
 * @param[out] response Buffer to store response
 * @param[inout] response_length Buffer length (input), response length (output)
 * @cond libTO
 * @details
 * The command and the response are expected to be secured (encrypted and MACed)
 * according to the pre-defined administration protocol.
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_ADMIN_API TO_ret_t TOSE_admin_command_with_response2(TOSE_ctx_t *ctx, const uint8_t *command, uint16_t length,
		uint8_t *response, uint16_t *response_length);

/**
 * @brief Terminates administration session.
 * @param[in] ctx Pointer to the SE context
 * @param[out] mac The session MAC returned by the Secure Element
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_ADMIN_API TO_ret_t TOSE_admin_session_fini(TOSE_ctx_t *ctx, uint8_t mac[TO_ADMIN_MAC_SIZE]);

/**
 * @brief Set administration slot to use from now on.
 * @param[in] ctx Pointer to the SE context
 * @param[in] index Admin slot index
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_*: for any error occurred while handling command
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_ADMIN_API TO_ret_t TOSE_admin_set_slot(TOSE_ctx_t *ctx, const uint8_t index);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_ADMIN_H_ */


/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2017 Trusted Objects. All rights reserved.
 */

/**
 * @file TODRV_HSE_cmd.h
 * @brief TO library commands API, to abstract Secure Element commands
 * protocol.
 *
 * Following APIs are based on libTO internal I/O buffers and mechanisms, to
 * prepare a new command data, send the command, and revieve the response or
 * error.
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#ifndef _TODRV_HSE_CMD_H_
#define _TODRV_HSE_CMD_H_

#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"

#ifndef TODRV_HSE_CMD_API
#ifdef __linux__
#define TODRV_HSE_CMD_API
#elif _WIN32
#define TODRV_HSE_CMD_API __declspec(dllexport)
#else
#define TODRV_HSE_CMD_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Helper to access internal I/O buffer command data section, only valid before
 * TO_send_command() call (even if an error occured while sending command).
 */
TODRV_HSE_CMD_API extern unsigned char *TODRV_HSE_command_data;

/**
 * Helper to access internal I/O buffer response data section, only valid after
 * TO_send_command() call.
 */
TODRV_HSE_CMD_API extern unsigned char *TODRV_HSE_response_data;

/**
 * @brief Reset command data.
 *
 * This function resets command data.
 * It MUST be called if command data has been prepared without subsequent call
 * to TODRV_HSE_send_command() (if command has been aborted for example).
 */
TODRV_HSE_CMD_API void TODRV_HSE_reset_command_data(void);

/**
 * @brief Prepare command data.
 * @param offset Buffer offset where to insert data
 * @param data Data to be copied into the buffer
 * @param len Data length
 *
 * Insert data into the internal I/O buffer at the specified offset.
 *
 * Warning: do not free data pointer parameter or overwrite data before having
 * called TODRV_HSE_send_command(), or before aborted command with
 * TODRV_HSE_reset_command_data().
 *
 * @return TO_OK on success
 * TO_MEMORY_ERROR: data overflows internal I/O buffer, in this case internal
 * command data buffers are invalidated (as if TODRV_HSE_reset_command_data()
 * has been called).
 */
TODRV_HSE_CMD_API TO_lib_ret_t TODRV_HSE_prepare_command_data(uint16_t offset,
		const unsigned char *data, uint16_t len);

/**
 * @brief Prepare command data byte.
 * @param offset Buffer offset where to insert data
 * @param byte Data byte to be copied into the buffer
 *
 * Insert data byte into the internal I/O buffer at the specified offset.
 *
 * @return TO_OK on success
 * TO_MEMORY_ERROR: data byte overflows internal I/O buffer, in this case
 * internal command data buffers are invalidated (as if
 * TODRV_HSE_reset_command_data() has been called).
 */
TODRV_HSE_CMD_API TO_lib_ret_t TODRV_HSE_prepare_command_data_byte(uint16_t offset,
		const char byte);

/**
 * @brief Set data range.
 * @param offset Buffer offset where to begin range
 * @param byte Value to be set for each byte in the range
 * @param len Range length
 *
 * Set internal I/O buffer range bytes to a defined value.
 *
 * @return TO_OK on success
 * TO_MEMORY_ERROR: range overflows internal I/O buffer, in this case internal
 * command data buffers are invalidated (as if TODRV_HSE_reset_command_data()
 * has been called).
 */
TODRV_HSE_CMD_API TO_lib_ret_t TODRV_HSE_set_command_data(uint16_t offset,
		const char byte, uint16_t len);

/**
 * @brief Send command to the Secure Element device.
 * @param cmd Command code (see TODRV_HSE_CMD_* definitions)
 * @param cmd_data_len Command data len (got from internal I/O buffer)
 * @param resp_data_len Response data len (expected)
 * @param resp_status Status of the command
 *
 * Send a command to the Secure Element device and get response data.
 * Internal command data buffers must be considered as invalidated after
 * calling this function.
 *
 * @return TO_OK on success
 * TO_MEMORY_ERROR: data overflows internal I/O buffer
 * TO_DEVICE_WRITE_ERROR: unable to send command
 * TO_DEVICE_READ_ERROR: unable to read response data
 * TO_INVALID_RESPONSE_LENGTH: expected response length differs from headers
 */
TODRV_HSE_CMD_API TO_lib_ret_t TODRV_HSE_send_command(const uint16_t cmd,
		uint16_t cmd_data_len, uint16_t* resp_data_len, TO_se_ret_t* resp_status);


/** defines the type of messages that can be found in the I/O buffer */
enum msg_type {
	MSG_TYPE_COMMAND, /**< command to the HSE */
	MSG_TYPE_RESPONSE, /**< response from the HSE */
};

/**
 * @brief retrieves the maximum size of data that can be put in a message from/to the HSE
 * @param[in] type message type
 * @return the max size of data, 0 if no limits
 **/
TODRV_HSE_CMD_API uint16_t TODRV_HSE_get_msg_data_size_max(enum msg_type type);

/** @addtogroup libhooks
 * @{ */

/**
 * @brief Hook function prototype to be called by TODRV_HSE_send_command() just
 * before sending a command to the Secure Element.
 * @param cmd Command code, see @ref command_codes
 * @param cmd_data_len Command data length
 *
 * Once return, the command response is read from Secure Element.
 *
 * Warning: do NOT call any libTO function from this kind of hook.
 */
typedef void (*TODRV_HSE_pre_command_hook)(uint16_t cmd, uint16_t cmd_data_len);

/**
 * @brief Hook function prototype to be called by TODRV_HSE_send_command() just
 * after writing command to the Secure Element, and before reading its response.
 * @param cmd Command code, see @ref command_codes
 * @param cmd_data_len Command data length
 *
 * This hook can be used by client application for power optimization, for
 * example making the system sleep for a while or until Secure Element status
 * GPIO signals response readyness. For this second use case, it is recommended
 * to arm GPIO wakeup interrupt by setting a hook with
 * TODRV_HSE_pre_command_hook(), to be sure to do not miss the response
 * readyness GPIO toggle.
 *
 * Once return, the command response is read from Secure Element.
 *
 * Warning: do NOT call any libTO function from this kind of hook.
 */
typedef void (*TODRV_HSE_post_write_hook)(uint16_t cmd, uint16_t cmd_data_len);

/**
 * @brief Hook function prototype to be called by TODRV_HSE_send_command() just
 * after reading command response from the Secure Element.
 * @param cmd Command code, see @ref command_codes
 * @param cmd_data_len Command data length
 * @param cmd_rsp_len Command response length
 * @param cmd_status Command status
 *
 * Warning: do NOT call any libTO function from this kind of hook.
 */
typedef void (*TODRV_HSE_post_command_hook)(uint16_t cmd, uint16_t cmd_data_len,
		uint16_t cmd_rsp_len, TO_se_ret_t cmd_status);

/** @} */

/** @addtogroup libhookssetup
 * @{ */

/**
 * @brief Set a pre command hook (see TODRV_HSE_pre_command_hook).
 * @param hook Pre command hook function to set (NULL to disable).
 */
TODRV_HSE_CMD_API void TODRV_HSE_set_lib_hook_pre_command(
		TODRV_HSE_pre_command_hook hook);

/**
 * @brief Set a post write hook (see TODRV_HSE_post_write_hook).
 * @param hook Post write hook function to set (NULL to disable).
 */
TODRV_HSE_CMD_API void TODRV_HSE_set_lib_hook_post_write(
		TODRV_HSE_post_write_hook hook);

/**
 * @brief Set a post cmd hook (see TODRV_HSE_post_command_hook).
 * @param hook Post cmd hook function to set (NULL to disable).
 */
TODRV_HSE_CMD_API void TODRV_HSE_set_lib_hook_post_command(
		TODRV_HSE_post_command_hook hook);

/** @} */

#ifdef __cplusplus
}
#endif

#endif

#endif /* TODRV_HSE_DRIVER_DISABLE */

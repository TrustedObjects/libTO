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
 * @file TODRV_HSE_admin.h
 * @brief
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#ifndef _TODRV_HSE_ADMIN_H_
#define _TODRV_HSE_ADMIN_H_

#ifndef TODRV_HSE_ADMIN_API
#ifdef __linux__
#define TODRV_HSE_ADMIN_API
#elif _WIN32
#define TODRV_HSE_ADMIN_API __declspec(dllexport)
#else
#define TODRV_HSE_ADMIN_API
#endif /* __LINUX__ */
#endif

#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"
#include "TODRV_HSE_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

TODRV_HSE_ADMIN_API TO_ret_t TODRV_HSE_admin_session_init(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t server_challenge[TO_ADMIN_CHALLENGE_SIZE],
		uint8_t se_challenge[TO_ADMIN_CHALLENGE_SIZE],
		uint8_t se_cryptogram[TO_ADMIN_CRYPTOGRAM_SIZE],
		uint8_t diversification_data[TO_ADMIN_DIVERS_DATA_SIZE],
		uint8_t protocol_info[TO_ADMIN_PROTO_INFO_SIZE]);

TODRV_HSE_ADMIN_API TO_ret_t TODRV_HSE_admin_session_auth_server(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t options[TO_ADMIN_OPTIONS_SIZE],
		const uint8_t server_cryptogram[TO_ADMIN_CRYPTOGRAM_SIZE],
		const uint8_t mac[TO_ADMIN_MAC_SIZE]);

TODRV_HSE_ADMIN_API TO_ret_t TODRV_HSE_admin_command(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *command,
		uint16_t length);

TODRV_HSE_ADMIN_API TO_ret_t TODRV_HSE_admin_command_with_response(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *command,
		uint16_t length,
		uint8_t *response,
		uint16_t response_length);

TODRV_HSE_ADMIN_API TO_ret_t TODRV_HSE_admin_command_with_response2(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t *command,
		uint16_t length,
		uint8_t *response,
		uint16_t *response_length);

TODRV_HSE_ADMIN_API TO_ret_t TODRV_HSE_admin_session_fini(
		TODRV_HSE_ctx_t *ctx,
		uint8_t mac[TO_ADMIN_MAC_SIZE]);

TODRV_HSE_ADMIN_API TO_ret_t TODRV_HSE_admin_set_slot(
		TODRV_HSE_ctx_t *ctx,
		const uint8_t index);

#ifdef __cplusplus
}
#endif

#endif /* _TODRV_HSE_ADMIN_H_ */

#endif /* TODRV_HSE_DRIVER_DISABLE */


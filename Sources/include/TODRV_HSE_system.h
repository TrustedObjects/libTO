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
 * @file TODRV_HSE_system.h
 * @brief
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#ifndef _TODRV_HSE_SYSTEM_H_
#define _TODRV_HSE_SYSTEM_H_

#ifndef TODRV_HSE_SYSTEM_API
#ifdef __linux__
#define TODRV_HSE_SYSTEM_API
#elif _WIN32
#define TODRV_HSE_SYSTEM_API __declspec(dllexport)
#else
#define TODRV_HSE_SYSTEM_API
#endif /* __LINUX__ */
#endif

#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_serial_number(
		TODRV_HSE_ctx_t *ctx,
		uint8_t serial_number[TO_SN_SIZE]);

TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_hardware_serial_number(
		TODRV_HSE_ctx_t *ctx,
		uint8_t hardware_serial_number[TO_HW_SN_SIZE]);

TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_product_number(
		TODRV_HSE_ctx_t *ctx,
		uint8_t product_number[TO_PN_SIZE]);

TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_hardware_version(
		TODRV_HSE_ctx_t *ctx,
		uint8_t hardware_version[TO_HW_VERSION_SIZE]);

TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_software_version(
		TODRV_HSE_ctx_t *ctx,
		uint8_t* major,
		uint8_t* minor,
		uint8_t* revision);

TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_access_dummy_data(TODRV_HSE_ctx_t *ctx,
		uint8_t write_data,
		uint32_t* dummy_data);

TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_product_id(TODRV_HSE_ctx_t *ctx,
		uint8_t product_id[TO_PRODUCT_ID_SIZE]);

TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_random(
		TODRV_HSE_ctx_t *ctx,
		const uint16_t random_length,
		uint8_t* random);

TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_set_status_PIO_config(
		TODRV_HSE_ctx_t *ctx,
		int enable,
		int opendrain,
		int ready_level,
		int idle_hz);

TODRV_HSE_SYSTEM_API TO_ret_t TODRV_HSE_get_status_PIO_config(
		TODRV_HSE_ctx_t *ctx,
		int *enable,
		int *opendrain,
		int *ready_level,
		int *idle_hz);

#ifdef __cplusplus
}
#endif

#endif /* _TODRV_HSE_SYSTEM_H_ */

#endif /* TODRV_HSE_DRIVER_DISABLE */


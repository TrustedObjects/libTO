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
 * @file TODRV_HSE_i2c.h
 * @brief
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#ifndef _TODRV_HSE_I2C_H_
#define _TODRV_HSE_I2C_H_

#include "TODRV_HSE_cfg.h"
#include "TO_defs.h"
#include "TO_retcodes.h"

#ifndef TODRV_HSE_I2C_API
#ifdef __linux__
#define TODRV_HSE_I2C_API
#elif _WIN32
#define TODRV_HSE_I2C_API __declspec(dllexport)
#else
#define TODRV_HSE_I2C_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup i2csetup
 * @{ */

/**
 * @brief Configure hardware Secure Element transport.
 * @param i2c_addr I2C address to use
 * @param misc_settings Misc. settings byte. It has the following bit form
 * (from MSB to LSB): RES, RES, RES, RES, RES, RES, RES, last byte NACKed.
 * The *last byte NACKed* bit must be set to 1 if remote device NACKs last
 * written byte.
 *
 * See TO_data_config() for more details.
 *
 * @return TO_OK if configuration was successful.
 */
TODRV_HSE_I2C_API TO_ret_t TODRV_HSE_trp_config(unsigned char i2c_addr, unsigned char misc_settings);

/** @} */

/** @addtogroup i2crw
 * @{ */

/**
 * @brief Write data to Secure Element
 * @param data Buffer containing data to send
 * @param length Amount of data to send in bytes
 *
 * This function uses the underlying TO_data_write() wrapper function. Refer
 * to its documentation for more details.
 *
 * @return
 * - TO_OK if data has been written sucessfully
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_ERROR if an internal error has occured
 */
TODRV_HSE_I2C_API TO_ret_t TODRV_HSE_trp_write(const void *data, unsigned int length);

/**
 * @brief Read data from Secure Element
 * @param data Buffer to store received data
 * @param length Amount of data to read in bytes
 *
 * This function uses the underlying TO_data_read() wrapper function. Refer
 * to its documentation for more details.
 *
 * @return
 * - TO_OK if data has been read sucessfully
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR if an internal error has occured
 */
TODRV_HSE_I2C_API TO_ret_t TODRV_HSE_trp_read(void *data, unsigned int length);

/**
 * @brief Last command duration from Secure Element
 * @param duration Pointer to store last command duration in microseconds
 *
 * This function uses the underlying TO_data_last_command_duration() wrapper
 * function. Refer to its documentation for more details.
 *
 * This function should only be called after a successful command or a
 * successful TO_read() call.
 * If it is called after a failed command or a failed TO_read(), or after a
 * TO_write() call, the result is unspecified and may be irrelevant.
 *
 * @return
 * - TO_OK if data has been read sucessfully
 * - TO_ERROR if an internal error has occured
 */
TODRV_HSE_I2C_API TO_ret_t TODRV_HSE_trp_last_command_duration(unsigned int *duration);

/**
 * @brief Last command stack depth's usage from Secure Element
 * @param duration Pointer to store last command stack depth's usage in bytes
 * *
 * @return
 * - TO_OK if data has been read sucessfully
 * - TO_ERROR if an internal error has occured
 */
TODRV_HSE_I2C_API TO_ret_t TODRV_HSE_trp_last_command_stack_usage(unsigned int *stack_depth);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TODRV_HSE_I2C_H_ */

#endif /* TODRV_HSE_DRIVER_DISABLE */


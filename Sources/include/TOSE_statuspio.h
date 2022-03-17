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
 * @file TOSE_statuspio.h
 * @brief
 */

#ifndef _TOSE_STATUSPIO_H_
#define _TOSE_STATUSPIO_H_

#ifndef TOSE_STATUSPIO_API
#ifdef __linux__
#define TOSE_STATUSPIO_API
#elif _WIN32
#define TOSE_STATUSPIO_API __declspec(dllexport)
#else
#define TOSE_STATUSPIO_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"

/** @addtogroup statuspio
 * @{ */

/**
 * @brief Configure Secure Element status PIO notification behavior.
 * @param[in] ctx Pointer to the SE context
 * @param[in] enable Set to 1 to enable status PIO notifications (default: 1)
 * @param[in] opendrain Set to 1 for open drain, 0 for push pull (default: 1)
 * @param[in] ready_level Set to 1 to signal readyness with high PIO level, 0 to
 * signal it with low PIO level (default: 1).
 * @param[in] idle_hz Set to 1 to have idle state signalled by PIO high impedance
 * signal it with a low level (default: 1)
 *
 * The configuration is stored permanently by the Secure Element, and then
 * persists across reboots.
 *
 * Note: this function do not have BUSY / READY states, the PIO remains in the
 * IDLE state when called. But if the pushed settings change the PIO levels or
 * signalling method, the PIO state can change when this function is called.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_ERROR: generic error
 */
TOSE_STATUSPIO_API TO_ret_t TOSE_set_status_PIO_config(TOSE_ctx_t *ctx, int enable,
		int opendrain, int ready_level, int idle_hz);

/**
 * @brief Return Secure Element status PIO notification configuration.
 * @param[in] ctx Pointer to the SE context
 * @param[out] enable Set to 1 if status PIO notification enabled
 * @param[out] opendrain Method to signal level, see TO_set_status_PIO_config()
 * @param[out] ready_level PIO level to signal ready state, see
 * TO_set_status_PIO_config()
 * @param[out] idle_hz Idle state signalled by PIO high impedance, see
 * TO_set_status_PIO_config()
 *
 * Note: this function do not have BUSY / READY states, the PIO remains in the
 * IDLE state when called.
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_ERROR: generic error
 */
TOSE_STATUSPIO_API TO_ret_t TOSE_get_status_PIO_config(TOSE_ctx_t *ctx, int *enable,
		int *opendrain, int *ready_level, int *idle_hz);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_STATUSPIO_H_ */


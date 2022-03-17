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

#ifndef _TODRV_SSE_H_
#define _TODRV_SSE_H_

#ifndef TODRV_SSE_DRIVER_DISABLE

#include "TO_retcodes.h"
#include "TO_defs.h"
#include "TOP_SecureStorage.h"
#include "TOP_info.h"

#ifndef TODRV_SSE_API
#ifdef __linux__
#define TODRV_SSE_API
#elif _WIN32
#define TODRV_SSE_API __declspec(dllexport)
#else
#define TODRV_SSE_API
#endif /* __LINUX__ */
#endif

// TODO : To be checked
//#include "TOP.h"

#include "TODRV_SSE_cfg.h"

#include "TO_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Secure storage NVM read function to be implemented
 */
TOP_secure_storage_read_func_t TODRV_SSE_secure_storage_read;

/**
 * @brief Secure storage NVM write function to be implemented
 */
TOP_secure_storage_write_func_t TODRV_SSE_secure_storage_write;

/**
 * @brief Secure storage NVM erase function to be implemented
 */
TOP_secure_storage_erase_func_t TODRV_SSE_secure_storage_erase;

/** @addtogroup context_api
 * @{ */

/**
 * @brief Get SSE context
 *
 * @return SSE context pointer
 */
TODRV_SSE_API TOSE_ctx_t* TODRV_SSE_get_ctx(void);

/** @} */

/** @addtogroup drv_test_api
 * @{ */

/**
 * @brief Self-test NVM read/write/erase functions with driver configuration.
 *
 * In order to verify your implementation, we recommend to call this function
 * (only in development, not in production, as it wears down the Flash memory).
 *
 * @return TO_OK in case of success, error otherwise
 */
TODRV_SSE_API TO_lib_ret_t TODRV_SSE_nvm_self_test(TO_log_ctx_t* log_ctx);

/**
 * @brief Self-test TO-Protect.
 *
 * In order to verify that TO-Protect is correctly flashed and not corrupted,
 * we recommend to call this function while in development mode.
 *
 * @return TO_OK in case of success, error otherwise
 */
TODRV_SSE_API TO_lib_ret_t TODRV_SSE_top_self_test(TO_log_ctx_t* log_ctx);

/** @} */

#ifdef __cplusplus
}
#endif

#endif // TODRV_SSE_DRIVER_DISABLE

#endif // _TODRV_SSE_H_

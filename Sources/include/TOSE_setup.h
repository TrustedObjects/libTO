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
 * @file TOSE_setup.h
 * @brief
 */

#ifndef _TOSE_SETUP_H_
#define _TOSE_SETUP_H_

#ifndef TOSE_SETUP_API
#ifdef __linux__
#define TOSE_SETUP_API
#elif _WIN32
#define TOSE_SETUP_API __declspec(dllexport)
#else
#define TOSE_SETUP_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"
#include "TO_retcodes.h"

/** @addtogroup setup
 * @{ */

/**
 * @brief Initialize TO-Protect.
 * @param[in] ctx Pointer to the SE context
 * @cond libTO
 * If endianness is not explicitely defined through project settings macros,
 * this function performs an automatic endianness detection.
 * @return
 * - TO_OK if initialization was successful.
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_SETUP_API TO_ret_t TOSE_init(TOSE_ctx_t *ctx);

/**
 * @brief Uninitialize TO-Protect.
 * @param[in] ctx Pointer to the SE context
 * @cond libTO
 * @return
 * - TO_OK if the uninitialization succeedeed.
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_SETUP_API TO_ret_t TOSE_fini(TOSE_ctx_t *ctx);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_SETUP_H_ */


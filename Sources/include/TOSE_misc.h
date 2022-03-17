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
 * @file TOSE_misc.h
 * @brief
 */

#ifndef _TOSE_MISC_H_
#define _TOSE_MISC_H_

#ifndef TOSE_MISC_API
#ifdef __linux__
#define TOSE_MISC_API
#elif _WIN32
#define TOSE_MISC_API __declspec(dllexport)
#else
#define TOSE_MISC_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"

/** @addtogroup misc
 * @{ */

/**
 * @brief Flush caches.
 * @param[in] ctx Pointer to the SE context
 *
 * This API needs to be called to flush all caches to NVM. It can be needed for
 * example before a MCU sleep.
 *
 * @return TO_OK on success.
 */
TOSE_MISC_API TO_ret_t TOSE_flush(TOSE_ctx_t *ctx);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_MISC_H_ */


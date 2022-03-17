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

#ifndef _TODRV_HSE_H_
#define _TODRV_HSE_H_

#include "TO_defs.h"

#ifndef TODRV_HSE_API
#ifdef __linux__
#define TODRV_HSE_API
#elif _WIN32
#define TODRV_HSE_API __declspec(dllexport)
#else
#define TODRV_HSE_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup context_defs
 * @{ */

typedef struct TODRV_HSE_ctx_s {
	uint8_t rfu;
} TODRV_HSE_ctx_t;

/** @} */

/** @addtogroup context_api
 * @{ */

/**
 * @brief Get HSE context
 *
 * @return HSE context pointer
 */
TODRV_HSE_API TOSE_ctx_t* TODRV_HSE_get_ctx(void);

/** @} */

#ifdef __cplusplus
}
#endif

#endif // _TODRV_HSE_H_


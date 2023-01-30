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
 * @file TODRV_HSE_core.h
 * @brief
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#ifndef _TODRV_HSE_CORE_H_
#define _TODRV_HSE_CORE_H_

#ifndef TODRV_HSE_CORE_API
#ifdef __linux__
#define TODRV_HSE_CORE_API
#elif _WIN32
#define TODRV_HSE_CORE_API __declspec(dllexport)
#else
#define TODRV_HSE_CORE_API
#endif /* __LINUX__ */
#endif

#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"

#ifdef __cplusplus
extern "C" {
#endif

TODRV_HSE_CORE_API TO_ret_t TODRV_HSE_init(
		TODRV_HSE_ctx_t *ctx,
		TO_log_level_t *log_ctx);

TODRV_HSE_CORE_API TO_ret_t TODRV_HSE_fini(
		TODRV_HSE_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _TODRV_HSE_CORE_H_ */

#endif /* TODRV_HSE_DRIVER_DISABLE */


/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2022 Trusted Objects. All rights reserved.
 */

/**
 * @file TO_log.h
 * @brief TO log definitions and functions.
 */

#ifndef _TO_LOG_H_
#define _TO_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_cfg.h"

#include <stdio.h>

/** @addtogroup log_level
 * @{ */

/**
 * Log levels
 */

#define TO_LOG_LEVEL_NONE	-1
#define TO_LOG_LEVEL_ERR	0
#define TO_LOG_LEVEL_WRN	1
#define TO_LOG_LEVEL_INF	2
#define TO_LOG_LEVEL_DBG	3
#define TO_LOG_LEVEL_MASK  	0x0f
#define TO_LOG_STRING		0x00
#define TO_LOG_BUFFER		0x10
#define TO_LOG_HEX_DISP		0x20

/**
 * @brief Different log levels that are available to the application.
 *
 */
typedef enum TO_log_level_e {
	TO_LOG_NONE          = TO_LOG_LEVEL_NONE,			/**< Disabled level */
	TO_LOG_STRING_ERR    = TO_LOG_LEVEL_ERR  | TO_LOG_STRING, 	/**< Error level */
	TO_LOG_STRING_WRN    = TO_LOG_LEVEL_WRN  | TO_LOG_STRING, 	/**< Warning level */
	TO_LOG_STRING_INF    = TO_LOG_LEVEL_INF  | TO_LOG_STRING, 	/**< Info level */
	TO_LOG_STRING_DBG    = TO_LOG_LEVEL_DBG  | TO_LOG_STRING, 	/**< Debug level */
	TO_LOG_BUFFER_ERR    = TO_LOG_LEVEL_ERR  | TO_LOG_BUFFER,	/**< Error level */
	TO_LOG_BUFFER_WRN    = TO_LOG_LEVEL_WRN  | TO_LOG_BUFFER,	/**< Warning level */
	TO_LOG_BUFFER_INF    = TO_LOG_LEVEL_INF  | TO_LOG_BUFFER,	/**< Info level */
	TO_LOG_BUFFER_DBG    = TO_LOG_LEVEL_DBG  | TO_LOG_BUFFER,	/**< Debug level */
	TO_LOG_HEX_DISP_ERR  = TO_LOG_LEVEL_ERR  | TO_LOG_HEX_DISP,	/**< Error level */
	TO_LOG_HEX_DISP_WRN  = TO_LOG_LEVEL_WRN  | TO_LOG_HEX_DISP,	/**< Warning level */
	TO_LOG_HEX_DISP_INF  = TO_LOG_LEVEL_INF  | TO_LOG_HEX_DISP,	/**< Info level */
	TO_LOG_HEX_DISP_DBG  = TO_LOG_LEVEL_DBG  | TO_LOG_HEX_DISP,	/**< Debug level */
} __attribute__ ((packed)) TO_log_level_t;

// Pre-definition of the context, we have to do this for defining both the context and the LOG function
typedef struct TO_log_ctx_s TO_log_ctx_t;

/**
 * @brief Pointer to a log function.
 * @details This function will be responsible for displaying/processing
 * logs in a way suitable for your application.
 */
typedef void (TO_log_func_t)(TO_log_ctx_t *log_ctx, const TO_log_level_t level, void *ptr, ...);

// With GCC, we have to ignore a message complaining about the fact the TO_log_ctx_t type is already defined.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
/**
 * @brief The Log context, propagated to all layers.
 *
 */
typedef struct TO_log_ctx_s {
	TO_log_func_t *log_function;	/**< Pointer to a log function */
	TO_log_level_t log_level;	/**< Dynamic level management */
} TO_log_ctx_t;
#pragma GCC diagnostic pop

/**
 * @brief Default print log function, potentialy to be customized per-target.
 * @details Depending on your target and the way to send string messages out, you may have to rewrite it.
 * In this case, just declare a function having the same names/parameters, printing-out the messages.
 * @param level Importance level of the message
 * @param log String to be displayed
 */
extern void print_log_function(const TO_log_level_t level, const char *log);

/**
 * @brief Default LOG "display" function
 *
 * @param log_ctx The LOG context
 * @param level The desired log display level
 * @param ptr Pointer to the string (mandatory parameter)
 */
extern void TO_log(TO_log_ctx_t *log_ctx, const TO_log_level_t level, void *ptr, ...);

// Enables setting the log level & function

/**
 * @brief Sets the Log function and log level.
 * @details This function permits to change the log level and the log function.
 * @param log_ctx Current log context
 * @param level Desired log level
 * @param log_function Log function (eg. TO_log)
 */
extern void TO_set_log_level(TO_log_ctx_t *log_ctx,
		const TO_log_level_t level,
		TO_log_func_t* log_function);

/**
 * @brief Get the LOG context.
 * @details This function is weak, and can be replaced by your own implementation.
 *
 * @return TO_log_ctx_t*
 */
extern TO_log_ctx_t* TO_log_get_ctx(void);

/** @} */

#if TO_LOG_LEVEL_MAX >= TO_LOG_LEVEL_ERR
#define TO_LOG_ERR(...) TO_log_get_ctx()->log_function(TO_log_get_ctx(), TO_LOG_STRING_ERR, (void *)__VA_ARGS__)
#define TO_LOG_ERR_HEX(...) { TO_log_get_ctx()->log_function(TO_log_get_ctx(), TO_LOG_HEX_DISP_ERR, (void *)__VA_ARGS__); }
#define TO_LOG_ERR_BUF(...) { TO_log_get_ctx()->log_function(log_func, TO_LOG_BUFFER_ERR, (void *)__VA_ARGS__); }
#else /* TO_LOG_LEVEL_MAX >= TO_LOG_LEVEL_ERR */
#define TO_LOG_ERR(...)
#define TO_LOG_ERR_HEX(...)
#define TO_LOG_ERR_BUF(...)
#endif /* TO_LOG_LEVEL_MAX >= TO_LOG_LEVEL_ERR */

#if TO_LOG_LEVEL_MAX >= TO_LOG_LEVEL_WRN
#define TO_LOG_WRN(...) TO_log_get_ctx()->log_function(TO_log_get_ctx(), TO_LOG_STRING_WRN, (void *)__VA_ARGS__)
#define TO_LOG_WRN_HEX(...) { TO_log_get_ctx()->log_function(TO_log_get_ctx(), TO_LOG_HEX_DISP_WRN, (void *)__VA_ARGS__); }
#define TO_LOG_WRN_BUF(...) { TO_log_get_ctx()->log_function(TO_log_get_ctx(), TO_LOG_BUFFER_WRN, (void *)__VA_ARGS__); }
#else
#define TO_LOG_WRN(...)
#define TO_LOG_WRN_HEX(...)
#define TO_LOG_WRN_BUF(...)
#endif

#if TO_LOG_LEVEL_MAX >= TO_LOG_LEVEL_INF
#define TO_LOG_INF(...) TO_log_get_ctx()->log_function(TO_log_get_ctx(), TO_LOG_STRING_INF, (void *)__VA_ARGS__)
#define TO_LOG_INF_HEX(...) { TO_log_get_ctx()->log_function(TO_log_get_ctx(), TO_LOG_HEX_DISP_INF, (void *)__VA_ARGS__); }
#define TO_LOG_INF_BUF(...) { TO_log_get_ctx()->log_function(TO_log_get_ctx(), TO_LOG_BUFFER_INF, (void *)__VA_ARGS__); }
#else
#define TO_LOG_INF(...)
#define TO_LOG_INF_HEX(...)
#define TO_LOG_INF_BUF(...)
#endif

#if TO_LOG_LEVEL_MAX >= TO_LOG_LEVEL_DBG
#define TO_LOG_DBG(...) TO_log_get_ctx()->log_function(TO_log_get_ctx(), TO_LOG_STRING_DBG, (void *)__VA_ARGS__)
#define TO_LOG_DBG_HEX(...) { TO_log_get_ctx()->log_function(TO_log_get_ctx(), TO_LOG_HEX_DISP_DBG, (void *)__VA_ARGS__); }
#define TO_LOG_DBG_BUF(...) { TO_log_get_ctx()->log_function(TO_log_get_ctx(), TO_LOG_BUFFER_DBG, (void *)__VA_ARGS__); }
#else
#define TO_LOG_DBG(...)
#define TO_LOG_DBG_HEX(...)
#define TO_LOG_DBG_BUF(...)
#endif

#ifdef __cplusplus
}
#endif

#endif


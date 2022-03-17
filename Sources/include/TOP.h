/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2022 Trusted Objects. All rights reserved.
 */

#ifndef _TOP_H_
#define _TOP_H_

#include <stdint.h>
#include <stdbool.h>
#include "TO_cfg.h"
#include "TO_defs.h"
#include "TO_endian.h"
#include "TO_retcodes.h"

#include "TOP_cfg.h"
#include "TOP_info.h"
#include "TOP_SecureStorage.h"
#include "TOP_storage.h"

/** @addtogroup log_defs
 * @{ */

/**
 * @brief Function pointer to a log function.
 * @details This function will be called when a log message must be displayed,
 * whatever its importance (from Informatory to an Error).
 * @param level The level of importance of the message
 * @param msg The string message in itself.
 */
typedef void (*TOP_log_f)(const TO_log_level_t level, const char *msg);

/**
 * @} */

/** @addtogroup context_defs
 * @{ */

/**
 * @brief Context specific definitions in the case of TO-Protect
 * @details The log is in front, and this is done on purpose. It will
 * be possible to move it once it is possible to send it in parameter of
 * TOP_init().
 */
typedef struct TOP_ext_ctx_s {
	TO_log_ctx_t		*log_ctx;							///< Logging context
	void			*data;								///< TO-Protect RAM workspace
	uint8_t			internal[TOP_INTERNAL_CTX_SIZE] __attribute__((aligned));	///< TO-Protect internal context
	TOP_secure_storage_t	*secure_storage;						///< Secure storage contexts
} TOP_ext_ctx_t;

/**
 * @} */

#endif // _TOP_H_


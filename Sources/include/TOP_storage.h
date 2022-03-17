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

#ifndef _TOP_STORAGE_H_
#define _TOP_STORAGE_H_

#include "TOP_SecureStorage.h"

/** @addtogroup secure_storage_defs
 * @{ */

/**
 * External secure storage configuration
 *
 * This structure is used by initialization function to configure secure storage
 * behavior.
 */
typedef struct TOP_secure_storage_s {
	TOP_secure_storage_ctx_t nvm_clear; /**< NVM clear context */
	TOP_secure_storage_ctx_t nvm_secret; /**< NVM secret context */
} TOP_secure_storage_t;

/**
 * @} */

#endif // _TOP_STORAGE_H_

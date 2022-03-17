/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2016-2017 Trusted Objects. All rights reserved.
 */

/**
 * @file TO.h
 * @brief Functions provided by libTO to deal with it and send commands to
 * Secure Element.
 */

#ifndef _TO_H_
#define _TO_H_

#ifdef TO_USER_CONFIG
#include "TO_user_config.h"
#endif

#include "TOSE_cfg.h"

#if defined(TOSE_DRIVER_SSE) && !defined(TOSE_DRIVER_HSE)
#define TO_DISABLE_CAPI
#endif

#include "TO_cfg.h"
#include "TO_endian.h"
#include "TO_stdint.h"
#include "TO_defs.h"
#include "TO_retcodes.h"
#include "TO_utils.h"
#include "TO_log.h"

#if !defined(TO_DEPRECATED) && defined(__GNUC__)
#define TO_DEPRECATED __attribute__((deprecated))
#else
#define TO_DEPRECATED
#endif

#include "TOSE_admin.h"
#include "TOSE_auth.h"
#include "TOSE_encryption.h"
#include "TOSE_hashes.h"
#include "TOSE_keys.h"
#include "TOSE_lora.h"
#include "TOSE_mac.h"
#include "TOSE_measured_boot.h"
#include "TOSE_misc.h"
#include "TOSE_nvm.h"
#include "TOSE_secmsg.h"
#include "TOSE_setup.h"
#include "TOSE_statuspio.h"
#include "TOSE_system.h"
#include "TOSE_tls.h"
#include "TOSE_loader.h"

#if defined(TOSE_DRIVER_HSE)
#include "TODRV_HSE.h"
#include "TODRV_HSE_i2c.h"
#endif
#if defined(TOSE_DRIVER_SSE)
#include "TODRV_SSE.h"
#endif
#if defined(TOSE_DRIVER_HSE)
#define DEFAULT_CTX (TODRV_HSE_get_ctx())
#elif defined(TOSE_DRIVER_SSE)
#define DEFAULT_CTX (TODRV_SSE_get_ctx())
#else
#error "No default driver defined"
#endif


#include "TO_legacy.h"

#endif


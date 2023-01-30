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
 * @file seclink.c
 * @brief Secure link common stuff.
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#include "TO_cfg.h"
#include "TO_stdint.h"
#include "TO_retcodes.h"

#include "TODRV_HSE_cfg.h"

#include "TO_seclink.h"

#include <stddef.h>

TODRV_HSE_seclink_store_keys_cb _seclink_store_keys_cb_p = NULL;
TODRV_HSE_seclink_load_keys_cb _seclink_load_keys_cb_p = NULL;

void TODRV_HSE_seclink_set_store_keys_cb(TODRV_HSE_seclink_store_keys_cb cb)
{
	_seclink_store_keys_cb_p = cb;
}

void TODRV_HSE_seclink_set_load_keys_cb(TODRV_HSE_seclink_load_keys_cb cb)
{
	_seclink_load_keys_cb_p = cb;
}

TO_lib_ret_t TODRV_HSE_seclink_request_renewed_keys(void)
{
	return TODRV_HSE_seclink_renew_keys();
}

#if defined(TODRV_HSE_ENABLE_SECLINK_AESHMAC)
uint8_t *conf_seclink_aeshmac;
#elif defined(TODRV_HSE_ENABLE_SECLINK_ARC4)
uint8_t *conf_seclink_arc4;
#endif

#endif /* TODRV_HSE_DRIVER_DISABLE */


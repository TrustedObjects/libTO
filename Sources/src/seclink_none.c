/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2017 Trusted Objects. All rights reserved.
 */

/**
 * @file seclink_none.c
 * @brief Empty secure link implementation.
 *
 * This implementation doesn't do anything, if used it means no security is
 * added to Secure Element commands and responses.
 */

#include "TO_cfg.h"
#include "TO_defs.h"
#include "TO_retcodes.h"

#if !defined(TODRV_HSE_ENABLE_SECLINK_ARC4) && !defined(TODRV_HSE_ENABLE_SECLINK_AESHMAC)

#include "TODRV_HSE.h"
#include "TODRV_HSE_cfg.h"

uint16_t TODRV_HSE_seclink_compute_cmd_size(uint16_t encaps_len)
{
	return encaps_len;
}

uint16_t TODRV_HSE_seclink_compute_rsp_size(uint16_t encaps_len)
{
	return encaps_len;
}

TO_lib_ret_t TODRV_HSE_seclink_init(void)
{
	return TO_OK;
}

TO_lib_ret_t TODRV_HSE_seclink_renew_keys(void)
{
	return TO_OK;
}

TO_lib_ret_t TODRV_HSE_seclink_secure(uint8_t *io_buffer, uint16_t len)
{
	(void)io_buffer;
	(void)len;
	return TO_OK;
}

TO_lib_ret_t TODRV_HSE_seclink_unsecure(uint8_t *io_buffer)
{
	(void)io_buffer;
	return TO_OK;
}

#endif // !TODRV_HSE_ENABLE_SECLINK_ARC4 && !TODRV_HSE_ENABLE_SECLINK_AESHMAC


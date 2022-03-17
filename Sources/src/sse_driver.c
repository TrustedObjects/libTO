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

#ifndef TODRV_SSE_DRIVER_DISABLE

#include "TO_cfg.h"
#include "TO_defs.h"
#include "TO_driver.h"

#include "TODRV_SSE_cfg.h"
#include "TODRV_SSE.h"

#include "TOP.h"
#include "TOP_vt.h"
#include "TOP_storage.h"
#include "TOP_info.h"

#include "sse_driver.h"

static uint8_t secure_storage_rambuff[TOP_SECURE_STORAGE_RAM_FOOTPRINT];

TOP_secure_storage_t TOP_secure_storage = {
	.nvm_secret = {
		.type = SECURE_STORAGE_SECRET_DATA,
		.address = (void*)0,
		.size = TOP_NVM_SECRET_DATA_SIZE,
		.rambuff = secure_storage_rambuff,
		.read_func = &TODRV_SSE_secure_storage_read,
		.write_func = &TODRV_SSE_secure_storage_write,
		.erase_func = &TODRV_SSE_secure_storage_erase
	},
	.nvm_clear = {
		.type = SECURE_STORAGE_CLEAR_DATA,
		.address = (void*)TOP_SECURE_STORAGE_NVM_CLEAR_OFFSET,
		.size = TOP_NVM_CLEAR_DATA_SIZE,
		.rambuff = secure_storage_rambuff,
		.read_func = &TODRV_SSE_secure_storage_read,
		.write_func = &TODRV_SSE_secure_storage_write,
		.erase_func = &TODRV_SSE_secure_storage_erase
	}
};

static uint8_t ram_workspace[TOP_RAM_DATA_SIZE];

static TOP_ext_ctx_t sse_ctx_priv = {
	.data = (void*)ram_workspace,
	.secure_storage = (TOP_secure_storage_t*)&TOP_secure_storage,
};

static TO_log_ctx_t log_ctx = {
	.log_function = &TO_log,		// By default a NULL function
	.log_level = TO_LOG_LEVEL_MAX,		// By default, no LOGs (as we ignore the log function)
};

static TOSE_drv_ctx_t drv_ctx = {
	.api = (TODRV_api_t *)TODRV_SSE_TOP_API_ADDRESS,
	.func_offset = TODRV_SSE_TOP_OFFSET_ADDRESS,
	.priv_ctx  = (void *)&sse_ctx_priv,
	.log_ctx = &log_ctx,
};

static TOSE_ctx_t drv_sse_ctx = {
	.drv = &drv_ctx,
	.initialized = 0,
};

TODRV_SSE_API TOSE_ctx_t* TODRV_SSE_get_ctx(void)
{
	return &drv_sse_ctx;
}

#endif // TODRV_SSE_DRIVER_DISABLE

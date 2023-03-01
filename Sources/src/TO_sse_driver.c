/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2019-2022 Trusted Objects. All rights reserved.
 */

#include "TO_cfg.h"
#ifndef TODRV_SSE_DRIVER_DISABLE

#include "TO_defs.h"
#include "TO_driver.h"

#include "TODRV_SSE_cfg.h"
#include "TODRV_SSE.h"

#include "TOP.h"
#include "TOP_vt.h"
#include "TOP_info.h"
#include "TOP_technical_info.h"
#include "TO_log.h"
#include "TOP_storage.h"

#include "TO_sse_driver.h"


// Create the area with a size aligned on 32-bits
static uint32_t secure_storage_rambuff[(TOP_SECURE_STORAGE_RAM_FOOTPRINT + sizeof(uint32_t) -1)/sizeof(uint32_t)];

TO_lib_ret_t TOP_data_load(zone_id_t zone_id,
		const void *dst)
{
	switch (zone_id) {
		case TEARING_ZONE_0:
			return TODRV_SSE_secure_storage_load((uint8_t *)dst,
					0,
					TOP_SECURE_STORAGE_NVM_FOOTPRINT);
			break;

		case TEARING_ZONE_1:
			return TODRV_SSE_secure_storage_load((uint8_t *)dst,
					TOP_SECURE_STORAGE_NVM_FOOTPRINT + SECTOR_LOST_BYTES,
					TOP_SECURE_STORAGE_NVM_FOOTPRINT);
			break;

		default:
			return TO_ERROR;
	}
}

TO_lib_ret_t TOP_data_store(zone_id_t zone_id,
		const void *src)
{
	switch (zone_id) {
		case TEARING_ZONE_0:
			return TODRV_SSE_secure_storage_store(0,
					src,
					TOP_SECURE_STORAGE_NVM_FOOTPRINT);
			break;

		case TEARING_ZONE_1:
			return TODRV_SSE_secure_storage_store(TOP_SECURE_STORAGE_NVM_FOOTPRINT +
					SECTOR_LOST_BYTES,
					src,
					TOP_SECURE_STORAGE_NVM_FOOTPRINT);
			break;

		default:
			return TO_ERROR;
	}
}

TOP_secure_data_ctx_t TOP_data = {
	.load_func = TOP_data_load,
	.store_func = TOP_data_store,
	.current_version = 0xffffffff,
	.storage = {
		.raw_ram_buffer = (uint8_t *)secure_storage_rambuff,
	        .raw_ram_buffer_size = sizeof(secure_storage_rambuff),
		.log_ctx = &log_ctx
	}
};

static uint8_t ram_workspace[TOP_RAM_DATA_SIZE];

static TOP_ext_ctx_t sse_ctx_priv = {
	.data = (void*)ram_workspace,
	.secure_storage = &TOP_data,
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

TOSE_ctx_t* TODRV_SSE_get_ctx(void)
{
	return &drv_sse_ctx;
}

TO_lib_ret_t TODRV_SSE_set_top_address(void *sse_top_address)
{
	TOSE_ctx_t *ctx = TODRV_SSE_get_ctx();

	ctx->drv->api = (TODRV_api_t *)sse_top_address;
	ctx->drv->func_offset = (uintptr_t)sse_top_address;

	return TO_OK;
}

#endif // TODRV_SSE_DRIVER_DISABLE

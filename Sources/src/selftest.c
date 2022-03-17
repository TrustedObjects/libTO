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

#include "TO_retcodes.h"
#include "TO_defs.h"
#include "TO_utils.h"

#include "TODRV_SSE.h"
#include "TODRV_SSE_cfg.h"

#include "sse_driver.h"

#ifdef TODRV_SSE_ENABLE_SELF_TESTS

TO_lib_ret_t TODRV_SSE_nvm_self_test(TO_log_ctx_t* log_ctx)
{
	(void)log_ctx;

	// TODO
	return TO_OK;
}

TO_lib_ret_t TODRV_SSE_top_self_test(TO_log_ctx_t* log_ctx)
{
	(void)log_ctx;
#if defined(TOP_VT_SIZE) && defined(TOP_TEXT_SIZE) && defined(TOP_VT_CRC) && defined(TOP_TEXT_CRC)
	uint16_t crc;

	TO_LOG_INF("%s: TO-Protect self-test started\n", __func__);
	TO_LOG_INF("%s: TO-Protect configuration:\n", __func__);
	TO_LOG_INF("%s:  - Vector table address: %08x\n", __func__, TOP_VT_ADDRESS);
	TO_LOG_INF("%s:  - Vector table size: %u\n", __func__, TOP_VT_SIZE);
	TO_LOG_INF("%s:  - Text address: %08x\n", __func__, TOP_TEXT_ADDRESS);
	TO_LOG_INF("%s:  - Text size: %u\n", __func__, TOP_TEXT_SIZE);

	/* Compute CRC of TO-Protect */
	crc = TO_crc16_ccitt_29b1(CRC16_SEED, (uint8_t*)TOP_VT_ADDRESS, TOP_VT_SIZE, 0);
	if (crc != TOP_VT_CRC) {
		TO_LOG_ERR("%s: Bad TO-Protect vector table CRC, computed: %04x, expected %04x\n",
				__func__,
				crc,
				TOP_VT_CRC);
		TO_LOG_ERR("%s: This error can occurs when TO-Protect is badly flashed, or flashed at wrong address\n",
				__func__);
		return TO_ERROR;
	}

	crc = TO_crc16_ccitt_29b1(CRC16_SEED, (uint8_t*)TOP_TEXT_ADDRESS, TOP_TEXT_SIZE, 0);
	if (crc != TOP_TEXT_CRC) {
		TO_LOG_ERR("%s: Bad TO-Protect text CRC, computed: %04x, expected %04x\n",
				__func__,
				crc,
				TOP_TEXT_CRC);
		TO_LOG_ERR("from %08x over %08x bytes\n",
				(uint32_t)TOP_TEXT_ADDRESS,TOP_TEXT_SIZE);
		TO_LOG_ERR("%s: This error can occurs when TO-Protect is badly flashed, or flashed at wrong address\n",
				__func__);
		return TO_ERROR;
	}
	TO_LOG_INF("%s: TO-Protect self-test passed\n",
			__func__);
#else
	TO_LOG_INF("%s: TO-Protect self-test unavailable\n",
			__func__);
#endif	
	return TO_OK;
}

#endif /* TODRV_SSE_ENABLE_SELF_TESTS */

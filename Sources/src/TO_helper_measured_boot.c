/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2021 Trusted Objects. All rights reserved.
 */

/**
 * @file helper_measured_boot.c
 * @brief Helper functions for Measured Boot
 */

#include "TOSE_helper_measured_boot.h"

TO_ret_t TOSE_helper_measured_boot(TOSE_ctx_t *hash_ctx, TOSE_ctx_t *hw_ctx,
		const uint8_t* fw_addr, uint32_t fw_length)
{
	TO_ret_t ret;
	SHA256_CTX ctx;
	uint8_t computed_sha256[SHA256_BLOCK_SIZE];

	(void)hash_ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, fw_addr, fw_length);
	sha256_final(&ctx, computed_sha256);
	ret = TOSE_measured_boot(hw_ctx, computed_sha256, SHA256_BLOCK_SIZE);
	if (ret != TORSP_SUCCESS) {
		TO_LOG_ERR("%s: error during TOSE_measured_boot() execution\n", __func__);
		return TO_ERROR | ret;
	}

	return TO_OK;
 }


TO_ret_t TOSE_helper_validate_update_fw_hash(TOSE_ctx_t *hash_ctx,
 		TOSE_ctx_t *hw_ctx, const uint8_t* fw_addr, uint32_t fw_length)
{
	TO_ret_t ret;
	SHA256_CTX ctx;
	uint8_t computed_sha256[SHA256_BLOCK_SIZE];

	(void)hash_ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, fw_addr, fw_length);
	sha256_final(&ctx, computed_sha256);
	ret = TOSE_validate_new_fw_hash(hw_ctx, computed_sha256,
			SHA256_BLOCK_SIZE);

	if (ret != TORSP_SUCCESS) {
		TO_LOG_ERR("%s: error during TOSE_measured_boot() execution\n", __func__);
		return TO_ERROR | ret;
	}

	return TO_OK;
}

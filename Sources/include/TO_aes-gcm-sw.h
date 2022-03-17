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
 *
 * aes-gcm generic declaration for TLS_HANDHAKE_ONLY mode.
 */

#ifndef _AES_GCM_SW_H_
#define _AES_GCM_SW_H_

#include "TO.h"
#include "TO_helper.h"

TO_ret_t aes_gcm_sw_setup_cipher_ctx(void *ctx, uint16_t cipher_suite,
		uint8_t **key_block, uint8_t *key_block_length,
		uint16_t *cipher_overhead_length,
		TOSE_helper_tls_unsecure_record *unsecure_record,
		TOSE_helper_tls_secure_record *secure_record);

#endif /* _AES_GCM_SW_H_ */

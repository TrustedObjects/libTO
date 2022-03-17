/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2021  Trusted Objects. All rights reserved.
 *
 * aes-gcm generic implementation for TLS_HANDHAKE_ONLY mode.
 */

#include "TO_aes-gcm-sw.h"
#include "TO_gcm.h"

static struct aes_gcm_sw_cipher_ctx aes_gcm_sw_cipher_ctx;
struct aes_gcm_sw_cipher_ctx {
	uint8_t key_block[2*(TO_AES_KEYSIZE + TO_TLS_AEAD_IMPLICIT_NONCE_SIZE)];
	uint8_t *cli_key;
	uint8_t *srv_key;
	uint8_t *cli_iv;
	uint8_t *srv_iv;
	uint64_t cli_seq;
	uint64_t srv_seq;
	gcm_context gcm_ctx_cli;
	gcm_context gcm_ctx_srv;
};
static TO_ret_t aes_gcm_sw_unsecure_record(void *cipher_ctx,
			uint16_t hdr_length,
			uint8_t *in, uint16_t in_length,
			uint8_t **out, uint16_t *out_length)
{
	int ret;
	struct aes_gcm_sw_cipher_ctx *ctx = cipher_ctx;
	if (ctx->srv_seq == 0) {
		/* 1st message to unsecure: create the server key's context */
		ret = gcm_setkey(&ctx->gcm_ctx_srv, ctx->srv_key, TO_AES_KEYSIZE);
		if (ret) {
			return TO_ERROR;
		}
	}

	/* nonce */
	uint8_t nonce[TO_TLS_AEAD_IMPLICIT_NONCE_SIZE + TO_TLS_AEAD_EXPLICIT_NONCE_SIZE];
	memcpy(nonce, ctx->srv_iv, TO_TLS_AEAD_IMPLICIT_NONCE_SIZE);
	memcpy(nonce + TO_TLS_AEAD_IMPLICIT_NONCE_SIZE, in + hdr_length,
			TO_TLS_AEAD_EXPLICIT_NONCE_SIZE);

	/* compute plain text length */
	*out_length = in_length - (hdr_length + TO_TLS_AEAD_EXPLICIT_NONCE_SIZE + TO_AESGCM_TAG_SIZE);
	uint64_t be64_val = htobe64(ctx->srv_seq);
	uint16_t be16_val = htobe16(*out_length);
	uint16_t ad_len = sizeof(be64_val) + hdr_length;
	uint8_t ad[32];
	if (ad_len > sizeof ad) {
		return TO_ERROR;
	}

	/* additional data: sequence_number || plain_text_header */
	memcpy(ad, &be64_val, sizeof be64_val);
	memcpy(ad + sizeof be64_val, in, hdr_length - sizeof be16_val);
	memcpy(ad + sizeof be64_val + hdr_length - sizeof be16_val, &be16_val, sizeof be16_val);

	/* unsecure payload in place */
	*out = in;
	ret = gcm_auth_decrypt(&ctx->gcm_ctx_srv, nonce, sizeof nonce, ad, ad_len,
			in + hdr_length + TO_TLS_AEAD_EXPLICIT_NONCE_SIZE,
			*out, *out_length,
			in + hdr_length + TO_TLS_AEAD_EXPLICIT_NONCE_SIZE + *out_length,
			TO_AESGCM_TAG_SIZE);

	if (ret) {
		return TO_ERROR;
	}
	ctx->srv_seq++;
	return TO_OK;
}

static TO_ret_t aes_gcm_sw_secure_record(void *cipher_ctx,
			uint8_t *hdr, uint16_t hdr_length,
			const uint8_t *in, uint16_t in_length,
			uint8_t **out, uint16_t *out_length)
{
	int ret;
	struct aes_gcm_sw_cipher_ctx *ctx = cipher_ctx;
	if (ctx->cli_seq == 0) {
		/* 1st message to secure: create the client key's context */
		ret = gcm_setkey(&ctx->gcm_ctx_cli, ctx->cli_key, TO_AES_KEYSIZE);
		if (ret) {
			return TO_ERROR;
		}
	}

	/* nonce */
	uint8_t nonce[TO_TLS_AEAD_IMPLICIT_NONCE_SIZE + TO_TLS_AEAD_EXPLICIT_NONCE_SIZE];
	uint64_t be64_val = htobe64(ctx->cli_seq);
	memcpy(nonce, ctx->cli_iv, TO_TLS_AEAD_IMPLICIT_NONCE_SIZE);
	memcpy(nonce + TO_TLS_AEAD_IMPLICIT_NONCE_SIZE, &be64_val,
			TO_TLS_AEAD_EXPLICIT_NONCE_SIZE);

	/* aditional data */
	uint16_t ad_len = sizeof(be64_val) + hdr_length;
	uint8_t ad[32];
	if (ad_len > sizeof ad) {
		return TO_ERROR;
	}
	memcpy(ad, &be64_val, sizeof be64_val);
	memcpy(ad + sizeof be64_val, hdr, hdr_length);

	/* secure payload */
	ret = gcm_crypt_and_tag(&ctx->gcm_ctx_cli, ENCRYPT,
			nonce, sizeof(nonce), ad, ad_len,
			in, *out + TO_TLS_AEAD_EXPLICIT_NONCE_SIZE, in_length,
			*out + TO_TLS_AEAD_EXPLICIT_NONCE_SIZE + in_length, TO_AESGCM_TAG_SIZE);
	memcpy(*out, &be64_val, TO_TLS_AEAD_EXPLICIT_NONCE_SIZE);
	if (ret) {
		return TO_ERROR;
	}
	*out_length = TO_TLS_AEAD_EXPLICIT_NONCE_SIZE + in_length + TO_AESGCM_TAG_SIZE;
	ctx->cli_seq++;
	return TO_OK;
}

TO_ret_t aes_gcm_sw_setup_cipher_ctx(void *cipher_ctx, uint16_t cipher_suite,
		uint8_t **key_block, uint8_t *key_block_length,
		uint16_t *cipher_overhead_length,
		TOSE_helper_tls_unsecure_record *unsecure_record,
		TOSE_helper_tls_secure_record *secure_record)
{
	if (cipher_suite != TO_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) {
		return TO_INVALID_PARAM;
	}
	struct aes_gcm_sw_cipher_ctx *ctx = cipher_ctx;
	memset(ctx, 0, sizeof *ctx);

	/* setup callback and cipher overhead needed by libTO */
	*unsecure_record = aes_gcm_sw_unsecure_record;
	*secure_record = aes_gcm_sw_secure_record;
	*cipher_overhead_length = TO_TLS_AEAD_EXPLICIT_NONCE_SIZE + TO_AESGCM_TAG_SIZE;

	/* setup the key materials inside the key block */
	ctx->cli_key = ctx->key_block;
	ctx->srv_key = ctx->cli_key + TO_AES_KEYSIZE;
	ctx->cli_iv = ctx->srv_key + TO_AES_KEYSIZE;
	ctx->srv_iv = ctx->cli_iv + TO_TLS_AEAD_IMPLICIT_NONCE_SIZE;

	/* The key block is still empty at this point, as this callback is called
	 * after the cipher suite is negotiated but before the computation of the
	 * master secret.
	 * The key context initialisation is thus deferred to the first call of
	 * aes_gcm_sw_unsecure_record/aes_gcm_sw_secure_record, but the tables
	 * can still be initialized now. */
	*key_block = ctx->key_block;
	*key_block_length = sizeof ctx->key_block;
	aes_init_keygen_tables();

	return TO_OK;
}

void *default_cipher_ctx = &aes_gcm_sw_cipher_ctx;
TOSE_helper_tls_setup_cipher_ctx default_setup_cipher_ctx = aes_gcm_sw_setup_cipher_ctx;

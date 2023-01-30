/**
 *
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 *
 * Copyright (C) 2020-2021 Trusted Objects. All rights reserved.
 *
 */

#define TODRV_API_CONFIG_ALL
#include "TO.h"
#include "TO_defs.h"
#include "TO_log.h"
#include "TO_cfg.h"
#include "TO_driver.h"
#include "TO_retcodes.h"
#include "TO_utils.h"
#include "TO_portability.h"


#define FUNC_PTR(ctx, type, func) \
	((uintptr_t)((TODRV_api_##type##_t*)(((uintptr_t*)&(ctx)->drv->api->api) + TO_saferead_uint8(&(ctx)->drv->api->offsets.type)))->func)

#define CHECK_CTX(ctx, type, func) \
{ \
	if (TO_saferead_uint8(&(ctx)->initialized) != 1) { \
		TO_LOG_ERR("Driver not initialized",0); \
		return TORSP_COND_OF_USE_NOT_SATISFIED; \
	} \
	if ((TO_saferead_uint8(&((ctx)->drv->api->offsets.type)) == TODRV_API_OFFSET_NOT_AVAILABLE) ||\
			(!FUNC_PTR(ctx, type, func))) { \
		TO_LOG_ERR("not implemented by driver (offset = %02x, ptr = %p)", \
				TO_saferead_uint8(&((ctx)->drv->api->offsets.type)), \
				FUNC_PTR(ctx, type, func)); \
		return TORSP_UNKNOWN_CMD; \
	} \
}

#define GET_PRIV_CTX(ctx) ((ctx)->drv->priv_ctx)

#define DRV_CALL(ctx, type, func, ...) ((TODRV_##func##_f*)(FUNC_PTR(ctx, type, func) + (ctx)->drv->func_offset))(__VA_ARGS__)
#define DRV_CALL_CHECK(ctx, type, func, ...) \
{ \
	CHECK_CTX(ctx, type, func) \
	return DRV_CALL(ctx, type, func, __VA_ARGS__); \
}

#ifdef TO_ENDIAN_RUNTIME_DETECT
int TO_byte_order = TO_BYTE_ORDER_LITTLE_ENDIAN;
static void detect_endianness(void)
{
	union {
		uint32_t intval;
		char rawval[sizeof(uint32_t)];
	} integer;
	integer.intval = 1;
	if (integer.rawval[0]) {
		TO_byte_order = TO_BYTE_ORDER_LITTLE_ENDIAN;
	} else {
		TO_byte_order = TO_BYTE_ORDER_BIG_ENDIAN;
	}
}
#endif

static TO_ret_t check_api_version(TOSE_ctx_t *ctx)
{
	const TODRV_api_version_t *drv_api_version = &ctx->drv->api->api_version;
	const TODRV_api_version_t cur_api_version = TODRV_API_VERSION;

	if (TO_saferead_uint8((void *)&drv_api_version->major) != cur_api_version.major) {
		TO_LOG_ERR("Driver API version major (%02x) must match current (%02x)",
				TO_saferead_uint8((void *)&drv_api_version->major),
				cur_api_version.major);
		return TORSP_COND_OF_USE_NOT_SATISFIED;
	}

	return TORSP_SUCCESS;
}

TO_lib_ret_t TOSE_init(TOSE_ctx_t *ctx)
{
	TO_ret_t ret;


#ifdef TO_ENDIAN_RUNTIME_DETECT
	detect_endianness();
#endif

	ctx->drv->log_ctx = TO_log_get_ctx();

	/* Check API version compatibility */
	if ((ret = check_api_version(ctx)) != TORSP_SUCCESS) {
		TO_LOG_ERR("Bad driver API version compatibility",0);
		return (TO_lib_ret_t)(TO_ERROR | ret);
	} else {
		TO_LOG_DBG("API versions are matching",0);
	}

	if ((ret = DRV_CALL(ctx, common, init, GET_PRIV_CTX(ctx),ctx->drv->log_ctx)) != TO_OK) {
		return (TO_lib_ret_t)ret;
	}

	ctx->initialized = 1;

	return (TO_lib_ret_t)TO_OK;
}

TO_lib_ret_t TOSE_fini(TOSE_ctx_t *ctx)
{
	TO_ret_t ret = DRV_CALL(ctx, common, fini, GET_PRIV_CTX(ctx));

	ctx->initialized = 0;

	return (TO_lib_ret_t)ret;
}

TO_ret_t TOSE_flush(TOSE_ctx_t *ctx) {
	TO_ret_t ret = DRV_CALL(ctx, common, flush, GET_PRIV_CTX(ctx));

	return (TO_lib_ret_t)ret;
}

TO_ret_t TOSE_get_serial_number(
		TOSE_ctx_t *ctx,
		uint8_t serial_number[TO_SN_SIZE]
) {
	DRV_CALL_CHECK(ctx, to_info, get_serial_number, GET_PRIV_CTX(ctx), serial_number)
}
TO_ret_t TOSE_get_hardware_serial_number(
		TOSE_ctx_t *ctx,
		uint8_t hardware_serial_number[TO_HW_SN_SIZE]
) {
	DRV_CALL_CHECK(ctx, to_info, get_hardware_serial_number, GET_PRIV_CTX(ctx), hardware_serial_number)
}
TO_ret_t TOSE_get_product_number(
		TOSE_ctx_t *ctx,
		uint8_t product_number[TO_PN_SIZE]
) {
	DRV_CALL_CHECK(ctx, to_info, get_product_number, GET_PRIV_CTX(ctx), product_number)
}
TO_ret_t TOSE_access_dummy_data(
		TOSE_ctx_t *ctx,
		uint8_t write_data,
		uint32_t *dummy_data
) {
	DRV_CALL_CHECK(ctx, to_info, access_dummy_data, GET_PRIV_CTX(ctx), write_data, dummy_data)
}
TO_ret_t TOSE_get_hardware_version(
		TOSE_ctx_t *ctx,
		uint8_t hardware_version[TO_HW_VERSION_SIZE]
) {
	DRV_CALL_CHECK(ctx, to_info, get_hardware_version, GET_PRIV_CTX(ctx), hardware_version)
}
TO_ret_t TOSE_get_software_version(
		TOSE_ctx_t *ctx,
		uint8_t* major,
		uint8_t* minor,
		uint8_t* revision
) {
	DRV_CALL_CHECK(ctx, to_info, get_software_version, GET_PRIV_CTX(ctx), major, minor, revision)
}
TO_ret_t TOSE_get_product_id(
		TOSE_ctx_t *ctx,
		uint8_t product_id[TO_PRODUCT_ID_SIZE]
) {
	DRV_CALL_CHECK(ctx, to_info, get_product_id, GET_PRIV_CTX(ctx), product_id)
}
TO_ret_t TOSE_sha256(
		TOSE_ctx_t *ctx,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t sha256[TO_SHA256_HASHSIZE]
) {
	DRV_CALL_CHECK(ctx, sha256, sha256, GET_PRIV_CTX(ctx), data, data_length, sha256)
}
TO_ret_t TOSE_sha256_init(TOSE_ctx_t *ctx) {
	DRV_CALL_CHECK(ctx, sha256, sha256_init, GET_PRIV_CTX(ctx))
}
TO_ret_t TOSE_sha256_update(
		TOSE_ctx_t *ctx,
		const uint8_t* data,
		const uint16_t length
) {
	DRV_CALL_CHECK(ctx, sha256, sha256_update, GET_PRIV_CTX(ctx), data, length)
}
TO_ret_t TOSE_sha256_final(
		TOSE_ctx_t *ctx,
		uint8_t sha256[TO_SHA256_HASHSIZE]
) {
	DRV_CALL_CHECK(ctx, sha256, sha256_final, GET_PRIV_CTX(ctx), sha256)
}
TO_ret_t TOSE_set_remote_public_key(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t public_key[TO_ECC_PUB_KEYSIZE],
		const uint8_t signature[TO_SIGNATURE_SIZE]
) {
	DRV_CALL_CHECK(ctx, keys_mgmt, set_remote_public_key, GET_PRIV_CTX(ctx), key_index, public_key, signature)
}
TO_ret_t TOSE_renew_ecc_keys(
		TOSE_ctx_t *ctx,
		const uint8_t key_index
) {
	DRV_CALL_CHECK(ctx, keys_mgmt, renew_ecc_keys, GET_PRIV_CTX(ctx), key_index)
}
TO_ret_t TOSE_get_public_key(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		uint8_t public_key[TO_ECC_PUB_KEYSIZE],
		uint8_t signature[TO_SIGNATURE_SIZE]
) {
	DRV_CALL_CHECK(ctx, keys_mgmt, get_public_key, GET_PRIV_CTX(ctx), key_index, public_key, signature)
}
TO_ret_t TOSE_get_unsigned_public_key(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		uint8_t public_key[TO_ECC_PUB_KEYSIZE]
) {
	DRV_CALL_CHECK(ctx, keys_mgmt, get_unsigned_public_key, GET_PRIV_CTX(ctx), key_index, public_key)
}
TO_ret_t TOSE_renew_shared_keys(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t public_key_index
) {
	DRV_CALL_CHECK(ctx, keys_mgmt, renew_shared_keys, GET_PRIV_CTX(ctx), key_index, public_key_index)
}
TO_ret_t TOSE_get_key_fingerprint(
		TOSE_ctx_t *ctx,
		TO_key_type_t key_type,
		uint8_t key_index,
		uint8_t* fingerprint[TO_KEY_FINGERPRINT_SIZE]
) {
	DRV_CALL_CHECK(ctx, keys_mgmt, get_key_fingerprint, GET_PRIV_CTX(ctx), key_type, key_index, fingerprint)
}
TO_ret_t TOSE_aes128cbc_encrypt(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram
) {
	DRV_CALL_CHECK(ctx, aes_encrypt, aes128cbc_encrypt, GET_PRIV_CTX(ctx), key_index, data, data_length, initial_vector, cryptogram)
}
TO_ret_t TOSE_aes128cbc_iv_encrypt(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t* cryptogram
) {
	DRV_CALL_CHECK(ctx, aes_encrypt, aes128cbc_iv_encrypt, GET_PRIV_CTX(ctx), key_index, initial_vector, data, data_length, cryptogram)
}
TO_ret_t TOSE_aes128cbc_decrypt(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram,
		const uint16_t cryptogram_length,
		uint8_t* data
) {
	DRV_CALL_CHECK(ctx, aes_encrypt, aes128cbc_decrypt, GET_PRIV_CTX(ctx), key_index, initial_vector, cryptogram, cryptogram_length, data)
}
TO_ret_t TOSE_aes128gcm_encrypt(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		const uint8_t* aad,
		const uint16_t aad_length,
		uint8_t initial_vector[TO_AESGCM_INITIALVECTOR_SIZE],
		uint8_t* cryptogram,
		uint8_t tag[TO_AESGCM_TAG_SIZE]
) {
	DRV_CALL_CHECK(ctx, aes_encrypt, aes128gcm_encrypt, GET_PRIV_CTX(ctx), key_index, data, data_length, aad, aad_length, initial_vector, cryptogram, tag)
}
TO_ret_t TOSE_aes128gcm_decrypt(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t initial_vector[TO_AESGCM_INITIALVECTOR_SIZE],
		const uint8_t* aad,
		const uint16_t aad_length,
		const uint8_t* cryptogram,
		const uint16_t cryptogram_length,
		const uint8_t tag[TO_AESGCM_TAG_SIZE],
		uint8_t* data
) {
	DRV_CALL_CHECK(ctx, aes_encrypt, aes128gcm_decrypt, GET_PRIV_CTX(ctx), key_index, initial_vector, aad, aad_length, cryptogram, cryptogram_length, tag, data)
}
TO_ret_t TOSE_aes128ccm_encrypt(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		const uint8_t* aad,
		const uint16_t aad_length,
		uint8_t nonce[TO_AESCCM_NONCE_SIZE],
		uint8_t* cryptogram,
		uint8_t tag[TO_AESCCM_TAG_SIZE]
) {
	DRV_CALL_CHECK(ctx, aes_encrypt, aes128ccm_encrypt, GET_PRIV_CTX(ctx), key_index, data, data_length, aad, aad_length, nonce, cryptogram, tag)
}
TO_ret_t TOSE_aes128ccm_decrypt(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t nonce[TO_AESCCM_NONCE_SIZE],
		const uint8_t* aad,
		const uint16_t aad_length,
		const uint8_t* cryptogram,
		const uint16_t cryptogram_length,
		const uint8_t tag[TO_AESCCM_TAG_SIZE],
		uint8_t* data
) {
	DRV_CALL_CHECK(ctx, aes_encrypt, aes128ccm_decrypt, GET_PRIV_CTX(ctx), key_index, nonce, aad, aad_length, cryptogram, cryptogram_length, tag, data)
}
TO_ret_t TOSE_aes128ecb_encrypt(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t* cryptogram
) {
	DRV_CALL_CHECK(ctx, aes_encrypt, aes128ecb_encrypt, GET_PRIV_CTX(ctx), key_index, data, data_length, cryptogram)
}
TO_ret_t TOSE_aes128ecb_decrypt(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* cryptogram,
		const uint16_t cryptogram_length,
		uint8_t* data
) {
	DRV_CALL_CHECK(ctx, aes_encrypt, aes128ecb_decrypt, GET_PRIV_CTX(ctx), key_index, cryptogram, cryptogram_length, data)
}
TO_ret_t TOSE_compute_hmac(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t hmac_data[TO_HMAC_SIZE]
) {
	DRV_CALL_CHECK(ctx, hmac, compute_hmac, GET_PRIV_CTX(ctx), key_index, data, data_length, hmac_data)
}
TO_ret_t TOSE_compute_hmac_init(
		TOSE_ctx_t *ctx,
		uint8_t key_index
) {
	DRV_CALL_CHECK(ctx, hmac, compute_hmac_init, GET_PRIV_CTX(ctx), key_index)
}
TO_ret_t TOSE_compute_hmac_update(
		TOSE_ctx_t *ctx,
		const uint8_t* data,
		uint16_t length
) {
	DRV_CALL_CHECK(ctx, hmac, compute_hmac_update, GET_PRIV_CTX(ctx), data, length)
}
TO_ret_t TOSE_compute_hmac_final(
		TOSE_ctx_t *ctx,
		uint8_t hmac[TO_HMAC_SIZE]
) {
	DRV_CALL_CHECK(ctx, hmac, compute_hmac_final, GET_PRIV_CTX(ctx), hmac)
}
TO_ret_t TOSE_verify_hmac(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		const uint8_t hmac_data[TO_HMAC_SIZE]
) {
	DRV_CALL_CHECK(ctx, hmac, verify_hmac, GET_PRIV_CTX(ctx), key_index, data, data_length, hmac_data)
}
TO_ret_t TOSE_verify_hmac_init(
		TOSE_ctx_t *ctx,
		uint8_t key_index
) {
	DRV_CALL_CHECK(ctx, hmac, verify_hmac_init, GET_PRIV_CTX(ctx), key_index)
}
TO_ret_t TOSE_verify_hmac_update(
		TOSE_ctx_t *ctx,
		const uint8_t* data,
		uint16_t length
) {
	DRV_CALL_CHECK(ctx, hmac, verify_hmac_update, GET_PRIV_CTX(ctx), data, length)
}
TO_ret_t TOSE_verify_hmac_final(
		TOSE_ctx_t *ctx,
		const uint8_t hmac[TO_HMAC_SIZE]
) {
	DRV_CALL_CHECK(ctx, hmac, verify_hmac_final, GET_PRIV_CTX(ctx), hmac)
}
TO_ret_t TOSE_compute_cmac(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t cmac_data[TO_CMAC_SIZE]
) {
	DRV_CALL_CHECK(ctx, cmac, compute_cmac, GET_PRIV_CTX(ctx), key_index, data, data_length, cmac_data)
}
TO_ret_t TOSE_verify_cmac(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		const uint8_t cmac_data[TO_CMAC_SIZE]
) {
	DRV_CALL_CHECK(ctx, cmac, verify_cmac, GET_PRIV_CTX(ctx), key_index, data, data_length, cmac_data)
}
TO_ret_t TOSE_aes128cbc_hmac_secure_message(
		TOSE_ctx_t *ctx,
		const uint8_t aes_key_index,
		const uint8_t hmac_key_index,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram,
		uint8_t hmac[TO_HMAC_SIZE]
) {
	DRV_CALL_CHECK(ctx, sec_msg, aes128cbc_hmac_secure_message, GET_PRIV_CTX(ctx), aes_key_index, hmac_key_index, data, data_length, initial_vector, cryptogram, hmac)
}
TO_ret_t TOSE_aes128cbc_hmac_unsecure_message(
		TOSE_ctx_t *ctx,
		const uint8_t aes_key_index,
		const uint8_t hmac_key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram,
		const uint16_t cryptogram_length,
		const uint8_t hmac[TO_HMAC_SIZE],
		uint8_t* data
) {
	DRV_CALL_CHECK(ctx, sec_msg, aes128cbc_hmac_unsecure_message, GET_PRIV_CTX(ctx), aes_key_index, hmac_key_index, initial_vector, cryptogram, cryptogram_length, hmac, data)
}
TO_ret_t TOSE_aes128cbc_cmac_secure_message(
		TOSE_ctx_t *ctx,
		const uint8_t aes_key_index,
		const uint8_t cmac_key_index,
		const uint8_t* data,
		const uint16_t data_length,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t* cryptogram,
		uint8_t cmac[TO_CMAC_SIZE]
) {
	DRV_CALL_CHECK(ctx, sec_msg, aes128cbc_cmac_secure_message, GET_PRIV_CTX(ctx), aes_key_index, cmac_key_index, data, data_length, initial_vector, cryptogram, cmac)
}
TO_ret_t TOSE_aes128cbc_cmac_unsecure_message(
		TOSE_ctx_t *ctx,
		const uint8_t aes_key_index,
		const uint8_t cmac_key_index,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram,
		const uint16_t cryptogram_length,
		const uint8_t cmac[TO_CMAC_SIZE],
		uint8_t* data
) {
	DRV_CALL_CHECK(ctx, sec_msg, aes128cbc_cmac_unsecure_message, GET_PRIV_CTX(ctx), aes_key_index, cmac_key_index, initial_vector, cryptogram, cryptogram_length, cmac, data)
}
TO_ret_t TOSE_secure_payload(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const TO_enc_alg_t enc_alg,
		const TO_mac_alg_t mac_alg,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t* payload,
		uint16_t* payload_len
) {
	DRV_CALL_CHECK(ctx, sec_msg, secure_payload, GET_PRIV_CTX(ctx), key_index, enc_alg, mac_alg, data, data_len, payload, payload_len)
}
TO_ret_t TOSE_secure_payload_init(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const TO_enc_alg_t enc_alg,
		const TO_mac_alg_t mac_alg,
		const uint16_t data_len,
		uint8_t sequence[TO_SEQUENCE_SIZE],
		uint8_t *iv,
		uint16_t *iv_len
) {
	DRV_CALL_CHECK(ctx, sec_msg, secure_payload_init, GET_PRIV_CTX(ctx), key_index, enc_alg, mac_alg, data_len, sequence, iv, iv_len)
}
TO_ret_t TOSE_secure_payload_update(
		TOSE_ctx_t *ctx,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t* cryptogram
) {
	DRV_CALL_CHECK(ctx, sec_msg, secure_payload_update, GET_PRIV_CTX(ctx), data, data_len, cryptogram)
}
TO_ret_t TOSE_secure_payload_final(
		TOSE_ctx_t *ctx,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t* cryptogram,
		uint16_t* cryptogram_len
) {
	DRV_CALL_CHECK(ctx, sec_msg, secure_payload_final, GET_PRIV_CTX(ctx), data, data_len, cryptogram, cryptogram_len)
}
TO_ret_t TOSE_unsecure_payload(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const TO_enc_alg_t enc_alg,
		const TO_mac_alg_t mac_alg,
		const uint8_t* payload,
		const uint16_t payload_len,
		uint8_t* data,
		uint16_t* data_len
) {
	DRV_CALL_CHECK(ctx, sec_msg, unsecure_payload, GET_PRIV_CTX(ctx), key_index, enc_alg, mac_alg, payload, payload_len, data, data_len)
}
TO_ret_t TOSE_unsecure_payload_init_cbc(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const TO_enc_alg_t enc_alg,
		const TO_mac_alg_t mac_alg,
		const uint16_t cryptogram_len,
		const uint8_t sequence[TO_SEQUENCE_SIZE],
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE]
) {
	DRV_CALL_CHECK(ctx, sec_msg, unsecure_payload_init_cbc, GET_PRIV_CTX(ctx), key_index, enc_alg, mac_alg, cryptogram_len, sequence, initial_vector, last_block_iv, last_block)
}
TO_ret_t TOSE_unsecure_payload_init_aead(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const TO_enc_alg_t enc_alg,
		const TO_mac_alg_t mac_alg,
		const uint16_t cryptogram_len,
		const uint8_t sequence[TO_SEQUENCE_SIZE]
) {
	DRV_CALL_CHECK(ctx, sec_msg, unsecure_payload_init_aead, GET_PRIV_CTX(ctx), key_index, enc_alg, mac_alg, cryptogram_len, sequence)
}
TO_ret_t TOSE_unsecure_payload_update(
		TOSE_ctx_t *ctx,
		const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t* data,
		uint16_t* data_len
) {
	DRV_CALL_CHECK(ctx, sec_msg, unsecure_payload_update, GET_PRIV_CTX(ctx), cryptogram, cryptogram_len, data, data_len)
}
TO_ret_t TOSE_unsecure_payload_final(TOSE_ctx_t *ctx) {
	DRV_CALL_CHECK(ctx, sec_msg, unsecure_payload_final, GET_PRIV_CTX(ctx))
}
TO_ret_t TOSE_sign(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* challenge,
		const uint16_t challenge_length,
		uint8_t signature[TO_SIGNATURE_SIZE]
) {
	DRV_CALL_CHECK(ctx, signing, sign, GET_PRIV_CTX(ctx), key_index, challenge, challenge_length, signature)
}
TO_ret_t TOSE_verify(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t* data,
		const uint16_t data_length,
		const uint8_t signature[TO_SIGNATURE_SIZE]
) {
	DRV_CALL_CHECK(ctx, signing, verify, GET_PRIV_CTX(ctx), key_index, data, data_length, signature)
}
TO_ret_t TOSE_sign_hash(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t hash[TO_HASH_SIZE],
		uint8_t signature[TO_SIGNATURE_SIZE])
{
	DRV_CALL_CHECK(ctx, signing, sign_hash, GET_PRIV_CTX(ctx), key_index, hash, signature)
}
TO_ret_t TOSE_verify_hash_signature(
		TOSE_ctx_t *ctx,
		const uint8_t key_index,
		const uint8_t hash[TO_HASH_SIZE],
		const uint8_t signature[TO_SIGNATURE_SIZE]
) {
	DRV_CALL_CHECK(ctx, signing, verify_hash_signature, GET_PRIV_CTX(ctx), key_index, hash, signature)
}
TO_ret_t TOSE_get_certificate_subject_cn(
		TOSE_ctx_t *ctx,
		const uint8_t certificate_index,
		char subject_cn[TO_CERT_SUBJECT_CN_MAXSIZE + 1]
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, get_certificate_subject_cn, GET_PRIV_CTX(ctx), certificate_index, subject_cn)
}
TO_ret_t TOSE_set_certificate_signing_request_dn(
		TOSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const uint8_t csr_dn[TO_CERT_DN_MAXSIZE],
		const uint16_t csr_dn_len
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, set_certificate_signing_request_dn, GET_PRIV_CTX(ctx), certificate_index, csr_dn, csr_dn_len)
}
TO_ret_t TOSE_get_certificate_signing_request(
		TOSE_ctx_t *ctx,
		const uint8_t certificate_index,
		uint8_t* csr,
		uint16_t* size
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, get_certificate_signing_request, GET_PRIV_CTX(ctx), certificate_index, csr, size)
}
TO_ret_t TOSE_get_certificate(
		TOSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const TO_certificate_format_t format,
		uint8_t* certificate
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, get_certificate, GET_PRIV_CTX(ctx), certificate_index, format, certificate)
}
TO_ret_t TOSE_get_certificate_x509(
		TOSE_ctx_t *ctx,
		const uint8_t certificate_index,
		uint8_t* certificate,
		uint16_t* size
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, get_certificate_x509, GET_PRIV_CTX(ctx), certificate_index, certificate, size)
}
TO_ret_t TOSE_set_certificate_x509(
		TOSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const uint8_t* certificate,
		const uint16_t size
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, set_certificate_x509, GET_PRIV_CTX(ctx), certificate_index, certificate, size)
}
TO_ret_t TOSE_set_certificate_x509_init(
		TOSE_ctx_t *ctx,
		const uint8_t certificate_index
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, set_certificate_x509_init, GET_PRIV_CTX(ctx), certificate_index)
}
TO_ret_t TOSE_set_certificate_x509_update(
		TOSE_ctx_t *ctx,
		const uint8_t* certificate,
		const uint16_t size
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, set_certificate_x509_update, GET_PRIV_CTX(ctx), certificate, size)
}
TO_ret_t TOSE_set_certificate_x509_final(
		TOSE_ctx_t *ctx
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, set_certificate_x509_final, GET_PRIV_CTX(ctx))
}
TO_ret_t TOSE_get_certificate_and_sign(
		TOSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const TO_certificate_format_t format,
		const uint8_t* challenge,
		const uint16_t challenge_length,
		uint8_t* certificate,
		uint8_t* signature
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, get_certificate_and_sign, GET_PRIV_CTX(ctx), certificate_index, format, challenge, challenge_length, certificate, signature)
}
TO_ret_t TOSE_get_certificate_x509_and_sign(
		TOSE_ctx_t *ctx,
		const uint8_t certificate_index,
		const uint8_t* challenge,
		const uint16_t challenge_length,
		uint8_t* certificate,
		uint16_t* size,
		uint8_t* signature
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, get_certificate_x509_and_sign, GET_PRIV_CTX(ctx), certificate_index, challenge, challenge_length, certificate, size, signature)
}
TO_ret_t TOSE_get_certificate_x509_init(
		TOSE_ctx_t *ctx,
		const uint8_t certificate_index
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, get_certificate_x509_init, GET_PRIV_CTX(ctx), certificate_index)
}
TO_ret_t TOSE_get_certificate_x509_update(
		TOSE_ctx_t *ctx,
		uint8_t* certificate,
		uint16_t* size
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, get_certificate_x509_update, GET_PRIV_CTX(ctx), certificate, size)
}
TO_ret_t TOSE_get_certificate_x509_final(
		TOSE_ctx_t *ctx,
		const uint8_t* challenge,
		const uint16_t challenge_length,
		uint8_t* signature
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, get_certificate_x509_final, GET_PRIV_CTX(ctx), challenge, challenge_length, signature)
}
TO_ret_t TOSE_verify_certificate_and_store(
		TOSE_ctx_t *ctx,
		const uint8_t ca_key_id,
		const TO_certificate_format_t format,
		const uint8_t* certificate
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, verify_certificate_and_store, GET_PRIV_CTX(ctx), ca_key_id, format, certificate)
}
TO_ret_t TOSE_verify_ca_certificate_and_store(
		TOSE_ctx_t *ctx,
		const uint8_t ca_key_index,
		const uint8_t subca_key_index,
		const uint8_t *certificate,
		const uint16_t certificate_len
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, verify_ca_certificate_and_store, GET_PRIV_CTX(ctx), ca_key_index, subca_key_index, certificate, certificate_len)
}
TO_ret_t TOSE_get_challenge_and_store(
		TOSE_ctx_t *ctx,
		uint8_t challenge[TO_CHALLENGE_SIZE]
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, get_challenge_and_store, GET_PRIV_CTX(ctx), challenge)
}
TO_ret_t TOSE_verify_challenge_signature(
		TOSE_ctx_t *ctx,
		const uint8_t signature[TO_SIGNATURE_SIZE]
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, verify_challenge_signature, GET_PRIV_CTX(ctx), signature)
}
TO_ret_t TOSE_verify_chain_certificate_and_store_init(
		TOSE_ctx_t *ctx,
		const uint8_t ca_key_index
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, verify_chain_certificate_and_store_init, GET_PRIV_CTX(ctx), ca_key_index)
}
TO_ret_t TOSE_verify_chain_certificate_and_store_update(
		TOSE_ctx_t *ctx,
		const uint8_t *chain_certificate,
		const uint16_t chain_certificate_length
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, verify_chain_certificate_and_store_update, GET_PRIV_CTX(ctx), chain_certificate, chain_certificate_length)
}
TO_ret_t TOSE_verify_chain_certificate_and_store_final(TOSE_ctx_t *ctx) {
	DRV_CALL_CHECK(ctx, cert_mgmt, verify_chain_certificate_and_store_final, GET_PRIV_CTX(ctx))
}
TO_ret_t TOSE_verify_chain_ca_certificate_and_store_init(
		TOSE_ctx_t *ctx,
		const uint8_t ca_key_index,
		const uint8_t subca_key_index
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, verify_chain_ca_certificate_and_store_init, GET_PRIV_CTX(ctx), ca_key_index, subca_key_index)
}
TO_ret_t TOSE_verify_chain_ca_certificate_and_store_update(
		TOSE_ctx_t *ctx,
		const uint8_t *chain_ca_certificate,
		const uint16_t chain_ca_certificate_length
) {
	DRV_CALL_CHECK(ctx, cert_mgmt, verify_chain_ca_certificate_and_store_update, GET_PRIV_CTX(ctx), chain_ca_certificate, chain_ca_certificate_length)
}
TO_ret_t TOSE_verify_chain_ca_certificate_and_store_final(TOSE_ctx_t *ctx) {
	DRV_CALL_CHECK(ctx, cert_mgmt, verify_chain_ca_certificate_and_store_final, GET_PRIV_CTX(ctx))
}
TO_ret_t TOSE_write_nvm(
		TOSE_ctx_t *ctx,
		const uint16_t offset,
		const void *data,
		unsigned int length,
		const uint8_t key[TO_AES_KEYSIZE]
) {
	DRV_CALL_CHECK(ctx, nvm, write_nvm, GET_PRIV_CTX(ctx), offset, data, length, key)
}
TO_ret_t TOSE_read_nvm(
		TOSE_ctx_t *ctx,
		const uint16_t offset,
		void *data,
		unsigned int length,
		const uint8_t key[TO_AES_KEYSIZE]
) {
	DRV_CALL_CHECK(ctx, nvm, read_nvm, GET_PRIV_CTX(ctx), offset, data, length, key)
}
TO_ret_t TOSE_get_nvm_size(
		TOSE_ctx_t *ctx,
		uint16_t *size
) {
	DRV_CALL_CHECK(ctx, nvm, get_nvm_size, GET_PRIV_CTX(ctx), size)
}
TO_ret_t TOSE_set_tls_server_random(
		TOSE_ctx_t *ctx,
		uint8_t random[TO_TLS_RANDOM_SIZE]
) {
	DRV_CALL_CHECK(ctx, tls, set_tls_server_random, GET_PRIV_CTX(ctx), random)
}
TO_ret_t TOSE_set_tls_server_eph_pub_key(
		TOSE_ctx_t *ctx,
		uint8_t key_index,
		uint8_t ecc_params[TO_TLS_SERVER_PARAMS_SIZE],
		uint8_t signature[TO_SIGNATURE_SIZE]
) {
	DRV_CALL_CHECK(ctx, tls, set_tls_server_eph_pub_key, GET_PRIV_CTX(ctx), key_index, ecc_params, signature)
}
TO_ret_t TOSE_get_tls_random_and_store(
		TOSE_ctx_t *ctx,
		uint8_t timestamp[TO_TIMESTAMP_SIZE],
		uint8_t random[TO_TLS_RANDOM_SIZE]
) {
	DRV_CALL_CHECK(ctx, tls, get_tls_random_and_store, GET_PRIV_CTX(ctx), timestamp, random)
}
TO_ret_t TOSE_get_tls_master_secret(
		TOSE_ctx_t *ctx,
		uint8_t master_secret[TO_TLS_MASTER_SECRET_SIZE]
) {
	DRV_CALL_CHECK(ctx, tls, get_tls_master_secret, GET_PRIV_CTX(ctx), master_secret)
}
TO_ret_t TOSE_get_tls_master_secret_derived_keys(
		TOSE_ctx_t *ctx,
		uint8_t key_block_length,
		uint8_t *key_block
) {
	DRV_CALL_CHECK(ctx, tls, get_tls_master_secret_derived_keys,
			GET_PRIV_CTX(ctx), key_block_length, key_block)
}
TO_ret_t TOSE_renew_tls_keys_ecdhe(
		TOSE_ctx_t *ctx,
		const uint8_t kpriv_index,
		const uint8_t kpub_index,
		const uint8_t enc_key_index,
		const uint8_t dec_key_index
) {
	DRV_CALL_CHECK(ctx, tls, renew_tls_keys_ecdhe, GET_PRIV_CTX(ctx), kpriv_index, kpub_index, enc_key_index, dec_key_index)
}
TO_ret_t TOSE_tls_calculate_finished(
		TOSE_ctx_t *ctx,
		const int from,
		const uint8_t handshake_hash[TO_HASH_SIZE],
		uint8_t finished[TO_TLS_FINISHED_SIZE]
) {
	DRV_CALL_CHECK(ctx, tls, tls_calculate_finished, GET_PRIV_CTX(ctx), from, handshake_hash, finished)
}
TO_ret_t TOSE_tls_reset(TOSE_ctx_t *ctx) {
	DRV_CALL_CHECK(ctx, tls, tls_reset, GET_PRIV_CTX(ctx))
}
TO_ret_t TOSE_tls_set_mode(
		TOSE_ctx_t *ctx,
		const TO_tls_mode_t mode
) {
	DRV_CALL_CHECK(ctx, tls, tls_set_mode, GET_PRIV_CTX(ctx), mode)
}
TO_ret_t TOSE_tls_set_config(
		TOSE_ctx_t *ctx,
		const TO_tls_config_id_t config_id,
		const uint8_t *config,
		const uint16_t config_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_set_config, GET_PRIV_CTX(ctx), config_id, config, config_len)
}
TO_ret_t TOSE_tls_set_session(
		TOSE_ctx_t *ctx,
		const uint8_t session
) {
	static int last_session = -1;
	static TO_ret_t last_ret;
	if ((int) session == last_session) {
		return last_ret;
	}
	CHECK_CTX(ctx, tls, tls_set_session)
	last_ret = DRV_CALL(ctx, tls, tls_set_session, GET_PRIV_CTX(ctx), session);
	last_session = session;
	return last_ret;
}
TO_ret_t TOSE_tls_set_cid_ext_id(
		TOSE_ctx_t *ctx,
		const TO_tls_extension_t cid_ext_id
) {
	DRV_CALL_CHECK(ctx, tls, tls_set_cid_ext_id, GET_PRIV_CTX(ctx), cid_ext_id)
}
TO_ret_t TOSE_tls_get_client_hello(
		TOSE_ctx_t *ctx,
		const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		uint8_t *client_hello,
		uint16_t *client_hello_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_get_client_hello, GET_PRIV_CTX(ctx), timestamp, client_hello, client_hello_len)
}
extern TO_ret_t TOSE_tls_get_client_hello_ext(TOSE_ctx_t *ctx,
		const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		const uint8_t *ext_data, uint16_t ext_length,
		uint8_t *client_hello, uint16_t *client_hello_len)
{
	DRV_CALL_CHECK(ctx, tls, tls_get_client_hello_ext, GET_PRIV_CTX(ctx), timestamp,
			ext_data, ext_length, client_hello, client_hello_len)
}
extern TO_ret_t TOSE_tls_get_client_hello_init(TOSE_ctx_t *ctx,
		const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		const uint8_t *ext_data, uint16_t ext_length,
		uint16_t *client_hello_len, uint8_t *final_flag)
{
	DRV_CALL_CHECK(ctx, tls, tls_get_client_hello_init, GET_PRIV_CTX(ctx), timestamp,
			ext_data, ext_length, client_hello_len, final_flag)
}
extern TO_ret_t TOSE_tls_get_client_hello_update(TOSE_ctx_t *ctx,
		uint8_t *data, uint16_t *part_len, uint8_t *final_flag)
{
	DRV_CALL_CHECK(ctx, tls, tls_get_client_hello_update, GET_PRIV_CTX(ctx),
			data, part_len, final_flag)
}
extern TO_ret_t TOSE_tls_get_client_hello_final(TOSE_ctx_t *ctx,
		uint8_t *data)
{
	DRV_CALL_CHECK(ctx, tls, tls_get_client_hello_final, GET_PRIV_CTX(ctx),
			data)
}
TO_ret_t TOSE_tls_handle_hello_verify_request(
		TOSE_ctx_t *ctx,
		const uint8_t *hello_verify_request,
		const uint32_t hello_verify_request_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_hello_verify_request, GET_PRIV_CTX(ctx), hello_verify_request, hello_verify_request_len)
}
TO_ret_t TOSE_tls_handle_server_hello(
		TOSE_ctx_t *ctx,
		const uint8_t *server_hello,
		const uint32_t server_hello_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_server_hello, GET_PRIV_CTX(ctx), server_hello, server_hello_len)
}
TO_ret_t TOSE_tls_handle_server_hello_init(
		TOSE_ctx_t *ctx,
		const uint32_t server_hello_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_server_hello_init, GET_PRIV_CTX(ctx), server_hello_len)
}
TO_ret_t TOSE_tls_handle_server_hello_update(
		TOSE_ctx_t *ctx,
		const uint8_t *data,
		const uint32_t part_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_server_hello_update, GET_PRIV_CTX(ctx), data, part_len)
}
TO_ret_t TOSE_tls_handle_server_hello_final(
		TOSE_ctx_t *ctx,
		const uint8_t *data,
		const uint32_t final_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_server_hello_final, GET_PRIV_CTX(ctx), data, final_len)
}
TO_ret_t TOSE_tls_handle_server_certificate(
		TOSE_ctx_t *ctx,
		const uint8_t *server_certificate,
		const uint32_t server_certificate_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_server_certificate, GET_PRIV_CTX(ctx), server_certificate, server_certificate_len)
}
TO_ret_t TOSE_tls_handle_server_certificate_init(
		TOSE_ctx_t *ctx,
		const uint8_t *server_certificate_init,
		const uint32_t server_certificate_init_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_server_certificate_init, GET_PRIV_CTX(ctx), server_certificate_init, server_certificate_init_len)
}
TO_ret_t TOSE_tls_handle_server_certificate_update(
		TOSE_ctx_t *ctx,
		const uint8_t *server_certificate_update,
		const uint32_t server_certificate_update_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_server_certificate_update, GET_PRIV_CTX(ctx), server_certificate_update, server_certificate_update_len)
}
TO_ret_t TOSE_tls_handle_server_certificate_final(TOSE_ctx_t *ctx) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_server_certificate_final, GET_PRIV_CTX(ctx))
}
TO_ret_t TOSE_tls_handle_server_key_exchange(
		TOSE_ctx_t *ctx,
		const uint8_t *server_key_exchange,
		const uint32_t server_key_exchange_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_server_key_exchange, GET_PRIV_CTX(ctx), server_key_exchange, server_key_exchange_len)
}
TO_ret_t TOSE_tls_handle_server_key_exchange_init(
		TOSE_ctx_t *ctx,
		const uint8_t *server_key_exchange_init,
		const uint32_t server_key_exchange_init_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_server_key_exchange_init, GET_PRIV_CTX(ctx), server_key_exchange_init, server_key_exchange_init_len)
}
TO_ret_t TOSE_tls_handle_server_key_exchange_update(
		TOSE_ctx_t *ctx,
		const uint8_t *server_key_exchange_update,
		const uint32_t server_key_exchange_update_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_server_key_exchange_update, GET_PRIV_CTX(ctx), server_key_exchange_update, server_key_exchange_update_len)
}
TO_ret_t TOSE_tls_handle_server_key_exchange_final(TOSE_ctx_t *ctx) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_server_key_exchange_final, GET_PRIV_CTX(ctx))
}
TO_ret_t TOSE_tls_handle_mediator_certificate(
		TOSE_ctx_t *ctx,
		const uint8_t *mediator_certificate,
		const uint32_t mediator_certificate_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_mediator_certificate, GET_PRIV_CTX(ctx), mediator_certificate, mediator_certificate_len)
}
TO_ret_t TOSE_tls_handle_certificate_request(
		TOSE_ctx_t *ctx,
		const uint8_t *certificate_request,
		const uint32_t certificate_request_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_certificate_request, GET_PRIV_CTX(ctx), certificate_request, certificate_request_len)
}
TO_ret_t TOSE_tls_handle_server_hello_done(
		TOSE_ctx_t *ctx,
		const uint8_t *server_hello_done,
		const uint32_t server_hello_done_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_server_hello_done, GET_PRIV_CTX(ctx), server_hello_done, server_hello_done_len)
}
TO_ret_t TOSE_tls_get_certificate(
		TOSE_ctx_t *ctx,
		uint8_t *certificate,
		uint16_t *certificate_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_get_certificate, GET_PRIV_CTX(ctx), certificate, certificate_len)
}
TO_ret_t TOSE_tls_get_certificate_init(
		TOSE_ctx_t *ctx,
		uint8_t *certificate,
		uint16_t *certificate_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_get_certificate_init, GET_PRIV_CTX(ctx), certificate, certificate_len)
}
TO_ret_t TOSE_tls_get_certificate_update(
		TOSE_ctx_t *ctx,
		uint8_t *certificate,
		uint16_t *certificate_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_get_certificate_update, GET_PRIV_CTX(ctx), certificate, certificate_len)
}
TO_ret_t TOSE_tls_get_certificate_final(TOSE_ctx_t *ctx) {
	DRV_CALL_CHECK(ctx, tls, tls_get_certificate_final, GET_PRIV_CTX(ctx))
}
TO_ret_t TOSE_tls_get_client_key_exchange(
		TOSE_ctx_t *ctx,
		uint8_t *client_key_exchange,
		uint16_t *client_key_exchange_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_get_client_key_exchange, GET_PRIV_CTX(ctx), client_key_exchange, client_key_exchange_len)
}
TO_ret_t TOSE_tls_get_certificate_verify(
		TOSE_ctx_t *ctx,
		uint8_t *certificate_verify,
		uint16_t *certificate_verify_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_get_certificate_verify, GET_PRIV_CTX(ctx), certificate_verify, certificate_verify_len)
}
TO_ret_t TOSE_tls_get_change_cipher_spec(
		TOSE_ctx_t *ctx,
		uint8_t *change_cipher_spec,
		uint16_t *change_cipher_spec_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_get_change_cipher_spec, GET_PRIV_CTX(ctx), change_cipher_spec, change_cipher_spec_len)
}
TO_ret_t TOSE_tls_get_finished(
		TOSE_ctx_t *ctx,
		uint8_t *finished,
		uint16_t *finished_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_get_finished, GET_PRIV_CTX(ctx), finished, finished_len)
}
TO_ret_t TOSE_tls_handle_change_cipher_spec(
		TOSE_ctx_t *ctx,
		const uint8_t *change_cipher_spec,
		const uint32_t change_cipher_spec_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_change_cipher_spec, GET_PRIV_CTX(ctx), change_cipher_spec, change_cipher_spec_len)
}
TO_ret_t TOSE_tls_handle_finished(
		TOSE_ctx_t *ctx,
		const uint8_t *finished,
		const uint32_t finished_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_handle_finished, GET_PRIV_CTX(ctx), finished, finished_len)
}
TO_ret_t TOSE_tls_get_certificate_slot(
		TOSE_ctx_t *ctx,
		uint8_t *slot
) {
	DRV_CALL_CHECK(ctx, tls, tls_get_certificate_slot, GET_PRIV_CTX(ctx), slot)
}
TO_ret_t TOSE_tls_secure_payload(
		TOSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t *payload,
		uint16_t *payload_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_secure_payload, GET_PRIV_CTX(ctx), header, header_len, data, data_len, payload, payload_len)
}
TO_ret_t TOSE_tls_secure_payload_init_cbc(
		TOSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE]
) {
	DRV_CALL_CHECK(ctx, tls, tls_secure_payload_init_cbc, GET_PRIV_CTX(ctx), header, header_len, initial_vector)
}
TO_ret_t TOSE_tls_secure_payload_init_aead(
		TOSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		uint8_t initial_vector[TO_TLS_AEAD_EXPLICIT_NONCE_SIZE]
) {
	DRV_CALL_CHECK(ctx, tls, tls_secure_payload_init_aead, GET_PRIV_CTX(ctx), header, header_len, initial_vector)
}
TO_ret_t TOSE_tls_secure_payload_update(
		TOSE_ctx_t *ctx,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t *cryptogram
) {
	DRV_CALL_CHECK(ctx, tls, tls_secure_payload_update, GET_PRIV_CTX(ctx), data, data_len, cryptogram)
}
TO_ret_t TOSE_tls_secure_payload_final(
		TOSE_ctx_t *ctx,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t *cryptogram,
		uint16_t* cryptogram_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_secure_payload_final, GET_PRIV_CTX(ctx), data, data_len, cryptogram, cryptogram_len)
}
TO_ret_t TOSE_tls_unsecure_payload(
		TOSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t* payload,
		const uint16_t payload_len,
		uint8_t *data,
		uint16_t *data_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_unsecure_payload, GET_PRIV_CTX(ctx), header, header_len, payload, payload_len, data, data_len)
}
TO_ret_t TOSE_tls_unsecure_payload_init_cbc(
		TOSE_ctx_t *ctx,
		const uint16_t cryptogram_len,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE]
) {
	DRV_CALL_CHECK(ctx, tls, tls_unsecure_payload_init_cbc, GET_PRIV_CTX(ctx), cryptogram_len, header, header_len, initial_vector, last_block_iv, last_block)
}
TO_ret_t TOSE_tls_unsecure_payload_init_aead(
		TOSE_ctx_t *ctx,
		const uint16_t cryptogram_len,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t initial_vector[TO_TLS_AEAD_EXPLICIT_NONCE_SIZE]
) {
	DRV_CALL_CHECK(ctx, tls, tls_unsecure_payload_init_aead, GET_PRIV_CTX(ctx), cryptogram_len, header, header_len, initial_vector)
}
TO_ret_t TOSE_tls_unsecure_payload_update(
		TOSE_ctx_t *ctx,
		const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t *data,
		uint16_t *data_len
) {
	DRV_CALL_CHECK(ctx, tls, tls_unsecure_payload_update, GET_PRIV_CTX(ctx), cryptogram, cryptogram_len, data, data_len)
}
TO_ret_t TOSE_tls_unsecure_payload_final(TOSE_ctx_t *ctx) {
	DRV_CALL_CHECK(ctx, tls, tls_unsecure_payload_final, GET_PRIV_CTX(ctx))
}
TO_ret_t TOSE_lora_compute_mic(
		TOSE_ctx_t *ctx,
		const uint8_t *data,
		uint16_t data_length,
		uint32_t address,
		uint8_t direction,
		uint32_t seq_counter,
		uint8_t mic[TO_LORA_MIC_SIZE]
) {
	DRV_CALL_CHECK(ctx, lora, lora_compute_mic, GET_PRIV_CTX(ctx), data, data_length, address, direction, seq_counter, mic)
}
TO_ret_t TOSE_lora_encrypt_payload(
		TOSE_ctx_t *ctx,
		const uint8_t *data,
		uint16_t data_length,
		const uint8_t *fport,
		uint32_t address,
		uint8_t direction,
		uint32_t seq_counter,
		uint8_t *enc_buffer
) {
	DRV_CALL_CHECK(ctx, lora, lora_encrypt_payload, GET_PRIV_CTX(ctx), data, data_length, fport, address, direction, seq_counter, enc_buffer)
}
TO_ret_t TOSE_lora_join_compute_mic(
		TOSE_ctx_t *ctx,
		const uint8_t *data,
		uint16_t data_length,
		uint8_t mic[TO_LORA_MIC_SIZE]
) {
	DRV_CALL_CHECK(ctx, lora, lora_join_compute_mic, GET_PRIV_CTX(ctx), data, data_length, mic)
}
TO_ret_t TOSE_lora_decrypt_join(
		TOSE_ctx_t *ctx,
		const uint8_t *data,
		uint16_t data_length,
		uint8_t *dec_buffer
) {
	DRV_CALL_CHECK(ctx, lora, lora_decrypt_join, GET_PRIV_CTX(ctx), data, data_length, dec_buffer)
}
TO_ret_t TOSE_lora_compute_shared_keys(
		TOSE_ctx_t *ctx,
		const uint8_t *app_nonce,
		const uint8_t *net_id,
		uint16_t dev_nonce
) {
	DRV_CALL_CHECK(ctx, lora, lora_compute_shared_keys, GET_PRIV_CTX(ctx), app_nonce, net_id, dev_nonce)
}
TO_ret_t TOSE_lora_get_app_eui(
		TOSE_ctx_t *ctx,
		uint8_t app_eui[TO_LORA_APPEUI_SIZE]
) {
	DRV_CALL_CHECK(ctx, lora, lora_get_app_eui, GET_PRIV_CTX(ctx), app_eui)
}
TO_ret_t TOSE_lora_get_dev_eui(
		TOSE_ctx_t *ctx,
		uint8_t dev_eui[TO_LORA_DEVEUI_SIZE]
) {
	DRV_CALL_CHECK(ctx, lora, lora_get_dev_eui, GET_PRIV_CTX(ctx), dev_eui)
}
TO_ret_t TOSE_lora_get_dev_addr(
		TOSE_ctx_t *ctx,
		uint8_t dev_addr[TO_LORA_DEVADDR_SIZE]
) {
	DRV_CALL_CHECK(ctx, lora, lora_get_dev_addr, GET_PRIV_CTX(ctx), dev_addr)
}
TO_ret_t TOSE_lora_get_join_request_phypayload(
		TOSE_ctx_t *ctx,
		uint8_t data[TO_LORA_JOINREQUEST_SIZE]
) {
	DRV_CALL_CHECK(ctx, lora, lora_get_join_request_phypayload, GET_PRIV_CTX(ctx), data)
}
TO_ret_t TOSE_lora_handle_join_accept_phypayload(
		TOSE_ctx_t *ctx,
		const uint8_t *data,
		const uint16_t data_length,
		uint8_t dec_buffer[TO_LORA_JOINACCEPT_CLEAR_MAXSIZE]
) {
	DRV_CALL_CHECK(ctx, lora, lora_handle_join_accept_phypayload, GET_PRIV_CTX(ctx), data, data_length, dec_buffer)
}
TO_ret_t TOSE_lora_secure_phypayload(
		TOSE_ctx_t *ctx,
		const uint8_t mhdr,
		const uint8_t fctrl,
		const uint8_t *fopts,
		const uint8_t fport,
		const uint8_t *payload,
		const int payload_size,
		uint8_t *enc_buffer
) {
	DRV_CALL_CHECK(ctx, lora, lora_secure_phypayload, GET_PRIV_CTX(ctx), mhdr, fctrl, fopts, fport, payload, payload_size, enc_buffer)
}
TO_ret_t TOSE_lora_unsecure_phypayload(
		TOSE_ctx_t *ctx,
		const uint8_t *data,
		const uint16_t data_length,
		uint8_t *dec_buffer
) {
	DRV_CALL_CHECK(ctx, lora, lora_unsecure_phypayload, GET_PRIV_CTX(ctx), data, data_length, dec_buffer)
}
TO_ret_t TOSE_admin_session_init(
		TOSE_ctx_t *ctx,
		const uint8_t server_challenge[TO_ADMIN_CHALLENGE_SIZE],
		uint8_t se_challenge[TO_ADMIN_CHALLENGE_SIZE],
		uint8_t se_cryptogram[TO_ADMIN_CRYPTOGRAM_SIZE],
		uint8_t diversification_data[TO_ADMIN_DIVERS_DATA_SIZE],
		uint8_t protocol_info[TO_ADMIN_PROTO_INFO_SIZE]
) {
	DRV_CALL_CHECK(ctx, admin, admin_session_init, GET_PRIV_CTX(ctx), server_challenge, se_challenge, se_cryptogram, diversification_data, protocol_info)
}
TO_ret_t TOSE_admin_session_auth_server(
		TOSE_ctx_t *ctx,
		const uint8_t options[TO_ADMIN_OPTIONS_SIZE],
		const uint8_t server_cryptogram[TO_ADMIN_CRYPTOGRAM_SIZE],
		const uint8_t mac[TO_ADMIN_MAC_SIZE]
) {
	DRV_CALL_CHECK(ctx, admin, admin_session_auth_server, GET_PRIV_CTX(ctx), options, server_cryptogram, mac)
}
TO_ret_t TOSE_admin_command(
		TOSE_ctx_t *ctx,
		const uint8_t *command,
		uint16_t length
) {
	DRV_CALL_CHECK(ctx, admin, admin_command, GET_PRIV_CTX(ctx), command, length)
}
TO_ret_t TOSE_admin_command_with_response(
		TOSE_ctx_t *ctx,
		const uint8_t *command,
		uint16_t length,
		uint8_t *response,
		uint16_t response_length
) {
	DRV_CALL_CHECK(ctx, admin, admin_command_with_response, GET_PRIV_CTX(ctx), command, length, response, response_length)
}
TO_ret_t TOSE_admin_command_with_response2(
		TOSE_ctx_t *ctx,
		const uint8_t *command,
		uint16_t length,
		uint8_t *response,
		uint16_t *response_length
) {
	DRV_CALL_CHECK(ctx, admin, admin_command_with_response2, GET_PRIV_CTX(ctx), command, length, response, response_length)
}
TO_ret_t TOSE_admin_session_fini(
		TOSE_ctx_t *ctx,
		uint8_t mac[TO_ADMIN_MAC_SIZE]
) {
	DRV_CALL_CHECK(ctx, admin, admin_session_fini, GET_PRIV_CTX(ctx), mac)
}
TO_ret_t TOSE_admin_set_slot(
		TOSE_ctx_t *ctx,
		const uint8_t index
) {
	DRV_CALL_CHECK(ctx, admin, admin_set_slot, GET_PRIV_CTX(ctx), index)
}
TO_ret_t TOSE_set_status_PIO_config(
		TOSE_ctx_t *ctx,
		int enable,
		int opendrain,
		int ready_level,
		int idle_hz
) {
	DRV_CALL_CHECK(ctx, status_pio, set_status_PIO_config, GET_PRIV_CTX(ctx), enable, opendrain, ready_level, idle_hz)
}
TO_ret_t TOSE_get_status_PIO_config(
		TOSE_ctx_t *ctx,
		int *enable,
		int *opendrain,
		int *ready_level,
		int *idle_hz
) {
	DRV_CALL_CHECK(ctx, status_pio, get_status_PIO_config, GET_PRIV_CTX(ctx), enable, opendrain, ready_level, idle_hz)
}
TO_ret_t TOSE_get_random(
		TOSE_ctx_t *ctx,
		const uint16_t random_length,
		uint8_t* random
) {
	DRV_CALL_CHECK(ctx, random, get_random, GET_PRIV_CTX(ctx), random_length, random)
}
TO_ret_t TOSE_loader_broadcast_get_info(
		TOSE_ctx_t *ctx,
		uint8_t loader_version[TO_SW_VERSION_SIZE],
		uint8_t software_version[TO_SW_VERSION_SIZE],
		uint8_t upgrade_version[TO_SW_VERSION_SIZE])
{
	DRV_CALL_CHECK(ctx, loader, loader_broadcast_get_info, GET_PRIV_CTX(ctx), loader_version, software_version, upgrade_version);
}

TO_ret_t TOSE_loader_broadcast_restore_loader(
		TOSE_ctx_t *ctx,
		const uint8_t upgrade_version[TO_SW_VERSION_SIZE],
		const uint8_t minimum_version[TO_SW_VERSION_SIZE],
		const uint8_t cmac[TO_CMAC_SIZE],
		const uint8_t password[TO_LD_BCAST_RESTORE_PASSWORD_SIZE])
{
	DRV_CALL_CHECK(ctx, loader, loader_broadcast_restore_loader, GET_PRIV_CTX(ctx), upgrade_version, minimum_version, cmac, password);
}

TO_ret_t TOSE_loader_broadcast_send_init_data(
		TOSE_ctx_t *ctx,
		const uint8_t init_data[TO_LD_BCAST_INIT_DATA_SIZE],
		const uint8_t cmac[TO_CMAC_SIZE])
{
	DRV_CALL_CHECK(ctx, loader, loader_broadcast_send_init_data, GET_PRIV_CTX(ctx), init_data, cmac);
}

TO_ret_t TOSE_loader_broadcast_write_data(
		TOSE_ctx_t *ctx,
		const uint8_t *segment,
		uint16_t length)
{
	DRV_CALL_CHECK(ctx, loader, loader_broadcast_write_data, GET_PRIV_CTX(ctx), segment, length);
}

TO_ret_t TOSE_loader_broadcast_commit_release(
		TOSE_ctx_t *ctx,
		const uint8_t cmac[TO_CMAC_SIZE])
{
	DRV_CALL_CHECK(ctx, loader, loader_broadcast_commit_release, GET_PRIV_CTX(ctx), cmac);
}

TO_ret_t TOSE_data_migration(TOSE_ctx_t *ctx)
{
	DRV_CALL_CHECK(ctx, loader, data_migration, GET_PRIV_CTX(ctx));
}

TO_ret_t TOSE_measured_boot(TOSE_ctx_t *ctx,
		const uint8_t *hash,
		uint16_t hash_length)
{
	DRV_CALL_CHECK(ctx, measure, measured_boot, GET_PRIV_CTX(ctx), hash, hash_length);
}

TO_ret_t TOSE_validate_new_fw_hash(TOSE_ctx_t *ctx,
		const uint8_t* hash,
		uint16_t hash_length)
{
	DRV_CALL_CHECK(ctx, measure, validate_new_fw_hash, GET_PRIV_CTX(ctx), hash, hash_length);
}

TO_ret_t TOSE_commit_new_fw_hash(TOSE_ctx_t *ctx,
		const uint8_t signed_challenge[TO_HMAC_SIZE])
{
	DRV_CALL_CHECK(ctx, measure, commit_new_fw_hash, GET_PRIV_CTX(ctx), signed_challenge);
}

TO_ret_t TOSE_store_new_trusted_fw_hash(TOSE_ctx_t *ctx,
		const uint8_t* fw_hash,
		const uint16_t fw_hash_length,
		const uint8_t  mac[TO_HMAC_SIZE])
{
	DRV_CALL_CHECK(ctx, measure, store_new_trusted_fw_hash, GET_PRIV_CTX(ctx),
			fw_hash,
			fw_hash_length,
			mac);
}

TO_ret_t TOSE_get_boot_measurement(TOSE_ctx_t *ctx,
		uint8_t* fw_hash,
		uint16_t fw_hash_length,
		const uint8_t* challenge,
		uint16_t challenge_length,
		measure_outcome_t* outcome,
		uint8_t  mac[TO_HMAC_SIZE])
{
	DRV_CALL_CHECK(ctx, measure, get_boot_measurement, GET_PRIV_CTX(ctx),
			fw_hash,
			fw_hash_length,
			challenge,
			challenge_length,
			outcome,
			mac);
}

TO_ret_t TOSE_get_se_measurement(TOSE_ctx_t *ctx,
		uint8_t* hash,
		uint16_t hash_length,
		const uint8_t* challenge,
		uint16_t challenge_length,
		measure_outcome_t* outcome,
		uint8_t  mac[TO_HMAC_SIZE])
{
	DRV_CALL_CHECK(ctx, measure, get_se_measurement, GET_PRIV_CTX(ctx),
			hash,
			hash_length,
			challenge,
			challenge_length,
			outcome,
			mac);
}

TO_ret_t TOSE_invalidate_new_hash(TOSE_ctx_t *ctx,
		const uint8_t password_challenge_hash[TO_SHA256_HASHSIZE])
{
	DRV_CALL_CHECK(ctx, measure, invalidate_new_hash, GET_PRIV_CTX(ctx),
			password_challenge_hash);
}


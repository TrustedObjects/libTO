/*
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (C) 2019-2021 Trusted Objects. All rights reserved.
 */

#include "TO_cfg.h"
#ifndef TODRV_HSE_DRIVER_DISABLE

#include "TO_driver.h"
#include "TO_defs.h"

#include "TODRV_HSE.h"
#include "TODRV_HSE_cfg.h"
#include "TODRV_HSE_admin.h"
#include "TODRV_HSE_auth.h"
#include "TODRV_HSE_core.h"
#include "TODRV_HSE_encrypt.h"
#include "TODRV_HSE_hash.h"
#include "TODRV_HSE_keys.h"
#include "TODRV_HSE_lora.h"
#include "TODRV_HSE_mac.h"
#include "TODRV_HSE_nvm.h"
#include "TODRV_HSE_system.h"
#include "TODRV_HSE_tls.h"
#include "TODRV_HSE_loader.h"
#include "TODRV_HSE_measure.h"
#ifdef TODRV_HSE_INTERFACE_TO_SSE
#include "TODRV_HSE_auth_toprotect.h"
#endif
#include "TO_log.h"

static TODRV_HSE_ctx_t hse_ctx_priv;

const TODRV_api_t drv_hse = {
	.api_version = TODRV_API_VERSION,
	.ctx_size = sizeof(TODRV_HSE_ctx_t),
	.offsets = TODRV_API_OFFSETS,
	.api = {
		.common = {
			.init = (TODRV_init_f*)TODRV_HSE_init,
			.fini = (TODRV_fini_f*)TODRV_HSE_fini,
		},
#if TODRV_API_CONFIG_TO_INFO > 0
		.to_info = {
			.get_serial_number = (TODRV_get_serial_number_f*)TODRV_HSE_get_serial_number,
			.get_hardware_serial_number = (TODRV_get_hardware_serial_number_f*)TODRV_HSE_get_hardware_serial_number,
			.get_product_number = (TODRV_get_product_number_f*)TODRV_HSE_get_product_number,
			.get_hardware_version = (TODRV_get_hardware_version_f*)TODRV_HSE_get_hardware_version,
			.get_software_version = (TODRV_get_software_version_f*)TODRV_HSE_get_software_version,
			.get_product_id = (TODRV_get_product_id_f*)TODRV_HSE_get_product_id,
			.access_dummy_data = (TODRV_access_dummy_data_f*)TODRV_HSE_access_dummy_data,
		},
#endif
#if TODRV_API_CONFIG_SHA256 > 0
		.sha256 = {
			.sha256 = (TODRV_sha256_f*)TODRV_HSE_sha256,
			.sha256_init = (TODRV_sha256_init_f*)TODRV_HSE_sha256_init,
			.sha256_update = (TODRV_sha256_update_f*)TODRV_HSE_sha256_update,
			.sha256_final = (TODRV_sha256_final_f*)TODRV_HSE_sha256_final,
		},
#endif
#if TODRV_API_CONFIG_KEYS_MGMT > 0
		.keys_mgmt = {
			.set_remote_public_key = (TODRV_set_remote_public_key_f*)TODRV_HSE_set_remote_public_key,
			.renew_ecc_keys = (TODRV_renew_ecc_keys_f*)TODRV_HSE_renew_ecc_keys,
			.get_public_key = (TODRV_get_public_key_f*)TODRV_HSE_get_public_key,
			.get_unsigned_public_key = (TODRV_get_unsigned_public_key_f*)TODRV_HSE_get_unsigned_public_key,
			.renew_shared_keys = (TODRV_renew_shared_keys_f*)TODRV_HSE_renew_shared_keys,
#if !defined(TO_DISABLE_FINGERPRINT)
			.get_key_fingerprint = (TODRV_get_key_fingerprint_f*)TODRV_HSE_get_key_fingerprint,
#endif
		},
#endif
#if TODRV_API_CONFIG_AES_ENCRYPT > 0
		.aes_encrypt = {
			.aes128cbc_encrypt = (TODRV_aes128cbc_encrypt_f*)TODRV_HSE_aes128cbc_encrypt,
			.aes128cbc_iv_encrypt = (TODRV_aes128cbc_iv_encrypt_f*)TODRV_HSE_aes128cbc_iv_encrypt,
			.aes128cbc_decrypt = (TODRV_aes128cbc_decrypt_f*)TODRV_HSE_aes128cbc_decrypt,
			.aes128gcm_encrypt = (TODRV_aes128gcm_encrypt_f*)TODRV_HSE_aes128gcm_encrypt,
			.aes128gcm_decrypt = (TODRV_aes128gcm_decrypt_f*)TODRV_HSE_aes128gcm_decrypt,
			.aes128ccm_encrypt = (TODRV_aes128ccm_encrypt_f*)TODRV_HSE_aes128ccm_encrypt,
			.aes128ccm_decrypt = (TODRV_aes128ccm_decrypt_f*)TODRV_HSE_aes128ccm_decrypt,
			.aes128ecb_encrypt = (TODRV_aes128ecb_encrypt_f*)TODRV_HSE_aes128ecb_encrypt,
			.aes128ecb_decrypt = (TODRV_aes128ecb_decrypt_f*)TODRV_HSE_aes128ecb_decrypt,
		},
#endif
#if TODRV_API_CONFIG_HMAC > 0
		.hmac = {
			.compute_hmac = (TODRV_compute_hmac_f*)TODRV_HSE_compute_hmac,
			.compute_hmac_init = (TODRV_compute_hmac_init_f*)TODRV_HSE_compute_hmac_init,
			.compute_hmac_update = (TODRV_compute_hmac_update_f*)TODRV_HSE_compute_hmac_update,
			.compute_hmac_final = (TODRV_compute_hmac_final_f*)TODRV_HSE_compute_hmac_final,
			.verify_hmac = (TODRV_verify_hmac_f*)TODRV_HSE_verify_hmac,
			.verify_hmac_init = (TODRV_verify_hmac_init_f*)TODRV_HSE_verify_hmac_init,
			.verify_hmac_update = (TODRV_verify_hmac_update_f*)TODRV_HSE_verify_hmac_update,
			.verify_hmac_final = (TODRV_verify_hmac_final_f*)TODRV_HSE_verify_hmac_final,
		},
#endif
#if TODRV_API_CONFIG_CMAC > 0
		.cmac = {
			.compute_cmac = (TODRV_compute_cmac_f*)TODRV_HSE_compute_cmac,
			.verify_cmac = (TODRV_verify_cmac_f*)TODRV_HSE_verify_cmac,
		},
#endif
#if TODRV_API_CONFIG_SEC_MSG > 0
		.sec_msg = {
			.aes128cbc_hmac_secure_message = (TODRV_aes128cbc_hmac_secure_message_f*)TODRV_HSE_aes128cbc_hmac_secure_message,
			.aes128cbc_hmac_unsecure_message = (TODRV_aes128cbc_hmac_unsecure_message_f*)TODRV_HSE_aes128cbc_hmac_unsecure_message,
			.aes128cbc_cmac_secure_message = (TODRV_aes128cbc_cmac_secure_message_f*)TODRV_HSE_aes128cbc_cmac_secure_message,
			.aes128cbc_cmac_unsecure_message = (TODRV_aes128cbc_cmac_unsecure_message_f*)TODRV_HSE_aes128cbc_cmac_unsecure_message,
			.secure_payload = (TODRV_secure_payload_f*)TODRV_HSE_secure_payload,
#if !defined(TO_DISABLE_API_SECURE_PAYLOAD_INIT_UPDATE_FINAL)
			.secure_payload_init = (TODRV_secure_payload_init_f*)TODRV_HSE_secure_payload_init,
			.secure_payload_update = (TODRV_secure_payload_update_f*)TODRV_HSE_secure_payload_update,
			.secure_payload_final = (TODRV_secure_payload_final_f*)TODRV_HSE_secure_payload_final,
#endif
			.unsecure_payload = (TODRV_unsecure_payload_f*)TODRV_HSE_unsecure_payload,
#if !defined(TO_DISABLE_API_UNSECURE_PAYLOAD_INIT_UPDATE_FINAL)
			.unsecure_payload_init_cbc = (TODRV_unsecure_payload_init_cbc_f*)TODRV_HSE_unsecure_payload_init_cbc,
			.unsecure_payload_init_aead = (TODRV_unsecure_payload_init_aead_f*)TODRV_HSE_unsecure_payload_init_aead,
			.unsecure_payload_update = (TODRV_unsecure_payload_update_f*)TODRV_HSE_unsecure_payload_update,
			.unsecure_payload_final = (TODRV_unsecure_payload_final_f*)TODRV_HSE_unsecure_payload_final,
#endif
		},
#endif
#if TODRV_API_CONFIG_SIGNING > 0
		.signing = {
			.sign = (TODRV_sign_f*)TODRV_HSE_sign,
			.verify = (TODRV_verify_f*)TODRV_HSE_verify,
			.sign_hash = (TODRV_sign_hash_f*)TODRV_HSE_sign_hash,
			.verify_hash_signature = (TODRV_verify_hash_signature_f*)TODRV_HSE_verify_hash_signature,
		},
#endif
#if TODRV_API_CONFIG_CERT_MGMT > 0
		.cert_mgmt = {
			.set_certificate_signing_request_dn = (TODRV_set_certificate_signing_request_dn_f*)TODRV_HSE_set_certificate_signing_request_dn,
			.get_certificate_subject_cn = (TODRV_get_certificate_subject_cn_f*)TODRV_HSE_get_certificate_subject_cn,
			.get_certificate_signing_request = (TODRV_get_certificate_signing_request_f*)TODRV_HSE_get_certificate_signing_request,
			.get_certificate = (TODRV_get_certificate_f*)TODRV_HSE_get_certificate,
			.get_certificate_x509 = (TODRV_get_certificate_x509_f*)TODRV_HSE_get_certificate_x509,
			.set_certificate_x509 = (TODRV_set_certificate_x509_f*)TODRV_HSE_set_certificate_x509,
#ifndef TO_DISABLE_CAPI
			.set_certificate_x509_init = (TODRV_set_certificate_x509_init_f*)TODRV_HSE_set_certificate_x509_init,
			.set_certificate_x509_update = (TODRV_set_certificate_x509_update_f*)TODRV_HSE_set_certificate_x509_update,
			.set_certificate_x509_final = (TODRV_set_certificate_x509_final_f*)TODRV_HSE_set_certificate_x509_final,
			.get_certificate_x509_init = (TODRV_get_certificate_x509_init_f*)TODRV_HSE_get_certificate_x509_init,
			.get_certificate_x509_update = (TODRV_get_certificate_x509_update_f*)TODRV_HSE_get_certificate_x509_update,
			.get_certificate_x509_final = (TODRV_get_certificate_x509_final_f*)TODRV_HSE_get_certificate_x509_final,
#endif
			.get_certificate_and_sign = (TODRV_get_certificate_and_sign_f*)TODRV_HSE_get_certificate_and_sign,
			.get_certificate_x509_and_sign = (TODRV_get_certificate_x509_and_sign_f*)TODRV_HSE_get_certificate_x509_and_sign,
			.verify_certificate_and_store = (TODRV_verify_certificate_and_store_f*)TODRV_HSE_verify_certificate_and_store,
			.verify_ca_certificate_and_store = (TODRV_verify_ca_certificate_and_store_f*)TODRV_HSE_verify_ca_certificate_and_store,
			.get_challenge_and_store = (TODRV_get_challenge_and_store_f*)TODRV_HSE_get_challenge_and_store,
			.verify_challenge_signature = (TODRV_verify_challenge_signature_f*)TODRV_HSE_verify_challenge_signature,
#ifndef TO_DISABLE_API_VERIFY_CHAIN_CERTIFICATE_AND_STORE
			.verify_chain_certificate_and_store_init = (TODRV_verify_chain_certificate_and_store_init_f*)TODRV_HSE_verify_chain_certificate_and_store_init,
			.verify_chain_certificate_and_store_update = (TODRV_verify_chain_certificate_and_store_update_f*)TODRV_HSE_verify_chain_certificate_and_store_update,
			.verify_chain_certificate_and_store_final = (TODRV_verify_chain_certificate_and_store_final_f*)TODRV_HSE_verify_chain_certificate_and_store_final,
#endif
#ifndef TO_DISABLE_API_VERIFY_CHAIN_CA_CERTIFICATE_AND_STORE
			.verify_chain_ca_certificate_and_store_init = (TODRV_verify_chain_ca_certificate_and_store_init_f*)TODRV_HSE_verify_chain_ca_certificate_and_store_init,
			.verify_chain_ca_certificate_and_store_update = (TODRV_verify_chain_ca_certificate_and_store_update_f*)TODRV_HSE_verify_chain_ca_certificate_and_store_update,
			.verify_chain_ca_certificate_and_store_final = (TODRV_verify_chain_ca_certificate_and_store_final_f*)TODRV_HSE_verify_chain_ca_certificate_and_store_final,
#endif
		},
#endif
#if TODRV_API_CONFIG_NVM > 0
		.nvm = {
			.write_nvm = (TODRV_write_nvm_f*)TODRV_HSE_write_nvm,
			.read_nvm = (TODRV_read_nvm_f*)TODRV_HSE_read_nvm,
			.get_nvm_size = (TODRV_get_nvm_size_f*)TODRV_HSE_get_nvm_size,
		},
#endif
#if TODRV_API_CONFIG_TLS > 0
		.tls = {
#if !defined(TO_DISABLE_TLS)
			.set_tls_server_random = (TODRV_set_tls_server_random_f*)TODRV_HSE_set_tls_server_random,
			.set_tls_server_eph_pub_key = (TODRV_set_tls_server_eph_pub_key_f*)TODRV_HSE_set_tls_server_eph_pub_key,
			.get_tls_random_and_store = (TODRV_get_tls_random_and_store_f*)TODRV_HSE_get_tls_random_and_store,
			.get_tls_master_secret = (TODRV_get_tls_master_secret_f*)TODRV_HSE_get_tls_master_secret,
			.renew_tls_keys_ecdhe = (TODRV_renew_tls_keys_ecdhe_f*)TODRV_HSE_renew_tls_keys_ecdhe,
			.tls_calculate_finished = (TODRV_tls_calculate_finished_f*)TODRV_HSE_tls_calculate_finished,
#endif
#if !defined(TO_DISABLE_TLS_OPTIMIZED)
			.tls_reset = (TODRV_tls_reset_f*)TODRV_HSE_tls_reset,
			.tls_set_mode = (TODRV_tls_set_mode_f*)TODRV_HSE_tls_set_mode,
			.tls_set_config = (TODRV_tls_set_config_f*)TODRV_HSE_tls_set_config,
			.tls_set_session = (TODRV_tls_set_session_f*)TODRV_HSE_tls_set_session,
			.tls_set_cid_ext_id = (TODRV_tls_set_cid_ext_id_f*)TODRV_HSE_tls_set_cid_ext_id,
			.tls_get_client_hello = (TODRV_tls_get_client_hello_f*)TODRV_HSE_tls_get_client_hello,
			.tls_get_client_hello_ext = (TODRV_tls_get_client_hello_ext_f*)TODRV_HSE_tls_get_client_hello_ext,
			.tls_get_client_hello_init = (TODRV_tls_get_client_hello_init_f*)TODRV_HSE_tls_get_client_hello_init,
			.tls_get_client_hello_update = (TODRV_tls_get_client_hello_update_f*)TODRV_HSE_tls_get_client_hello_update,
			.tls_get_client_hello_final = (TODRV_tls_get_client_hello_final_f*)TODRV_HSE_tls_get_client_hello_final,
			.tls_handle_hello_verify_request = (TODRV_tls_handle_hello_verify_request_f*)TODRV_HSE_tls_handle_hello_verify_request,
			.tls_handle_server_hello = (TODRV_tls_handle_server_hello_f*)TODRV_HSE_tls_handle_server_hello,
			.tls_handle_server_hello_init = (TODRV_tls_handle_server_hello_init_f*)TODRV_HSE_tls_handle_server_hello_init,
			.tls_handle_server_hello_update = (TODRV_tls_handle_server_hello_update_f*)TODRV_HSE_tls_handle_server_hello_update,
			.tls_handle_server_hello_final = (TODRV_tls_handle_server_hello_final_f*)TODRV_HSE_tls_handle_server_hello_final,
			.tls_handle_server_certificate = (TODRV_tls_handle_server_certificate_f*)TODRV_HSE_tls_handle_server_certificate,
			.tls_handle_server_certificate_init = (TODRV_tls_handle_server_certificate_init_f*)TODRV_HSE_tls_handle_server_certificate_init,
			.tls_handle_server_certificate_update = (TODRV_tls_handle_server_certificate_update_f*)TODRV_HSE_tls_handle_server_certificate_update,
			.tls_handle_server_certificate_final = (TODRV_tls_handle_server_certificate_final_f*)TODRV_HSE_tls_handle_server_certificate_final,
			.tls_handle_server_key_exchange = (TODRV_tls_handle_server_key_exchange_f*)TODRV_HSE_tls_handle_server_key_exchange,
			.tls_handle_server_key_exchange_init = (TODRV_tls_handle_server_key_exchange_init_f*)TODRV_HSE_tls_handle_server_key_exchange_init,
			.tls_handle_server_key_exchange_update = (TODRV_tls_handle_server_key_exchange_update_f*)TODRV_HSE_tls_handle_server_key_exchange_update,
			.tls_handle_server_key_exchange_final = (TODRV_tls_handle_server_key_exchange_final_f*)TODRV_HSE_tls_handle_server_key_exchange_final,
			.tls_handle_certificate_request = (TODRV_tls_handle_certificate_request_f*)TODRV_HSE_tls_handle_certificate_request,
			.tls_handle_server_hello_done = (TODRV_tls_handle_server_hello_done_f*)TODRV_HSE_tls_handle_server_hello_done,
			.tls_handle_mediator_certificate = (TODRV_tls_handle_mediator_certificate_f*)TODRV_HSE_tls_handle_mediator_certificate,
			.tls_get_certificate = (TODRV_tls_get_certificate_f*)TODRV_HSE_tls_get_certificate,
			.tls_get_certificate_init = (TODRV_tls_get_certificate_init_f*)TODRV_HSE_tls_get_certificate_init,
			.tls_get_certificate_update = (TODRV_tls_get_certificate_update_f*)TODRV_HSE_tls_get_certificate_update,
			.tls_get_certificate_final = (TODRV_tls_get_certificate_final_f*)TODRV_HSE_tls_get_certificate_final,
			.tls_get_client_key_exchange = (TODRV_tls_get_client_key_exchange_f*)TODRV_HSE_tls_get_client_key_exchange,
			.tls_get_certificate_verify = (TODRV_tls_get_certificate_verify_f*)TODRV_HSE_tls_get_certificate_verify,
			.tls_get_change_cipher_spec = (TODRV_tls_get_change_cipher_spec_f*)TODRV_HSE_tls_get_change_cipher_spec,
			.tls_get_finished = (TODRV_tls_get_finished_f*)TODRV_HSE_tls_get_finished,
			.tls_handle_change_cipher_spec = (TODRV_tls_handle_change_cipher_spec_f*)TODRV_HSE_tls_handle_change_cipher_spec,
			.tls_handle_finished = (TODRV_tls_handle_finished_f*)TODRV_HSE_tls_handle_finished,
			.tls_get_certificate_slot = (TODRV_tls_get_certificate_slot_f*)TODRV_HSE_tls_get_certificate_slot,
			.tls_secure_payload = (TODRV_tls_secure_payload_f*)TODRV_HSE_tls_secure_payload,
			.tls_secure_payload_init_cbc = (TODRV_tls_secure_payload_init_cbc_f*)TODRV_HSE_tls_secure_payload_init_cbc,
			.tls_secure_payload_init_aead = (TODRV_tls_secure_payload_init_aead_f*)TODRV_HSE_tls_secure_payload_init_aead,
			.tls_secure_payload_update = (TODRV_tls_secure_payload_update_f*)TODRV_HSE_tls_secure_payload_update,
			.tls_secure_payload_final = (TODRV_tls_secure_payload_final_f*)TODRV_HSE_tls_secure_payload_final,
			.tls_unsecure_payload = (TODRV_tls_unsecure_payload_f*)TODRV_HSE_tls_unsecure_payload,
			.tls_unsecure_payload_init_cbc = (TODRV_tls_unsecure_payload_init_cbc_f*)TODRV_HSE_tls_unsecure_payload_init_cbc,
			.tls_unsecure_payload_init_aead = (TODRV_tls_unsecure_payload_init_aead_f*)TODRV_HSE_tls_unsecure_payload_init_aead,
			.tls_unsecure_payload_update = (TODRV_tls_unsecure_payload_update_f*)TODRV_HSE_tls_unsecure_payload_update,
			.tls_unsecure_payload_final = (TODRV_tls_unsecure_payload_final_f*)TODRV_HSE_tls_unsecure_payload_final,
			.get_tls_master_secret_derived_keys =
				(TODRV_get_tls_master_secret_derived_keys_f*)TODRV_HSE_get_tls_master_secret_derived_keys,
#endif
		},
#endif
#if TODRV_API_CONFIG_LORA > 0
		.lora = {
#if !defined(TO_DISABLE_LORA) || !defined(TO_DISABLE_LORA_OPTIMIZED)
			.lora_get_app_eui = (TODRV_lora_get_app_eui_f*)TODRV_HSE_lora_get_app_eui,
			.lora_get_dev_eui = (TODRV_lora_get_dev_eui_f*)TODRV_HSE_lora_get_dev_eui,
			.lora_get_dev_addr = (TODRV_lora_get_dev_addr_f*)TODRV_HSE_lora_get_dev_addr,
#endif
#if !defined(TO_DISABLE_LORA)
			.lora_compute_mic = (TODRV_lora_compute_mic_f*)TODRV_HSE_lora_compute_mic,
			.lora_encrypt_payload = (TODRV_lora_encrypt_payload_f*)TODRV_HSE_lora_encrypt_payload,
			.lora_join_compute_mic = (TODRV_lora_join_compute_mic_f*)TODRV_HSE_lora_join_compute_mic,
			.lora_decrypt_join = (TODRV_lora_decrypt_join_f*)TODRV_HSE_lora_decrypt_join,
			.lora_compute_shared_keys = (TODRV_lora_compute_shared_keys_f*)TODRV_HSE_lora_compute_shared_keys,
#endif
#if !defined(TO_DISABLE_LORA_OPTIMIZED)
			.lora_get_join_request_phypayload = (TODRV_lora_get_join_request_phypayload_f*)TODRV_HSE_lora_get_join_request_phypayload,
			.lora_handle_join_accept_phypayload = (TODRV_lora_handle_join_accept_phypayload_f*)TODRV_HSE_lora_handle_join_accept_phypayload,
			.lora_secure_phypayload = (TODRV_lora_secure_phypayload_f*)TODRV_HSE_lora_secure_phypayload,
			.lora_unsecure_phypayload = (TODRV_lora_unsecure_phypayload_f*)TODRV_HSE_lora_unsecure_phypayload,
#endif
		},
#endif
#if TODRV_API_CONFIG_ADMIN > 0
		.admin = {
			.admin_session_init = (TODRV_admin_session_init_f*)TODRV_HSE_admin_session_init,
			.admin_session_auth_server = (TODRV_admin_session_auth_server_f*)TODRV_HSE_admin_session_auth_server,
			.admin_command = (TODRV_admin_command_f*)TODRV_HSE_admin_command,
			.admin_command_with_response = (TODRV_admin_command_with_response_f*)TODRV_HSE_admin_command_with_response,
			.admin_command_with_response2 = (TODRV_admin_command_with_response2_f*)TODRV_HSE_admin_command_with_response2,
			.admin_session_fini = (TODRV_admin_session_fini_f*)TODRV_HSE_admin_session_fini,
			.admin_set_slot = (TODRV_admin_set_slot_f*)TODRV_HSE_admin_set_slot,
		},
#endif
#if TODRV_API_CONFIG_STATUS_PIO > 0
		.status_pio = {
			.set_status_PIO_config = (TODRV_set_status_PIO_config_f*)TODRV_HSE_set_status_PIO_config,
			.get_status_PIO_config = (TODRV_get_status_PIO_config_f*)TODRV_HSE_get_status_PIO_config,
		},
#endif
#if TODRV_API_CONFIG_RANDOM > 0
		.random = {
			.get_random = (TODRV_get_random_f*)TODRV_HSE_get_random,
		},
#endif
#if TODRV_API_CONFIG_LOADER > 0
		.loader = {
			.loader_broadcast_get_info = (TODRV_loader_broadcast_get_info_f*)TODRV_HSE_loader_broadcast_get_info,
			.loader_broadcast_restore_loader = (TODRV_loader_broadcast_restore_loader_f*)TODRV_HSE_loader_broadcast_restore_loader,
			.loader_broadcast_send_init_data = (TODRV_loader_broadcast_send_init_data_f*)TODRV_HSE_loader_broadcast_send_init_data,
			.loader_broadcast_write_data = (TODRV_loader_broadcast_write_data_f*)TODRV_HSE_loader_broadcast_write_data,
			.loader_broadcast_commit_release = (TODRV_loader_broadcast_commit_release_f*)TODRV_HSE_loader_broadcast_commit_release,
			.data_migration = (TODRV_data_migration_f*)TODRV_HSE_data_migration,
		},
#endif
#if TODRV_API_CONFIG_MEASURE > 0
		.measure = {
			.measured_boot = (TODRV_measured_boot_f*)TODRV_HSE_measured_boot,
			.validate_new_fw_hash = (TODRV_validate_new_fw_hash_f*)TODRV_HSE_validate_new_fw_hash,
			.commit_new_fw_hash = (TODRV_commit_new_fw_hash_f*)TODRV_HSE_commit_new_fw_hash,
			.store_new_trusted_fw_hash = (TODRV_store_new_trusted_fw_hash_f*)TODRV_HSE_store_new_trusted_fw_hash,
			.get_boot_measurement = (TODRV_get_boot_measurement_f*)TODRV_HSE_get_boot_measurement,
			.get_se_measurement = (TODRV_get_se_measurement_f*)TODRV_HSE_get_se_measurement,
			.invalidate_new_hash = (TODRV_invalidate_new_hash_f*)TODRV_HSE_invalidate_new_hash
		}
#endif
	},
};

#include <stdio.h>

static TOSE_drv_ctx_t drv_ctx = {
	.api = (TODRV_api_t *)&drv_hse,
	.log_ctx = &log_ctx,
	.priv_ctx = (void *)&hse_ctx_priv,
};

static TOSE_ctx_t drv_hse_ctx = {
	.drv = &drv_ctx,
	.initialized = 0,
};

TODRV_HSE_API TOSE_ctx_t* TODRV_HSE_get_ctx(void)
{
	return &drv_hse_ctx;
}

#endif /* TODRV_HSE_DRIVER_DISABLE */


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
 * @file TO_legacy.h
 * @author Vincent Dupaquis (v.dupaquis@trusted-objects.com)
 * @brief Main source file for the TOSE interface
 * @copyright Copyright (c) Trusted-Objects 2019
 *
 */

#ifndef _TO_LEGACY_H_
#define _TO_LEGACY_H_

#include "TOSE_helper_cfg.h"

#ifdef TO_ENABLE_DTLS
#define __TLS_HEADER_SIZE TO_DTLS_HEADER_SIZE
#define __TLS_HANDSHAKE_HEADER_SIZE TO_DTLS_HANDSHAKE_HEADER_SIZE
#else
#define __TLS_HEADER_SIZE TO_TLS_HEADER_SIZE
#define __TLS_HANDSHAKE_HEADER_SIZE TO_TLS_HANDSHAKE_HEADER_SIZE
#endif

#define TO_TLS_SERVER_HELLO_DONE_SIZE __TLS_HANDSHAKE_HEADER_SIZE
#define TO_TLS_SERVER_CERTIFICATE_INIT_SIZE (__TLS_HANDSHAKE_HEADER_SIZE + 3UL)
#define TO_TLS_FINISHED_PAYLOAD_SIZE (__TLS_HANDSHAKE_HEADER_SIZE + 12UL)

#define TO_init() TOSE_init(DEFAULT_CTX)
#define TO_fini() TOSE_fini(DEFAULT_CTX)
#define TO_get_serial_number(...) TOSE_get_serial_number(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_hardware_serial_number(...) TOSE_get_hardware_serial_number(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_product_number(...) TOSE_get_product_number(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_hardware_version(...) TOSE_get_hardware_version(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_software_version(...) TOSE_get_software_version(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_product_id(...) TOSE_get_product_id(DEFAULT_CTX, __VA_ARGS__)
#define TO_sha256(...) TOSE_sha256(DEFAULT_CTX, __VA_ARGS__)
#define TO_sha256_init(...) TOSE_sha256_init(DEFAULT_CTX)
#define TO_sha256_update(...) TOSE_sha256_update(DEFAULT_CTX, __VA_ARGS__)
#define TO_sha256_final(...) TOSE_sha256_final(DEFAULT_CTX, __VA_ARGS__)
#define TO_set_remote_public_key(...) TOSE_set_remote_public_key(DEFAULT_CTX, __VA_ARGS__)
#define TO_renew_ecc_keys(...) TOSE_renew_ecc_keys(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_public_key(...) TOSE_get_public_key(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_unsigned_public_key(...) TOSE_get_unsigned_public_key(DEFAULT_CTX, __VA_ARGS__)
#define TO_renew_shared_keys(...) TOSE_renew_shared_keys(DEFAULT_CTX, __VA_ARGS__)
#define TO_aes128cbc_encrypt(...) TOSE_aes128cbc_encrypt(DEFAULT_CTX, __VA_ARGS__)
#define TO_aes_encrypt TO_aes128cbc_encrypt
#define TO_aes128cbc_iv_encrypt(...) TOSE_aes128cbc_iv_encrypt(DEFAULT_CTX, __VA_ARGS__)
#define TO_aes_iv_encrypt TO_aes128cbc_iv_encrypt
#define TO_aes128cbc_decrypt(...) TOSE_aes128cbc_decrypt(DEFAULT_CTX, __VA_ARGS__)
#define TO_aes_decrypt TO_aes128cbc_decrypt
#define TO_aes128gcm_encrypt(...) TOSE_aes128gcm_encrypt(DEFAULT_CTX, __VA_ARGS__)
#define TO_aes128gcm_decrypt(...) TOSE_aes128gcm_decrypt(DEFAULT_CTX, __VA_ARGS__)
#define TO_aes128ccm_encrypt(...) TOSE_aes128ccm_encrypt(DEFAULT_CTX, __VA_ARGS__)
#define TO_aes128ccm_decrypt(...) TOSE_aes128ccm_decrypt(DEFAULT_CTX, __VA_ARGS__)
#define TO_aes128ecb_encrypt(...) TOSE_aes128ecb_encrypt(DEFAULT_CTX, __VA_ARGS__)
#define TO_aes128ecb_decrypt(...) TOSE_aes128ecb_decrypt(DEFAULT_CTX, __VA_ARGS__)
#define TO_compute_hmac(...) TOSE_compute_hmac(DEFAULT_CTX, __VA_ARGS__)
#define TO_compute_hmac_init(...) TOSE_compute_hmac_init(DEFAULT_CTX, __VA_ARGS__)
#define TO_compute_hmac_update(...) TOSE_compute_hmac_update(DEFAULT_CTX, __VA_ARGS__)
#define TO_compute_hmac_final(...) TOSE_compute_hmac_final(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify_hmac(...) TOSE_verify_hmac(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify_hmac_init(...) TOSE_verify_hmac_init(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify_hmac_update(...) TOSE_verify_hmac_update(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify_hmac_final(...) TOSE_verify_hmac_final(DEFAULT_CTX, __VA_ARGS__)
#define TO_compute_cmac(...) TOSE_compute_cmac(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify_cmac(...) TOSE_verify_cmac(DEFAULT_CTX, __VA_ARGS__)
#define TO_secure_payload(...) TOSE_secure_payload(DEFAULT_CTX, __VA_ARGS__)
#define TO_unsecure_payload(...) TOSE_unsecure_payload(DEFAULT_CTX, __VA_ARGS__)
#define TO_unsecure_payload_init_ccm TO_unsecure_payload_init_aead
#define TO_sign(...) TOSE_sign(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify(...) TOSE_verify(DEFAULT_CTX, __VA_ARGS__)
#define TO_sign_hash(...) TOSE_sign_hash(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify_hash_signature(...) TOSE_verify_hash_signature(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_certificate_subject_cn(...) TOSE_get_certificate_subject_cn(DEFAULT_CTX, __VA_ARGS__)
#define TO_set_certificate_signing_request_dn(...) TOSE_set_certificate_signing_request_dn(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_certificate_signing_request(...) TOSE_get_certificate_signing_request(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_certificate(...) TOSE_get_certificate(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_certificate_x509(...) TOSE_get_certificate_x509(DEFAULT_CTX, __VA_ARGS__)
#define TO_set_certificate_x509(...) TOSE_set_certificate_x509(DEFAULT_CTX, __VA_ARGS__)
#define TO_set_certificate_x509_init(...) TOSE_set_certificate_x509_init(DEFAULT_CTX, __VA_ARGS__)
#define TO_set_certificate_x509_update(...) TOSE_set_certificate_x509_update(DEFAULT_CTX, __VA_ARGS__)
#define TO_set_certificate_x509_final(...) TOSE_set_certificate_x509_final(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_certificate_and_sign(...) TOSE_get_certificate_and_sign(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_certificate_x509_and_sign(...) TOSE_get_certificate_x509_and_sign(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify_certificate_and_store(...) TOSE_verify_certificate_and_store(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify_chain_certificate_and_store_init(...) TOSE_verify_chain_certificate_and_store_init(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify_chain_certificate_and_store_update(...) TOSE_verify_chain_certificate_and_store_update(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify_chain_certificate_and_store_final(...) TOSE_verify_chain_certificate_and_store_final(DEFAULT_CTX)
#define TO_verify_ca_certificate_and_store(...) TOSE_verify_ca_certificate_and_store(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify_chain_ca_certificate_and_store_init(...) TOSE_verify_chain_ca_certificate_and_store_init(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify_chain_ca_certificate_and_store_update(...) TOSE_verify_chain_ca_certificate_and_store_update(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify_chain_ca_certificate_and_store_final(...) TOSE_verify_chain_ca_certificate_and_store_final(DEFAULT_CTX)
#define TO_get_challenge_and_store(...) TOSE_get_challenge_and_store(DEFAULT_CTX, __VA_ARGS__)
#define TO_verify_challenge_signature(...) TOSE_verify_challenge_signature(DEFAULT_CTX, __VA_ARGS__)
#define TO_write_nvm(...) TOSE_write_nvm(DEFAULT_CTX, __VA_ARGS__)
#define TO_read_nvm(...) TOSE_read_nvm(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_nvm_size(...) TOSE_get_nvm_size(DEFAULT_CTX, __VA_ARGS__)
#define TO_set_tls_server_random(...) TOSE_set_tls_server_random(DEFAULT_CTX, __VA_ARGS__)
#define TO_set_tls_server_eph_pub_key(...) TOSE_set_tls_server_eph_pub_key(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_tls_random_and_store(...) TOSE_get_tls_random_and_store(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_tls_master_secret(...) TOSE_get_tls_master_secret(DEFAULT_CTX, __VA_ARGS__)
#define TO_renew_tls_keys(...) TOSE_renew_tls_keys(DEFAULT_CTX, __VA_ARGS__)
#define TO_renew_tls_keys_ecdhe(...) TOSE_renew_tls_keys_ecdhe(DEFAULT_CTX, __VA_ARGS__)
#define TO_aes128cbc_hmac_secure_message(...) TOSE_aes128cbc_hmac_secure_message(DEFAULT_CTX, __VA_ARGS__)
#define TO_aes128cbc_hmac_unsecure_message(...) TOSE_aes128cbc_hmac_unsecure_message(DEFAULT_CTX, __VA_ARGS__)
#define TO_aes128cbc_cmac_secure_message(...) TOSE_aes128cbc_cmac_secure_message(DEFAULT_CTX, __VA_ARGS__)
#define TO_aes128cbc_cmac_unsecure_message(...) TOSE_aes128cbc_cmac_unsecure_message(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_calculate_finished(...) TOSE_tls_calculate_finished(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_reset(...) TOSE_tls_reset(DEFAULT_CTX)
#define TO_tls_set_session(...) TOSE_tls_set_session(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_set_config(...) TOSE_tls_set_config(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_set_mode(...) TOSE_tls_set_mode(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_set_cid_ext_id(...) TOSE_tls_set_cid_ext_id(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_get_client_hello(...) TOSE_tls_get_client_hello(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_handle_hello_verify_request(...) TOSE_tls_handle_hello_verify_request(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_handle_server_hello(...) TOSE_tls_handle_server_hello(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_handle_server_certificate(...) TOSE_tls_handle_server_certificate(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_handle_server_certificate_init(...) TOSE_tls_handle_server_certificate_init(DEFAULT_CTX, __VA_ARGS__, TO_TLS_SERVER_CERTIFICATE_INIT_SIZE)
#define TO_tls_handle_server_certificate_update(...) TOSE_tls_handle_server_certificate_update(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_handle_server_certificate_final(...) TOSE_tls_handle_server_certificate_final(DEFAULT_CTX)
#define TO_tls_handle_server_key_exchange(...) TOSE_tls_handle_server_key_exchange(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_handle_server_key_exchange_init(...) TOSE_tls_handle_server_key_exchange_init(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_handle_server_key_exchange_update(...) TOSE_tls_handle_server_key_exchange_update(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_handle_server_key_exchange_final(...) TOSE_tls_handle_server_key_exchange_final(DEFAULT_CTX)
#define TO_tls_handle_certificate_request(...) TOSE_tls_handle_certificate_request(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_handle_server_hello_done(...) TOSE_tls_handle_server_hello_done(DEFAULT_CTX, __VA_ARGS__, TO_TLS_SERVER_HELLO_DONE_SIZE)
#define TO_tls_get_certificate(...) TOSE_tls_get_certificate(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_get_certificate_init(...) TOSE_tls_get_certificate_init(DEFAULT_CTX, __VA_ARGS__, NULL)
#define TO_tls_get_certificate_update(...) TOSE_tls_get_certificate_update(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_get_certificate_final(...) TOSE_tls_get_certificate_final(DEFAULT_CTX)
#define TO_tls_get_client_key_exchange(...) TOSE_tls_get_client_key_exchange(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_get_certificate_verify(...) TOSE_tls_get_certificate_verify(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_get_change_cipher_spec(...) TOSE_tls_get_change_cipher_spec(DEFAULT_CTX, __VA_ARGS__, NULL)
#define TO_tls_get_finished(...) TOSE_tls_get_finished(DEFAULT_CTX, __VA_ARGS__, NULL)
#define TO_tls_handle_change_cipher_spec(...) TOSE_tls_handle_change_cipher_spec(DEFAULT_CTX, __VA_ARGS__, TO_TLS_CHANGE_CIPHER_SPEC_SIZE)
#define TO_tls_handle_finished(...) TOSE_tls_handle_finished(DEFAULT_CTX, __VA_ARGS__, TO_TLS_FINISHED_PAYLOAD_SIZE)
#define TO_tls_get_certificate_slot(...) TOSE_tls_get_certificate_slot(DEFAULT_CTX, __VA_ARGS__, NULL)
#define TO_tls_secure_payload(...) TOSE_tls_secure_payload(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_secure_payload_init_cbc(...) TOSE_tls_secure_payload_init_cbc(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_secure_payload_init_aead(...) TOSE_tls_secure_payload_init_aead(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_secure_payload_init_ccm TO_tls_secure_payload_init_aead
#define TO_tls_secure_payload_update(...) TOSE_tls_secure_payload_update(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_secure_payload_final(...) TOSE_tls_secure_payload_final(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_unsecure_payload(header, payload, payload_len, data, data_len) TOSE_tls_unsecure_payload(DEFAULT_CTX, header, __TLS_HEADER_SIZE, payload, payload_len, data, data_len)
#define TO_tls_unsecure_payload_init_cbc(cryptogram_len, header, initial_vector, last_block_iv, last_block) TOSE_tls_unsecure_payload_init_cbc(DEFAULT_CTX, cryptogram_len, header, __TLS_HEADER_SIZE, initial_vector, last_block_iv, last_block)
#define TO_tls_unsecure_payload_init_aead(cryptogram_len, header, initial_vector) TOSE_tls_unsecure_payload_init_aead(DEFAULT_CTX, cryptogram_len, header, __TLS_HEADER_SIZE, initial_vector)
#define TO_tls_unsecure_payload_init_ccm TO_tls_unsecure_payload_init_aead
#define TO_tls_unsecure_payload_update(...) TOSE_tls_unsecure_payload_update(DEFAULT_CTX, __VA_ARGS__)
#define TO_tls_unsecure_payload_final(...) TOSE_tls_unsecure_payload_final(DEFAULT_CTX)
#define TO_lora_compute_mic(...) TOSE_lora_compute_mic(DEFAULT_CTX, __VA_ARGS__)
#define TO_lora_encrypt_payload(...) TOSE_lora_encrypt_payload(DEFAULT_CTX, __VA_ARGS__)
#define TO_lora_join_compute_mic(...) TOSE_lora_join_compute_mic(DEFAULT_CTX, __VA_ARGS__)
#define TO_lora_decrypt_join(...) TOSE_lora_decrypt_join(DEFAULT_CTX, __VA_ARGS__)
#define TO_lora_compute_shared_keys(...) TOSE_lora_compute_shared_keys(DEFAULT_CTX, __VA_ARGS__)
#define TO_lora_get_app_eui(...) TOSE_lora_get_app_eui(DEFAULT_CTX, __VA_ARGS__)
#define TO_lora_get_dev_eui(...) TOSE_lora_get_dev_eui(DEFAULT_CTX, __VA_ARGS__)
#define TO_lora_get_dev_addr(...) TOSE_lora_get_dev_addr(DEFAULT_CTX, __VA_ARGS__)
#define TO_lora_get_join_request_phypayload(...) TOSE_lora_get_join_request_phypayload(DEFAULT_CTX, __VA_ARGS__)
#define TO_lora_handle_join_accept_phypayload(...) TOSE_lora_handle_join_accept_phypayload(DEFAULT_CTX, __VA_ARGS__)
#define TO_lora_secure_phypayload(...) TOSE_lora_secure_phypayload(DEFAULT_CTX, __VA_ARGS__)
#define TO_lora_unsecure_phypayload(...) TOSE_lora_unsecure_phypayload(DEFAULT_CTX, __VA_ARGS__)
#define TO_admin_session_init(...) TOSE_admin_session_init(DEFAULT_CTX, __VA_ARGS__)
#define TO_admin_session_auth_server(...) TOSE_admin_session_auth_server(DEFAULT_CTX, __VA_ARGS__)
#define TO_admin_command(...) TOSE_admin_command(DEFAULT_CTX, __VA_ARGS__)
#define TO_admin_command_with_response(...) TOSE_admin_command_with_response(DEFAULT_CTX, __VA_ARGS__)
#define TO_admin_command_with_response2(...) TOSE_admin_command_with_response2(DEFAULT_CTX, __VA_ARGS__)
#define TO_admin_session_fini(...) TOSE_admin_session_fini(DEFAULT_CTX, __VA_ARGS__)
#define TO_admin_set_slot(...) TOSE_admin_set_slot(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_key_fingerprint(...) TOSE_get_key_fingerprint(DEFAULT_CTX, __VA_ARGS__)
#define TO_flush() TOSE_flush(DEFAULT_CTX)
#define TO_get_random(...) TOSE_get_random(DEFAULT_CTX, __VA_ARGS__)
#define TO_set_status_PIO_config(...) TOSE_set_status_PIO_config(DEFAULT_CTX, __VA_ARGS__)
#define TO_get_status_PIO_config(...) TOSE_get_status_PIO_config(DEFAULT_CTX, __VA_ARGS__)
#define TO_loader_broadcast_get_info(...) TOSE_loader_broadcast_get_info(DEFAULT_CTX, __VA_ARGS__)
#define TO_loader_broadcast_restore_loader(...) TOSE_loader_broadcast_restore_loader(DEFAULT_CTX, __VA_ARGS__)
#define TO_loader_broadcast_send_init_data(...) TOSE_loader_broadcast_send_init_data(DEFAULT_CTX, __VA_ARGS__)
#define TO_loader_broadcast_write_data(...) TOSE_loader_broadcast_write_data(DEFAULT_CTX, __VA_ARGS__)
#define TO_loader_broadcast_commit_release(...) TOSE_loader_broadcast_commit_release(DEFAULT_CTX, __VA_ARGS__)

#define TO_helper_ecies_seq_auth_TO(...) TOSE_helper_ecies_seq_auth_TO(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_ecies_seq_auth_remote_1(...) TOSE_helper_ecies_seq_auth_remote_1(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_ecies_seq_auth_remote_2(...) TOSE_helper_ecies_seq_auth_remote_2(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_ecies_seq_secure_messaging(...) TOSE_helper_ecies_seq_secure_messaging(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_tls_ctx_t TOSE_helper_tls_ctx_t
#define TO_helper_tls_handle_server_certificate(...) TOSE_helper_tls_handle_server_certificate(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_tls_handle_server_key_exchange(...) TOSE_helper_tls_handle_server_key_exchange(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_tls_get_certificate(...) TOSE_helper_tls_get_certificate(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_tls_init_session(...) TOSE_helper_tls_init_session(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_tls_close(...) TOSE_helper_tls_close(__VA_ARGS__)
#define TO_helper_tls_fini(...) TOSE_helper_tls_fini(__VA_ARGS__)
#define TO_helper_tls_cleanup(...) TOSE_helper_tls_cleanup(__VA_ARGS__)
#define TO_helper_tls_set_retransmission_timeout(...) TOSE_helper_tls_set_retransmission_timeout(__VA_ARGS__)
#define TO_helper_tls_set_retransmission_max(...) TOSE_helper_tls_set_retransmission_max(__VA_ARGS__)
#define TO_helper_tls_set_fragment_max_size(...) TOSE_helper_tls_set_fragment_max_size(__VA_ARGS__)
#define TO_helper_tls_set_cipher_suites(...) TOSE_helper_tls_set_cipher_suites(__VA_ARGS__)
#define TO_helper_tls_set_config(...) TOSE_helper_tls_set_config(__VA_ARGS__)
#define TO_helper_tls_do_handshake_step(...) TOSE_helper_tls_do_handshake_step(__VA_ARGS__)
#define TO_helper_tls_do_handshake(...) TOSE_helper_tls_do_handshake(__VA_ARGS__)
#define TO_helper_tls_get_certificate_slot(...) TOSE_helper_tls_get_certificate_slot(__VA_ARGS__)
#define TO_helper_tls_send(...) TOSE_helper_tls_send(__VA_ARGS__)
#define TO_helper_tls_receive(...) TOSE_helper_tls_receive(__VA_ARGS__)
#define TO_helper_tls_secure_message(...) TOSE_helper_tls_secure_message(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_tls_unsecure_message(...) TOSE_helper_tls_unsecure_message(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_tls_secure_payload_cbc(...) TOSE_helper_tls_secure_payload_cbc(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_tls_secure_payload_aead(...) TOSE_helper_tls_secure_payload_aead(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_tls_unsecure_payload_cbc(...) TOSE_helper_tls_unsecure_payload_cbc(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_tls_unsecure_payload_aead(...) TOSE_helper_tls_unsecure_payload_aead(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_verify_chain_certificate_and_store(...) TOSE_helper_verify_chain_certificate_and_store(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_verify_chain_ca_certificate_and_store(...) TOSE_helper_verify_chain_ca_certificate_and_store(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_set_certificate_x509(...) TOSE_helper_set_certificate_x509(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_secure_payload(...) TOSE_helper_secure_payload(DEFAULT_CTX, __VA_ARGS__)
#define TO_helper_unsecure_payload(...) TOSE_helper_unsecure_payload(DEFAULT_CTX, __VA_ARGS__)

#define TO_set_lib_hook_pre_command TODRV_HSE_set_lib_hook_pre_command
#define TO_set_lib_hook_post_write TODRV_HSE_set_lib_hook_post_write
#define TO_set_lib_hook_post_command TODRV_HSE_set_lib_hook_post_command
#define TO_seclink_set_store_keys_cb TODRV_HSE_seclink_set_store_keys_cb
#define TO_seclink_store_keys_cb TODRV_HSE_seclink_store_keys_cb
#define TO_seclink_set_load_keys_cb TODRV_HSE_seclink_set_load_keys_cb
#define TO_seclink_load_keys_cb TODRV_HSE_seclink_load_keys_cb
#define TO_seclink_set_key_renewal_cb TODRV_HSE_seclink_set_key_renewal_cb
#define TO_seclink_keys_renewal_cb TODRV_HSE_seclink_keys_renewal_cb
#define TO_seclink_reset TODRV_HSE_seclink_reset
#define TO_seclink_request_renewed_keys TODRV_HSE_seclink_request_renewed_keys
#define TO_seclink_bypass TODRV_HSE_seclink_bypass
#define TO_config TODRV_HSE_trp_config
#define TO_write TODRV_HSE_trp_write
#define TO_read TODRV_HSE_trp_read
#define TO_last_command_duration TODRV_HSE_trp_last_command_duration

#endif // _TO_LEGACY_H_


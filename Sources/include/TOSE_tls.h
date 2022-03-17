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

/**
 * @file TOSE_tls.h
 * @brief
 */

#ifndef _TOSE_TLS_H_
#define _TOSE_TLS_H_

#ifndef TOSE_TLS_API
#ifdef __linux__
#define TOSE_TLS_API
#elif _WIN32
#define TOSE_TLS_API __declspec(dllexport)
#else
#define TOSE_TLS_API
#endif /* __LINUX__ * @endcond
 */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"

/** @addtogroup tls
 * @{
 */

/**
 * @brief Set TLS server random
 * @param[in] ctx Pointer to the SE context
 * @param[in] random Server random including a timestamp as prefix
 * @details
 * Send TLS server random to Secure Element.
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_TLS_API TO_ret_t TOSE_set_tls_server_random(TOSE_ctx_t *ctx,
		uint8_t random[TO_TLS_RANDOM_SIZE]);

/**
 *
 * @brief Set TLS server ephemeral public key
 * @param[in] ctx Pointer to the SE context
 * @param[in] key_index Index of the public key to update
 * @param[in] ecc_params Includes curve type, format and name, length of the public
 * key concatenated with the uncompression tag (0x04)
 * @param[in] signature Signature of the concatenation of 'client_random',
 * 'server_random' and 'ecc_params'
 * @details
 * Send TLS server ephemeral public key to Secure Element.
 * This key must be signed with the private key associated to the certificate
 * sent to the Secure Element using TOSE_verify_certificate_and_store().
 * Commands TOSE_verify_certificate_and_store(), TOSE_get_tls_random_and_store(),
 * and TOSE_set_tls_server_random() must be called prior to this command.
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_TLS_API TO_ret_t TOSE_set_tls_server_eph_pub_key(TOSE_ctx_t *ctx,
		uint8_t key_index,
		uint8_t ecc_params[TO_TLS_SERVER_PARAMS_SIZE],
		uint8_t signature[TO_SIGNATURE_SIZE]);

/**
 * @brief Get TLS random
 * @param[in] ctx Pointer to the SE context
 * @param[in] timestamp POSIX timestamp (seconds since January 1st 1970 00:00:00
 * UTC)
 * @param[out] random Returned random challenge
 * @details
 * Get TLS random from Secure Element.
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_TLS_API TO_ret_t TOSE_get_tls_random_and_store(TOSE_ctx_t *ctx,
		uint8_t timestamp[TO_TIMESTAMP_SIZE],
		uint8_t random[TO_TLS_RANDOM_SIZE]);

/**
 * @brief Get TLS master secret.
 * @param[in] ctx Pointer to the SE context
 * @param[out] master_secret returned master secret
 * @details
 * Requests TLS master secret to Secure Element.
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid certificate index
 * - TO_INVALID_RESPONSE_LENGTH: invalid response length
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_TLS_API TO_ret_t TOSE_get_tls_master_secret(TOSE_ctx_t *ctx,
		uint8_t master_secret[TO_TLS_MASTER_SECRET_SIZE]);

/**
 * @brief Get TLS master secret derived keys.
 * @param ctx SE context
 * @param[in] key_block_length length of the derived key block, value 0 means a length of 256
 * @param[out] key_block buffer with keys derivation
 *
 * Request the Secure Element to derive TLS keys from the master secret and return them
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid certificate index
 * - TO_INVALID_RESPONSE_LENGTH: invalid response length
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 */
TOSE_TLS_API TO_ret_t TOSE_get_tls_master_secret_derived_keys(TOSE_ctx_t *ctx,
		uint8_t key_block_length,
		uint8_t key_block[]);

/**
 * @brief Derive master secret.
 * @param[in] ctx Pointer to the SE context
 * @param[in] kpriv_index Index of the private key to use
 * @param[in] kpub_index Index of the remote public key to use
 * @param[in] enc_key_index Index to store encryption AES/HMAC keys
 * @param[in] dec_key_index Index to store decryption AES/HMAC keys
 * @details
 * Renew TLS keys within Secure Element using master secret derivation with
 * ECDHE method.
 * Need to call TOSE_renew_ecc_keys(), TOSE_get_public_key(),
 * TOSE_verify_certificate_and_store(), TOSE_tls_get_random_and_store(),
 * TOSE_tls_set_server_random(), and TOSE_tls_set_server_epublic_key() prior
 * to this command.
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_ARG_OUT_OF_RANGE: invalid certificate index
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_TLS_API TO_ret_t TOSE_renew_tls_keys_ecdhe(TOSE_ctx_t *ctx,
		const uint8_t kpriv_index,
		const uint8_t kpub_index,
		const uint8_t enc_key_index,
		const uint8_t dec_key_index);

/**
 * @brief Calculate finished
 * @param[in] ctx Pointer to the SE context
 * @param[in] from 0 if message is from client, 1 if it is from server
 * @param[in] handshake_hash Hash of all handshake messages
 * @param[out] finished Result
 * @details
 * Compute the TLS “verify_data” of the “Finished” message from the
 * handshake messages’ hash.
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element136
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element136
 * - TO_ERROR: generic error
 */
TOSE_TLS_API TO_ret_t TOSE_tls_calculate_finished(TOSE_ctx_t *ctx,
		const int from,
		const uint8_t handshake_hash[TO_HASH_SIZE],
		uint8_t finished[TO_TLS_FINISHED_SIZE]);

/** @}
 */

/** @addtogroup tlsoptim
 * @{
 */

/**
 * @brief Resets the current TLS/DTLS session.
 * @param[in] ctx Pointer to the SE context
 * @note After resetting the session, a full handshake will have to be re-negociated, as the session keys
 * and master secrets are reset for this session. It does not have any influence on the other sessions that may be opened. @n
 * It can be used also to fix a malfunctioning TLS slot.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_reset(TOSE_ctx_t *ctx);

/**
 * @brief Selects between TLS and DTLS mode and resets the session for the current selected slot.
 * @param[in] ctx Pointer to the SE context
 * @param[in] mode TLS mode. Currently only @ref TO_TLS_MODE_TLS_1_2 and @ref TO_TLS_MODE_DTLS_1_2 are supported.
 * @deprecated
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_set_mode(TOSE_ctx_t *ctx,
		const TO_tls_mode_t mode
) TO_DEPRECATED;

/**
 * @brief Set TLS config (either mode or cipher suite selection).
 * @param[in] ctx Pointer to the SE context
 * @param[in] config_id TLS configuration ID (either @ref TO_TLS_CONFIG_ID_MODE or @ref TO_TLS_CONFIG_ID_CIPHER_SUITES)
 * @param[in] config Pointer to the desired new TLS configuration
 * @param[in] config_len TLS configuration length (1 for the mode, 2 for the cipher suite)
 * @details Permits to switch to TLS or DTLS, to select a cipher suite for the handshake and resets the current session (if the configuration has changed).
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_set_config(TOSE_ctx_t *ctx,
		const TO_tls_config_id_t config_id,
		const uint8_t *config,
		const uint16_t config_len);

/**
 * @brief Selects the current TLS session slot to be used.
 * @note There are several session slots available which can be connected to
 * different servers. Depending on your application you may have
 * to switch between those session slots.
 * @param[in] ctx Pointer to the SE context
 * @param[in] session TLS session ID
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_set_session(TOSE_ctx_t *ctx, const uint8_t session);

/**
 * @brief Set sets the type of the extension ID corresponding to the connection ID
 * @param[in] ctx Pointer to the SE context
 * @param[in] cid_ext_id Connection ID extension ID
 * @details Currently, the ID corresponding to the connection ID is still part of a draft standard (dec. 2021). Until the moment the RFC standard is published, this entry-point is used to provide this information.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_set_cid_ext_id(TOSE_ctx_t *ctx,
		const TO_tls_extension_t cid_ext_id);

/**
 * @brief Generates the TLS Client_Hello (client) message
 * @param[in] ctx Pointer to the SE context
 * @param[in] timestamp Timestamp (seconds since epoch)
 * @param[out] client_hello Pointer to a buffer receiving the ClientHello payload (up to 79 bytes in TLS, 120 bytes in DTLS)
 * @param[out] client_hello_len Pointer to receive the ClientHello payload length
 * @details
 * When a client first connects to a server, it is required to send
 * the ClientHello as its first message.  The client can also send a
 * ClientHello in response to a HelloRequest or on its own initiative
 * in order to renegotiate the security parameters in an existing
 * connection.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_get_client_hello(TOSE_ctx_t *ctx,
		const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		uint8_t *client_hello,
		uint16_t *client_hello_len);

/* XXX to remove */
/**
 * @brief Get TLS ClientHello with extension
 * @param[in,out] ctx SE context
 * @param[in] timestamp Timestamp (seconds since epoch)
 * @param[in] ext_data extension data
 * @param[in] ext_length extension length
 * @param[out] client_hello ClientHello payload
 * @param[out] client_hello_len ClientHello payload length
 *
 * Return the TLS handshake payload of the standard TLS “ClientHello” message.
 * This payload must be encapsulated in a TLS record.
 * The length of the response can be different depending on the use case.
 *
 * @retval TORSP_SUCCESS on success
 * @retval TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * @retval TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * @retval TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * @retval TO_MEMORY_ERROR: internal I/O buffer overflow
 * @retval TO_ERROR: generic error
 */
TOSE_TLS_API TO_ret_t TOSE_tls_get_client_hello_ext(TOSE_ctx_t *ctx, const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		const uint8_t *ext_data, uint16_t ext_length,
		uint8_t *client_hello, uint16_t *client_hello_len);

/**
 * @brief Get TLS ClientHello - CAPI version - Init
 * @param[in,out] ctx SE context
 * @param[in] timestamp Timestamp (seconds since epoch)
 * @param[in] ext_data extension data
 * @param[in] ext_length extension length
 * @param[out] client_hello_len ClientHello payload length
 * @param[out] final_flag signal the final chunk of ClientHello to be received with TOSE_tls_get_client_hello_final()
 *
 * Initialize retrieval of the TLS handshake payload of the standard TLS “ClientHello” message.
 * This payload must be encapsulated in a TLS record.
 *
 * @retval TORSP_SUCCESS on success
 * @retval TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * @retval TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * @retval TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * @retval TO_MEMORY_ERROR: internal I/O buffer overflow
 * @retval TO_ERROR: generic error
 */
TOSE_TLS_API TO_ret_t TOSE_tls_get_client_hello_init(TOSE_ctx_t *ctx,
		const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		const uint8_t *ext_data, uint16_t ext_length,
		uint16_t *client_hello_len, uint8_t *final_flag);

/**
 * @brief Get TLS ClientHello - CAPI version - Update
 * @param[in,out] ctx SE context
 * @param[out] data ClientHello payload part
 * @param[out] part_len ClientHello payload part length
 * @param[out] final_flag signal the final chunk of ClientHello to be received with TOSE_tls_get_client_hello_final()
 *
 * Return a part of the TLS handshake payload of the standard TLS “ClientHello” message.
 * This payload must be encapsulated in a TLS record.
 *
 * @retval TORSP_SUCCESS on success
 * @retval TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * @retval TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * @retval TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * @retval TO_MEMORY_ERROR: internal I/O buffer overflow
 * @retval TO_ERROR: generic error
 */
TOSE_TLS_API TO_ret_t TOSE_tls_get_client_hello_update(TOSE_ctx_t *ctx,
		uint8_t *data,
		uint16_t *part_len, uint8_t *final_flag);

/**
 * @brief Get TLS ClientHello - CAPI version - Final
 * @param[in,out] ctx SE context
 * @param[out] data last ClientHello payload part
 *
 * Return the last part of the TLS handshake payload of the standard TLS “ClientHello” message.
 * This payload must be encapsulated in a TLS record.
 *
 * @retval TORSP_SUCCESS on success
 * @retval TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * @retval TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * @retval TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * @retval TO_MEMORY_ERROR: internal I/O buffer overflow
 * @retval TO_ERROR: generic error
 */
TOSE_TLS_API TO_ret_t TOSE_tls_get_client_hello_final(TOSE_ctx_t *ctx, uint8_t *data);

/**
 * @brief Handles the DTLS HelloVerifyRequest (server) message
 * @param[in] ctx Pointer to the SE context
 * @param[in] hello_verify_request HelloVerifyRequest message
 * @param[in] hello_verify_request_len HelloVerifyRequest message length
 * @note This message processing is only needed in the case of DTLS
 * @details
 * When the client sends its ClientHello message to the server, the server
 * MAY respond with a HelloVerifyRequest message. This message contains
 * a stateless cookie.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_hello_verify_request(TOSE_ctx_t *ctx,
		const uint8_t *hello_verify_request,
		const uint32_t hello_verify_request_len);

/**
 * @brief Handles the ServerHello (server) message
 * @param[in] ctx Pointer to the SE context
 * @param[in] server_hello ServertHello payload
 * @param[in] server_hello_len ServertHello payload length
 * @details
 * The server will send this message in response to a ClientHello
 * message when it was able to find an acceptable set of algorithms.
 * If it cannot find such a match, it will respond with a handshake
 * failure alert.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_server_hello(TOSE_ctx_t *ctx,
		const uint8_t *server_hello,
		const uint32_t server_hello_len);

/**
 * @brief Handle TLS ServerHello - CAPI version - Init
 * @param[in,out] ctx SE context
 * @param[in] server_hello_len ServerHello payload length
 *
 * Initialize handling of the TLS handshake payload of the standard TLS
 * “ServerHello” message received during TLS handshake.
 *
 * @retval TORSP_SUCCESS on success
 * @retval TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * @retval TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * @retval TORSP_ARG_OUT_OF_RANGE: bad content
 * @retval TO_MEMORY_ERROR: internal I/O buffer overflow
 * @retval TO_ERROR: generic error
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_server_hello_init(TOSE_ctx_t *ctx,
		const uint32_t server_hello_len);

/**
 * @brief Handle TLS ServerHello - CAPI version - Update
 * @param[in,out] ctx SE context
 * @param[in] data part of ServerHello payload
 * @param[in] part_len part length
 *
 * Handle a part of the TLS handshake payload of the standard TLS
 * “ServerHello” message received during TLS handshake.
 *
 * @retval TORSP_SUCCESS on success
 * @retval TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * @retval TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * @retval TORSP_ARG_OUT_OF_RANGE: bad content
 * @retval TO_MEMORY_ERROR: internal I/O buffer overflow
 * @retval TO_ERROR: generic error
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_server_hello_update(TOSE_ctx_t *ctx,
		const uint8_t *data,
		const uint32_t part_len);

/**
 * @brief Handle TLS ServerHello - CAPI version - Final
 * @param[in,out] ctx SE context
 * @param[in] data last part of ServerHello payload
 * @param[in] last_len last part len
 *
 * Handle the last part of the TLS handshake payload of the standard TLS
 * “ServerHello” message received during TLS handshake.
 *
 * @retval TORSP_SUCCESS on success
 * @retval TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * @retval TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * @retval TORSP_ARG_OUT_OF_RANGE: bad content
 * @retval TO_MEMORY_ERROR: internal I/O buffer overflow
 * @retval TO_ERROR: generic error
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_server_hello_final(TOSE_ctx_t *ctx,
		const uint8_t *data,
		const uint32_t last_len);

/**
 * @brief Handles the TLS Certificate (server) message
 * @param[in] ctx Pointer to the SE context
 * @param[in] server_certificate Certificate payload
 * @param[in] server_certificate_len Certificate payload length
 * @details The server MUST send a Certificate message whenever the agreed-
 * upon key exchange method uses certificates for authentication
 * (this includes all key exchange methods defined in this document
 * except DH_anon).  This message will always immediately follow the
 * ServerHello message.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_server_certificate(TOSE_ctx_t *ctx,
		const uint8_t *server_certificate,
		const uint32_t server_certificate_len);

/**
 * @brief Handles the TLS Server Certificate header (server)
 * @param[in] ctx Pointer to the SE context
 * @param[in] server_certificate_init Certificate payload header (handshake header
 * + certificates list length)
 * @param[in] server_certificate_init_len Certificate payload header length
 * @details Handle TLS Server Certificate header from TLS handshake payload of the
 * standard TLS “ServerCertificate” message.
 * The goal of TOSE_tls_handle_server_certificate_ init(), udate() and final(),
 * is to validate a certificate chain, and to store the public key of the first
 * certificate.
 * You must decapsulate it from TLS record prior to use this command.
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_server_certificate_init(TOSE_ctx_t *ctx,
		const uint8_t *server_certificate_init,
		const uint32_t server_certificate_init_len);

/**
 * @brief Handles the TLS Server Certificate partial payload (server)
 * @param[in] ctx Pointer to the SE context
 * @param[in] server_certificate_update Certificate partial payload
 * @param[in] server_certificate_update_len Certificate partial payload length
 * @details
 * Handle TLS Server Certificate partial payload from TLS handshake payload of
 * the standard TLS “ServerCertificate” message, and if possible, verify the
 * signature and memories the key of the current certificate of the certificates
 * chain.
 * You must decapsulate it from TLS record prior to use this command.
 * This command can be called several times.
 * TOSE_tls_handle_server_certificate_init() must be called prior to this call.
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_server_certificate_update(TOSE_ctx_t *ctx,
		const uint8_t *server_certificate_update,
		const uint32_t server_certificate_update_len);

/**
 * @brief Finishes the TLS Server Certificate handling (server)
 * @param[in] ctx Pointer to the SE context *
 * Finish Server Certificate TLS handshake payload handling by verifying
 * signature of last certificate and store the public key of the first
 * certificate of the chain.
 * You must decapsulate it from TLS record prior to use this command.
 * Functions TOSE_tls_handle_server_certificate_init(), and
 * TOSE_tls_handle_server_certificate_update() must be called prior to this call.
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_server_certificate_final(TOSE_ctx_t *ctx);

/**
 * @brief Handle the TLS ServerKeyExchange (server) message
 * @param[in] ctx Pointer to the SE context
 * @param[in] server_key_exchange ServerKeyExchange payload
 * @param[in] server_key_exchange_len ServerKeyExchange payload length
 * @details
 * Handle TLS handshake payload of the standard TLS “ServerKeyExchange” message.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_server_key_exchange(TOSE_ctx_t *ctx,
		const uint8_t *server_key_exchange,
		const uint32_t server_key_exchange_len);

/**
 * @brief Handles the TLS Server ServerKeyExchange (server) header
 * @param[in] ctx Pointer to the SE context
 * @param[in] server_key_exchange_init ServerKeyExchange payload header (handshake header
 * + key_exchanges list length)
 * @param[in] server_key_exchange_init_len ServerKeyExchange payload header length
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_server_key_exchange_init(TOSE_ctx_t *ctx,
		const uint8_t *server_key_exchange_init,
		const uint32_t server_key_exchange_init_len);

/**
 * @brief Handles the TLS Server ServerKeyExchange partial payload (server)
 * @param[in] ctx Pointer to the SE context
 * @param[in] server_key_exchange_update ServerKeyExchange partial payload
 * @param[in] server_key_exchange_update_len ServerKeyExchange partial payload length
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_server_key_exchange_update(TOSE_ctx_t *ctx,
		const uint8_t *server_key_exchange_update,
		const uint32_t server_key_exchange_update_len);

/**
 * @brief Finishes TLS Server ServerKeyExchange handling (server)
 * @param[in] ctx Pointer to the SE context
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_server_key_exchange_final(TOSE_ctx_t *ctx);

/**
 * @brief Handles the TLS CertificateRequest (server) message
 * @param[in] ctx Pointer to the SE context
 * @param[in] certificate_request CertificateRequest payload
 * @param[in] certificate_request_len CertificateRequest payload length
 * @details
 * The server MUST send a Certificate message whenever the agreed-
 * upon key exchange method uses certificates for authentication
 * (this includes all key exchange methods defined in this document
 * except DH_anon).  This message will always immediately follow the
 * ServerHello message.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_certificate_request(TOSE_ctx_t *ctx,
		const uint8_t *certificate_request,
		const uint32_t certificate_request_len);

/**
 * @brief Handles the DTLS ServerHelloDone (server) message
 * @param[in] ctx Pointer to the SE context
 * @param[in] server_hello_done ServerHelloDone payload
 * @param[in] server_hello_done_len ServerHelloDone payload length
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_server_hello_done(TOSE_ctx_t *ctx,
		const uint8_t *server_hello_done,
		const uint32_t server_hello_done_len);

/**
 * @brief Generates the TLS Certificate (client) message
 * @param[in] ctx Pointer to the SE context
 * @param[out] certificate Certificate payload
 * @param[out] certificate_len Certificate payload length
 * @details
 * This is the first message the client can send after receiving a
 * ServerHelloDone message.  This message is only sent if the server
 * requests a certificate.  If no suitable certificate is available,
 * the client MUST send a certificate message containing no
 * certificates.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_get_certificate(TOSE_ctx_t *ctx,
		uint8_t *certificate,
		uint16_t *certificate_len);

/**
 * @brief Get the TLS Certificate initialization (client)
 * @param[in] ctx Pointer to the SE context
 * @param[out] certificate Certificate payload
 * @param[out] certificate_len Certificate payload length
 * @details
 * This function is used with TOSE_tls_get_certificate_update() and
 * TOSE_tls_get_certificate_final() to get TLS Certificate of more than 512
 * bytes without limitation.
 * This first command initiates the process.
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_get_certificate_init(TOSE_ctx_t *ctx,
		uint8_t *certificate,
		uint16_t *certificate_len);

/**
 * @brief Gets the TLS Certificate update (client)
 * @param[in] ctx Pointer to the SE context
 * @param[out] certificate Certificate payload
 * @param[out] certificate_len Certificate payload length
 * @details
 * This command can be called several times.
 * Function TOSE_tls_get_certificate_init() must be called prior to this command.
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_get_certificate_update(TOSE_ctx_t *ctx,
		uint8_t *certificate,
		uint16_t *certificate_len);

/**
 * @brief Gets the TLS Certificate finalize (client)
 * @param[in] ctx Pointer to the SE context
 *
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_get_certificate_final(TOSE_ctx_t *ctx);

/**
 * @brief Gets the TLS ClientKeyExchange (client) message
 * @param[in] ctx Pointer to the SE context
 * @param[out] client_key_exchange ClientKeyExchange payload
 * @param[out] client_key_exchange_len ClientKeyExchange payload length
 * @details
 * Get TLS handshake payload of the standard TLS message “ClientKeyExchange”,
 * containing internal Secure Element's ephemeral public key if using ECDHE
 * cipher suite.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_get_client_key_exchange(TOSE_ctx_t *ctx,
		uint8_t *client_key_exchange,
		uint16_t *client_key_exchange_len);

/**
 * @brief Generates the TLS Certificate_Verify (client) message
 * @param[in] ctx Pointer to the SE context
 * @param[out] certificate_verify CertificateVerify payload
 * @param[out] certificate_verify_len CertificateVerify payload length
 * @details
 * This message is used to provide explicit verification of a client
 * certificate.  This message is only sent following a client
 * certificate that has signing capability (i.e., all certificates
 * except those containing fixed Diffie-Hellman parameters).  When
 * sent, it MUST immediately follow the client key exchange message.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_get_certificate_verify(TOSE_ctx_t *ctx,
		uint8_t *certificate_verify,
		uint16_t *certificate_verify_len);

/**
 * @brief Generates the TLS Change_Cipher_Spec (client) message
 * @param[in] ctx Pointer to the SE context
 * @param[out] change_cipher_spec ChangeCipherSpec payload
 * @param[out] change_cipher_spec_len ChangeCipherSpec payload length
 * @details
 * The ChangeCipherSpec message is sent by both the client and the
 * server to notify the receiving party that subsequent records will be
 * protected under the newly negotiated CipherSpec and keys. This message
 * is technically not part of the handshake.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_get_change_cipher_spec(TOSE_ctx_t *ctx,
		uint8_t *change_cipher_spec,
		uint16_t *change_cipher_spec_len);

/**
 * @brief Generates the TLS Finished (client) message
 * @param[in] ctx Pointer to the SE context
 * @param[out] finished Finish payload
 * @param[out] finished_len Finish payload length
 * @details
 * The Finished message is the first one protected with the just
 * negotiated algorithms, keys, and secrets.  Recipients of Finished
 * messages MUST verify that the contents are correct.  Once a side
 * has sent its Finished message and received and validated the
 * Finished message from its peer, it may begin to send and receive
 * application data over the connection.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_get_finished(TOSE_ctx_t *ctx,
		uint8_t *finished,
		uint16_t *finished_len);

/**
 * @brief Handles the TLS ChangeCipherSpec (server) message
 * @param[in] ctx Pointer to the SE context
 * @param[in] change_cipher_spec ChangeCipherSpec payload
 * @param[in] change_cipher_spec_len ChangeCipherSpec payload length
 * @details
 * The change cipher spec protocol exists to signal transitions in
 * ciphering strategies.  The protocol consists of a single message,
 * which is encrypted and compressed under the current (not the pending)
 * connection state.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_change_cipher_spec(TOSE_ctx_t *ctx,
		const uint8_t *change_cipher_spec,
		const uint32_t change_cipher_spec_len);

/**
 * @brief Handles the TLS Finished (server) message
 * @param[in] ctx Pointer to the SE context
 * @param[in] finished Finished payload
 * @param[in] finished_len Finish payload length
 * @details
 * The Finished message is the first one protected with the just
 * negotiated algorithms, keys, and secrets.  Recipients of Finished
 * messages MUST verify that the contents are correct.  Once a side
 * has sent its Finished message and received and validated the
 * Finished message from its peer, it may begin to send and receive
 * application data over the connection.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_finished(TOSE_ctx_t *ctx,
		const uint8_t *finished,
		const uint32_t finished_len);

/**
 * @brief Generates the TLS certificate slot used during handshake (client) message
 * @param[in] ctx Pointer to the SE context
 * @param[out] slot Certificate slot
 * @post Handshake must have been proceeded before calling this function.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TORSP_COND_OF_USE_NOT_SATISFIED: TLS handshake not done
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_get_certificate_slot(TOSE_ctx_t *ctx,
		uint8_t *slot);

/**
 * @brief Secures a (client) message with TLS
 * @param[in] ctx Pointer to the SE context
 * @param[in] header TLS header
 * @param[in] header_len TLS header length
 * @param[in] data TLS data
 * @param[in] data_len TLS data length
 * @param[out] payload Secured message (without header)
 * @param[out] payload_len Secured message (without header) length
 * @post Handshake must have been proceeded before calling this function.
 * @cond libTO
 * @details
 * This function encrypts and MACs a payload with the negociated session keys.
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_secure_payload(TOSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t *data,
		const uint16_t data_len,
		uint8_t *payload,
		uint16_t *payload_len);

/**
 * @brief Unsecure message with TLS
 * @param[in] ctx Pointer to the SE context
 * @param[in] header TLS header
 * @param[in] header_len TLS header length
 * @param[in] payload Secured message (without header)
 * @param[in] payload_len Secured message (without header) length
 * @param[out] data TLS data
 * @param[out] data_len TLS data length
 * @post Handshake must have been proceeded before calling this function.
 * @details
 * Decrypt data received from server through TLS.
 * Take a TLS record as input with encrypted content and return a TLS record
 * with clear content.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_unsecure_payload(TOSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t *payload,
		const uint16_t payload_len,
		uint8_t *data,
		uint16_t *data_len);

/**
 * @brief Handles the TLS proprietary MediatorCertificate (server) message
 * @param[in] ctx Pointer to the SE context
 * @param[in] mediator_certificate MediatorCertificate payload
 * @param[in] mediator_certificate_len MediatorCertificate payload length
 * @details
 * This is a TO-specific message, used to handle the mediator certificate. This message
 * is not part of any standard (TLS or DTLS).
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TORSP_ARG_OUT_OF_RANGE: bad content
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_handle_mediator_certificate(TOSE_ctx_t *ctx,
		const uint8_t *mediator_certificate,
		const uint32_t mediator_certificate_len);


/** @}
 */

/**
 * @brief Secure message with TLS initialization (CBC)
 * @param[in] ctx Pointer to the SE context
 * @param[in] header TLS header
 * @param[in] header_len TLS header length
 * @param[in] initial_vector Initial vector used to encrypt
 * @post Handshake must have been proceeded before calling this function.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_secure_payload_init_cbc(TOSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE]);

/**
 * @brief Secure message with TLS initialization (AEAD)
 * @param[in] ctx Pointer to the SE context *
 * @param[in] header TLS header
 * @param[in] header_len TLS header length
 * @param[in] initial_vector Initial vector used to encrypt
 * @post Handshake must have been proceeded before calling this function.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_secure_payload_init_aead(TOSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		uint8_t initial_vector[TO_TLS_AEAD_EXPLICIT_NONCE_SIZE]);

/**
 * @brief Update secure message data to secure message with TLS
 * @param[in] ctx Pointer to the SE context
 * @param[in] data TLS data
 * @param[in] data_len TLS data length (must be 16 bytes aligned, last unaligned
 * bytes must be sent with `TO_tls_secure_payload_final`
 * @param[out] cryptogram Secured data
 * @post Handshake must have been proceeded before calling this function.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_secure_payload_update(TOSE_ctx_t *ctx,
		const uint8_t *data,
		const uint16_t data_len,
		uint8_t *cryptogram);

/**
 * @brief Secure message with TLS finalization
 * @param[in] ctx Pointer to the SE context
 * @param[in] data TLS end data
 * @param[in] data_len TLS end data length (must be less than 16 bytes)
 * @param[out] cryptogram Secured message last blocks
 * @param[out] cryptogram_len Secured message last blocks length
 * @post Handshake must have been proceeded before calling this function.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_secure_payload_final(TOSE_ctx_t *ctx,
		const uint8_t *data,
		const uint16_t data_len,
		uint8_t *cryptogram,
		uint16_t *cryptogram_len);

/**
 * @brief Unsecure message with TLS initialization (CBC)
 * @param[in] ctx Pointer to the SE context
 * @param[in] cryptogram_len Cryptogram length
 * @param[in] header TLS header
 * @param[in] header_len TLS header length
 * @param[in] initial_vector Initial vector used to encrypt
 * @param[in] last_block_iv Last AES block initial vector (penultimate block)
 * @param[in] last_block Last AES block
 * @post Handshake must have been proceeded before calling this function.
 * Do not use this function directly, use TOSE_helper_tls_unsecure_payload_cbc()
 * instead.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_unsecure_payload_init_cbc(TOSE_ctx_t *ctx, const uint16_t cryptogram_len,
		const uint8_t *header, const uint16_t header_len,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block_iv[TO_INITIALVECTOR_SIZE],
		const uint8_t last_block[TO_AES_BLOCK_SIZE]);

/**
 * @brief Unsecure message with TLS initialization (AEAD)
 * @param[in] ctx Pointer to the SE context
 * @param[in] cryptogram_len Cryptogram length
 * @param[in] header TLS header
 * @param[in] header_len TLS header length
 * @param[in] initial_vector Initial vector used to encrypt
 * @post Handshake must have been proceeded before calling this function.
 * @details
 * Do not use this function directly, use TOSE_helper_tls_unsecure_payload_aead()
 * instead.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_unsecure_payload_init_aead(TOSE_ctx_t *ctx,
		const uint16_t cryptogram_len,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t initial_vector[TO_TLS_AEAD_EXPLICIT_NONCE_SIZE]);

/**
 * @brief Update unsecure message data to unsecure message with TLS
 * @param[in] ctx Pointer to the SE context
 * @param[in] cryptogram Secured message (without header and initial vector)
 * @param[in] cryptogram_len Secured message (without header and initial vector)
 * length
 * @param[out] data TLS clear data
 * @param[out] data_len TLS clear data length
 * @post Handshake must have been proceeded before calling this function.
 * @details
 * Do not use this function directly, use TOSE_helper_tls_unsecure_payload_cbc()
 * or TOSE_helper_tls_unsecure_payload_aead() instead.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_unsecure_payload_update(TOSE_ctx_t *ctx,
		const uint8_t *cryptogram,
		const uint16_t cryptogram_len,
		uint8_t *data,
		uint16_t *data_len);

/**
 * @brief Unsecure message with TLS finalization
 * @param[in] ctx Pointer to the SE context
 * @post Handshake must have been proceeded before calling this function.
 * @details
 * Do not use this function directly, use TOSE_helper_tls_unsecure_payload_cbc()
 * or TOSE_helper_tls_unsecure_payload_aead() instead.
 * @cond libTO
 * @return
 * - TORSP_SUCCESS on success
 * - TORSP_BAD_SIGNATURE: invalid HMAC
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 * @endcond
 */
TOSE_TLS_API TO_ret_t TOSE_tls_unsecure_payload_final(TOSE_ctx_t *ctx);


#ifdef __cplusplus
}
#endif

#endif /* _TOSE_TLS_H_ * @endcond
 */


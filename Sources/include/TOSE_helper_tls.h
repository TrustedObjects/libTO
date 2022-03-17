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

/**
 * @file TOSE_helper_tls.h
 * @brief
 */

#ifndef _TOSE_HELPER_TLS_H_
#define _TOSE_HELPER_TLS_H_

#ifndef TOSE_HELPER_TLS_API
#ifdef __linux__
#define TOSE_HELPER_TLS_API
#elif _WIN32
#define TOSE_HELPER_TLS_API __declspec(dllexport)
#else
#define TOSE_HELPER_TLS_API
#endif /* __LINUX__ */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "TO_defs.h"
#include "TO_retcodes.h"

/** @addtogroup helper_tls_handshake_capi
 * @{ */

/**
 * @brief Get TLS ClientHello with extension
 * @param[in,out] ctx SE context
 * @param[in] timestamp Timestamp (seconds since epoch)
 * @param[in] ext_data extension data
 * @param[in] ext_length extension length
 * @param[out] client_hello ClientHello payload
 * @param[in,out] client_hello_len ClientHello payload length in output, client_hello buffer length in input
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
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_get_client_hello_ext(TOSE_ctx_t *ctx,
		const uint8_t timestamp[TO_TIMESTAMP_SIZE],
		const uint8_t *ext_data, uint16_t ext_length,
		uint8_t *client_hello, uint16_t *client_hello_len);

/**
 * @brief Handle TLS ServerHello
 * @param[in,out] ctx SE context
 * @param[in] server_hello ServerHello payload
 * @param[in] server_hello_len ServerHello payload length
 *
 * Handle TLS handshake payload of the standard TLS “ServerHello” message
 * received during TLS handshake.
 * You must decapsulate it from TLS record prior to use this command.
 *
 * @retval TORSP_SUCCESS on success
 * @retval TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * @retval TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * @retval TORSP_ARG_OUT_OF_RANGE: bad content
 * @retval TO_MEMORY_ERROR: internal I/O buffer overflow
 * @retval TO_ERROR: generic error
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_handle_server_hello(TOSE_ctx_t *ctx,
		const uint8_t *server_hello,
		const uint16_t server_hello_len);

/**
 * @brief Handle TLS Server Certificate at once
 * @param[in] ctx Pointer to the SE context
 * @param[in] server_certificate Certificate payload
 * @param[in] server_certificate_len Certificate payload length
 *
 * This API is automatically called by TOSE_helper_tls_do_handshake(TOSE_ctx_t *ctx, ) and
 * TOSE_helper_tls_do_handshake_step(TOSE_ctx_t *ctx, ).
 *
 * @return TO_OK if data has been sent successfully, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_handle_server_certificate(TOSE_ctx_t *ctx,
		const uint8_t *server_certificate,
		const uint32_t server_certificate_len);

/**
 * @brief Handle TLS Server ServerKeyExchange at once
 * @param[in] ctx Pointer to the SE context
 * @param[in] server_key_exchange ServerKeyExchange payload
 * @param[in] server_key_exchange_len ServerKeyExchange payload length
 *
 * This API is automatically called by TOSE_helper_tls_do_handshake(TOSE_ctx_t *ctx, ) and
 * TOSE_helper_tls_do_handshake_step(TOSE_ctx_t *ctx, ).
 *
 * @return TO_OK if data has been sent successfully, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_handle_server_key_exchange(TOSE_ctx_t *ctx,
		const uint8_t *server_key_exchange,
		const uint32_t server_key_exchange_len);

/**
 * @brief Get TLS Certificate at once
 * @param[in] ctx Pointer to the SE context
 * @param[out] certificate Certificate payload
 * @param[out] certificate_len Certificate payload length
 *
 * This API is automatically called by TOSE_helper_tls_do_handshake(TOSE_ctx_t *ctx, ) and
 * TOSE_helper_tls_do_handshake_step(TOSE_ctx_t *ctx, ).
 *
 * @return TO_OK if data has been received successfully, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_get_certificate(TOSE_ctx_t *ctx,
		uint8_t *certificate,
		uint16_t *certificate_len);

/* @} */

/** @addtogroup helper_tls_defs
 * @{ */

/**
 * @brief Handshake helper network send function.
 * @param[in] priv_ctx Opaque context given to "TOSE_helper_tls_handshake"
 * @param[in] data Data to send
 * @param[in] len Length of data
 *
 * This function is used by "TOSE_helper_tls_handshake" to send data on the
 * network.
 *
 * @return TO_OK if data has been sent successfully, else TO_ERROR
 */
typedef TO_lib_ret_t (*TOSE_helper_tls_send_func)(void *priv_ctx,
		const uint8_t *data, const uint32_t len);

/**
 * @brief Handshake helper network receive function.
 * @param[in] priv_ctx Opaque context given to "TOSE_helper_tls_handshake"
 * @param[in] data Data output
 * @param[in] len Length of data to read
 * @param[out] read_len Length of data read
 * @param[in] timeout Receive timeout in milliseconds (-1 for no timeout)
 *
 * This function is used by "TOSE_helper_tls_handshake" to receive data from
 * the network.
 *
 * @retval TO_OK if some data has been received successfully, read_len is updated and >0
 * @retval TO_TIMEOUT timed out elapsed before any data was available
 * @retval TO_AGAIN the function has been interrupted before receiving any data
 * @retval TO_ERROR Other error
 *
 * @note #TO_AGAIN may be returned for example when this callback is implemented with
 * POSIX' recv(), and recv() returns #EINTR
 */
typedef TO_lib_ret_t (*TOSE_helper_tls_receive_func)(void *priv_ctx, uint8_t *data,
		const uint32_t len, uint32_t *read_len, int32_t timeout);

/**
 * @brief callback to unsecure a received protected record (HANDSHAKE_ONLY_MODE)
 *
 * @param[in,out] ctx cipher context
 * @param[in] header_length length of the record's header
 * @param[in] in input buffer containing the entire protected record (e.g. with the header)
 * @param[in] in_length length of the protected record in the input buffer
 * @param[out] out buffer with the plain text content of the record (e.g. without the header)
 * @param[out] out_length length of the plain text content
 *
 * @retval TO_OK if the record is authenticated and decrypted
 * @retval TO_ERROR Otherwise
 *
 * @note The in parameter isn't const because the callback can reuse it to unsecure
 * in place provided it doesn't write above in_length.
 * For example if it uses hardware decryption with constraints on memory regions
 * used by the DMA.
 **/
typedef TO_ret_t (*TOSE_helper_tls_unsecure_record)(void *ctx,
			uint16_t header_length,
			uint8_t *in, uint16_t in_length,
			uint8_t **out, uint16_t *out_length);
/**
 * @brief callback to secure a plain text record before sending (HANDSHAKE_ONLY_MODE)
 *
 * @param[in,out] ctx cipher context
 * @param[in] hdr plain text record header buffer
 * @param[in] hdr_length plain text record header length
 * @param[in] in input buffer with the plain text record's content data (e.g. withot header)
 * @param[in] in_length length of the plain text record's content data
 * @param[in,out] out output buffer with the ciphered content of the protected record
 *
 * @retval TO_OK if the record cannot be encrypted
 * @retval TO_ERROR Otherwise
 *
 * @note input and output buffers provided by the caller may overlap with a gap
 * of at least 1 AES block (*out + hdr_length + AES_BLOCK_LEN <= in).
 **/
typedef TO_ret_t (*TOSE_helper_tls_secure_record)(void *ctx,
			uint8_t *hdr, uint16_t hdr_length,
			const uint8_t *in, uint16_t in_length,
			uint8_t **out, uint16_t *out_length);
/**
 * @brief callback to setup the cipher context (HANDSHAKE_ONLY_MODE)
 *
 * @param[in,out] ctx cipher context
 * @param[in] cipher_suite the negociated cipher_suite identifier (as specified in TLS RFCs)
 * @param[out] key_block pointer on the key block where key derivation from master secret is stored
 * @param[out] key_block_length length of the key block, depends upon the negociated cipher suite
 * @param[in, out] cipher_overhead_length the maximum difference of length between the plain
 * text content and the ciphered text content. The caller provides its own value if possible,
 * the callee can lower it to 0 if it provides its own buffer to store protected records.
 * @param[out] unsecure_record callback used to authenticate and decrypt
 * incoming records
 * @param[out] secure_record callback used to encrypt data to the outcoming
 * records
 *
 * @note This callback is called during the handshake after the cipher suite is
 * negotiated with the server and before extracting the derived key from the
 * Secure Element.
 *
 * @retval TO_OK if setup completed correctly
 * @retval TO_ERROR Otherwise
 **/
typedef TO_ret_t (*TOSE_helper_tls_setup_cipher_ctx)(void *ctx, uint16_t cipher_suite,
		uint8_t **key_block, uint8_t *key_block_length,
		uint16_t *cipher_overhead_length,
		TOSE_helper_tls_unsecure_record *unsecure_record,
		TOSE_helper_tls_secure_record *secure_record);

/**
 * Opaque TLS helper context
 */
typedef struct TOSE_helper_tls_ctx_s TOSE_helper_tls_ctx_t;

/* @} */

/** @addtogroup helper_tls_handshake
 * @{ */

/**
 * @brief Initialize TLS handshake
 * @param[in] ctx Pointer to the SE context
 * @param[in] tls_ctx TLS context assigned
 * @param[in] session TLS session to use
 * @param[in] priv_ctx Opaque context to forward to given functions
 * @param[in] send_func Function to send on network
 * @param[in] receive_func Function to receive from network
 *
 * This function initialize TLS handshake.
 * It configures the Secure Element and initialize static envrionment.
 *
 * Each initialized session must be cleaned with TOSE_helper_tls_cleanup().
 *
 * @return TO_OK if initialization succeed, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_init_session(
		TOSE_ctx_t *ctx,
		TOSE_helper_tls_ctx_t **tls_ctx,
		const uint8_t session,
		void *priv_ctx,
		TOSE_helper_tls_send_func send_func,
		TOSE_helper_tls_receive_func receive_func
);

/**
 * @brief Close TLS handshake
 * @param[in] tls_ctx TLS context
 *
 * This function closes TLS handshake by sending a close notify alert to the
 * TLS server.
 * Given context must not be used anymore.
 * In TCP, the socket used by this session might not be usable anymore due to
 * close notify alert.
 *
 * @return TO_OK if close succeed, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_close(
		TOSE_helper_tls_ctx_t *tls_ctx
);

/**
 * @brief Finalize TLS context
 * @param[in] tls_ctx TLS context
 *
 * It is needed to call this function if TCP socket closed for any reason.
 *
 * @return TO_OK if finalize succeed, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_fini(
		TOSE_helper_tls_ctx_t *tls_ctx
);

/**
 * @brief Cleanup TLS handshake
 * @param[in] tls_ctx TLS context
 *
 * This function closes and finalizes TLS handshake and session using
 * TOSE_helper_tls_close and TOSE_helper_tls_fini.
 *
 * @return TO_OK if cleanup succeed, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_cleanup(
		TOSE_helper_tls_ctx_t *tls_ctx
);

/**
 * @brief Set DTLS retransmission timeout min/max values
 * @param[in] tls_ctx TLS context
 * @param[in] min_timeout Minimal (initial) retransmission timeout, in
 * milliseconds
 * @param[in] max_timeout Maximal retransmission timeout, in milliseconds
 *
 * @return TO_OK if cleanup succeed, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_set_retransmission_timeout(
		TOSE_helper_tls_ctx_t *tls_ctx,
		const uint32_t min_timeout,
		const uint32_t max_timeout
);

/**
 * @brief Set DTLS retransmission max value
 * @param[in] tls_ctx TLS context
 * @param[in] max_retransmissions Maximal retransmissions count
 *
 * Retransmission counter is reset in case of successful receive.
 *
 * @return TO_OK if cleanup succeed, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_set_retransmission_max(
		TOSE_helper_tls_ctx_t *tls_ctx,
		const uint32_t max_retransmissions
);

/**
 * @brief Set DTLS fragment maximum size
 * @param[in] tls_ctx TLS context
 * @param[in] max_size Maximum fragment size in bytes (record & handshake
 * headers excluded)
 *
 * @return TO_OK if cleanup succeed, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_set_fragment_max_size(
		TOSE_helper_tls_ctx_t *tls_ctx,
		const uint16_t max_size
);

/**
 * @brief Set cipher suites list
 * @param[in] tls_ctx TLS context
 * @param[in] cipher_suites Array of cipher suites (array of 16-bits integer
 * values. See TO_tls_cipher_suite_e.)
 * @param[in] cipher_suites_cnt Cipher suites count
 *
 * cipher_suites values must be values defined in helper header
 * (TO_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, etc)
 *
 * @return TO_OK in case of success, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_set_cipher_suites(
		TOSE_helper_tls_ctx_t *tls_ctx,
		const uint16_t *cipher_suites,
		const uint16_t cipher_suites_cnt);

/**
 * @brief Set configuration mode of the TLS session
 * @param[in] tls_ctx TLS context
 * @param[in] mode configuration mode (see TO_tls_mode_e)
 *
 * @note updating the mode is persistent across reboot.
 *
 * @return TO_OK in case of success, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_set_config_mode(
		TOSE_helper_tls_ctx_t *tls_ctx,
		TO_tls_mode_t mode);

/**
 * @brief Configure client certificate slot of the TLS session
 * @param[in] tls_ctx TLS context
 * @param[in] mode client certificate mode
 *
 * @note updating the certificate slot is persistent across reboot.
 *
 * @return TO_OK in case of success, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_set_config_certificate_slot(
		TOSE_helper_tls_ctx_t *tls_ctx,
		uint8_t certificate_slot);

/**
 * @brief Configure the server's domain name
 *
 * When the server name is configured, it is used during handshake within the
 * SNI extension (section 3 - RFC 6066)
 *
 * @param[in,out] tls_ctx context of the TLS session
 * @param[in] server_name a string with the server's domain name
 *
 * @note server_name may be NULL or empty, in that case the TLS context
 * is configured to not use the SNI extension.
 *
 * @retval TO_OK the server name is configured inside the TLS context
 * @retval TO_ERROR the server name configuration failed
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_set_server_name(
		TOSE_helper_tls_ctx_t *tls_ctx,
		const char *server_name);

/**
 * @brief configure the TLS session in HANDSHAKE_ONLY_MODE
 *
 * In this mode the encryption and decryption of TLS records is delegated
 * to the upper layer. This layer shall provide a set of callbacks to be
 * called by the libTO to transmit the key block and to secure/unsecure
 * records.
 *
 * @param[in,out] tls_ctx context of the TLS session
 * @param[in] cipher_ctx private cipher context given to the callbacks
 * @param[in] setup_cipher_ctx callback used to setup the cipher context,
 * call during the TLS handshake after cipher suite have been negotiated.
 *
 * @note The callback @p setup_cipher_ctx can been NULL if the libTO has been
 * built with a default callback enabled. In that case the parameter @p cipher_ctx
 * is ignored.
 *
 * @note This function shall be called with a initialized tls_ctx, so after
 * calling @ref TOSE_helper_tls_init_session(), and it shall be called before
 * starting a handshake, so before @ref TOSE_helper_tls_do_handshake()
 * The following sequence show the calls needed to use the mode Handshake Only
 * with the default cipher in AES128-GCM:
 * @code
// function returns are ignored for compactness but should be handled in
// production code.
#define CIPHER_SUITE_CNT 2
uint16_t cipher_suites[CIPHER_SUITE_CNT] =
			{TO_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TO_TLS_PSK_WITH_AES_128_GCM_SHA256};
TOSE_helper_tls_ctx_t *tls_ctx;
TOSE_helper_tls_init_session(DEFAULT_CTX, &tls_ctx, session_slot,
			&your_recv_send_ctx, your_send_func, your_receive_func);
TOSE_helper_tls_set_cipher_suites(tls_ctx, // setting the cipher suite is optional
			cipher_suites,     // if the server is known to always
			CIPHER_SUITE_CNT); // choose an AES-GCM cipher suite
TOSE_helper_tls_set_mode_handshake_only(tls_ctx, NULL, NULL);
TOSE_helper_tls_do_handshake(tls_ctx);
@endcode
 *
 * @note Once the handshake is completed. The Secure Element can be shutdown with @ref TOSE_fini()
 * as the encryption/decryption/authentication of payloads are done at the library layer.
 *
 * @note Setting the mode Handshake Only has for effect to change the persistent
 * configuration of the Secure Element. In order to go back to the mode
 * Full TLS, the session shall be re-configured using the following sequence:
 * @code
// function returns are ignored for compactness but should be handled in
// production code.
TOSE_helper_tls_ctx_t *tls_ctx;
TOSE_helper_tls_init_session(DEFAULT_CTX, &tls_ctx, session_slot,
			&your_recv_send_ctx, your_send_func, your_receive_func);
TOSE_helper_tls_set_mode(tls_ctx, TO_TLS_MODE_TLS_1_2_FULL);
TOSE_helper_tls_do_handshake(tls_ctx);
@endcode
 *
 * @retval TO_OK the TLS session switched to HANDSHAKE_ONLY_MODE
 * @retval TO_ERROR the TLS session didn't switch to HANDSHAKE_ONLY_MODE
 **/
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_set_mode_handshake_only(
		TOSE_helper_tls_ctx_t *tls_ctx,
		void *cipher_ctx,
		TOSE_helper_tls_setup_cipher_ctx setup_cipher_ctx);

/**
 * @brief default cipher context when NULL is passed to
 * TOSE_helper_tls_set_mode_handshake_only()
 * */
extern void *default_cipher_ctx;

/**
 * @brief default setup cipher context when NULL is passed to
 * TOSE_helper_tls_set_mode_handshake_only()
 * */
extern TOSE_helper_tls_setup_cipher_ctx default_setup_cipher_ctx;

/**
 * @brief Do TLS handshake step
 * @param[in] tls_ctx TLS context
 *
 * This function does one step of a TLS handshake.
 * It encapsulates Secure Element payloads from optimized API in a TLS record,
 * and sends it on the network through given function.
 * It decapsulates TLS records received from the network and sends it to the
 * Secure Element.
 *
 * @return TO_AGAIN if intermediate step suceed, TO_OK if last step succeed,
 * else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_do_handshake_step(
		TOSE_helper_tls_ctx_t *tls_ctx
);

/**
 * @brief Do TLS handshake
 * @param[in] tls_ctx TLS context
 *
 * This function does all the steps of a TLS handshake except initialization
 * and cleanup.
 * It encapsulates the Secure Element payloads from optimized API in a TLS record,
 * and sends it on the network through given function.
 * It decapsulates TLS records received from the network and sends it to the
 * Secure Element.
 * This function uses TOSE_helper_tls_handshake_init() and
 * TOSE_helper_tls_handshake_step().
 *
 * @return TO_OK if data has been sent successfully, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_do_handshake(
		TOSE_helper_tls_ctx_t *tls_ctx
);

/**
 * @brief Get certificate slot used during TLS handshake
 * @param[in] tls_ctx TLS context
 * @param[out] slot Certificate slot
 *
 * This function must be called after handshake.
 *
 * @return TO_OK if slot has been retrieved successfully, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_get_certificate_slot(
		TOSE_helper_tls_ctx_t *tls_ctx,
		uint8_t *slot
);

/* @} */

/** @addtogroup helper_tls_messaging
 * @{ */

/**
 * @brief Send TLS encrypted data
 * @param[in] tls_ctx TLS context
 * @param[in] msg Message
 * @param[in] msg_len Message length
 *
 * This function uses TLS handshake keys to encrypt and send a message on the
 * network through given function.
 *
 * @return TO_OK if message has been sent successfully, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_send(
		TOSE_helper_tls_ctx_t *tls_ctx,
		const uint8_t *msg,
		const uint32_t msg_len
);

/**
 * @brief Receive TLS encrypted data
 * @param[in] tls_ctx TLS context
 * @param[out] msg Message output buffer
 * @param[in] max_msg_len Message output buffer length
 * @param[out] msg_len Receive message length
 * @param[in] timeout Receive timeout in milliseconds (-1 for no timeout)
 *
 * This function uses given function to receive a message from the network and
 * decrypts it with TLS handshake keys.
 *
 * @return TO_OK if message has been received successfully, TO_TIMEOUT if
 * given timeout has been exceeded, else TO_ERROR
 *
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_receive(
		TOSE_helper_tls_ctx_t *tls_ctx,
		uint8_t *msg,
		uint32_t max_msg_len,
		uint32_t *msg_len,
		int32_t timeout
);

/**
 * @brief receive plain text application data
 *
 * More precisely, receives at most a plain text record of type
 * application data, less if the receiving buffer is too short or if a record
 * has been partially received previously.
 *
 * @param[in,out] tls_ctx the TLS context
 * @param[out] msg received data
 * @param[in] max_msg_len maximum length of data writable in msg
 * @param[out] msg_len number of bytes read
 * @param[in] timeout_ms the maximum time to wait data in milliseconds
 *
 * @retval TO_OK application data received with success, msg is updated
 * and *msg_len is greater than 0
 * @retval TO_AGAIN some data has been received but not enough to receive
 * a complete record, or it was not application data (see note above)
 * @retval TO_TIMEOUT timeout elapsed before any bytes were received
 * @retval TO_ERROR data cannot be received, the connection shall be
 * (re-)initialized
 *
 * @note the parameter timeout_ms is given to the receive_func() callback
 * provided to TOSE_helper_tls_init_session().
 * To ensure to not block more than timeout_ms, the recv() callback is called
 * just once, thus the #TO_AGAIN retval if partial data has been received.
 * */
TO_lib_ret_t TOSE_helper_tls_recv(
		TOSE_helper_tls_ctx_t *tls_ctx,
		uint8_t *msg,
		uint32_t max_msg_len,
		uint32_t *msg_len,
		int32_t timeout_ms
);
/* @} */

/** @addtogroup helper_tls_secmsg
 * @{ */

/**
 * @brief Secure payload with TLS (CBC)
 * @param[in] ctx Pointer to the SE context
 * @param[in] header TLS header
 * @param[in] header_len TLS header length
 * @param[in] data TLS data
 * @param[in] data_len TLS data length
 * @param[in] initial_vector Initial vector used to encrypt
 * @param[out] cryptogram Securized message (without header)
 * @param[out] cryptogram_len Securized message (without header) length
 *
 * Input (`data`) and output (`initial_vector`) buffers must not be exactly the
 * same. If you want to use the same buffer, you need to shift data from input
 * buffer by `TO_INITIALVECTOR_SIZE` bytes (and send the shifted pointer in
 * `data`).
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_secure_payload_cbc(TOSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		uint8_t *cryptogram,
		uint16_t *cryptogram_len
);

/**
 * @brief Alias to TOSE_helper_tls_secure_payload_aead()
 */
#define TOSE_helper_tls_secure_payload_ccm TOSE_helper_tls_secure_payload_aead

/**
 * @brief Secure payload with TLS (AEAD)
 * @param[in] ctx Pointer to the SE context
 * @param[in] header TLS header
 * @param[in] header_len TLS header length
 * @param[in] data TLS data
 * @param[in] data_len TLS data length
 * @param[in] initial_vector Initial vector used to encrypt
 * @param[out] cryptogram Securized message (without header)
 * @param[out] cryptogram_len Securized message (without header) length
 *
 * Input (`data`) and output (`initial_vector`) buffers must not be exactly the
 * same. If you want to use the same buffer, you need to shift data from input
 * buffer by `TO_INITIALVECTOR_SIZE` bytes (and send the shifted pointer in
 * `data`).
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_INVALID_RESPONSE_LENGTH: unexpected response length from device
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_secure_payload_aead(TOSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t* data,
		const uint16_t data_len,
		uint8_t initial_vector[TO_TLS_AEAD_EXPLICIT_NONCE_SIZE],
		uint8_t *cryptogram,
		uint16_t *cryptogram_len
);

/**
 * @brief Unsecure payload with TLS (CBC)
 * @param[in] ctx Pointer to the SE context
 * @param[in] header TLS header
 * @param[in] header_len TLS header length
 * @param[in] initial_vector Initial vector used to encrypt
 * @param[in] cryptogram Securized message (without header)
 * @param[in] cryptogram_len Securized message (without header) length
 * @param[in] data TLS data
 * @param[out] data_len TLS data length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_unsecure_payload_cbc(TOSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t initial_vector[TO_INITIALVECTOR_SIZE],
		const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t *data,
		uint16_t *data_len
);

/**
 * @brief Alias to TOSE_helper_tls_unsecure_payload_aead()
 */
#define TOSE_helper_tls_unsecure_payload_ccm TOSE_helper_tls_unsecure_payload_aead

/**
 * @brief Unsecure payload with TLS (AEAD)
 * @param[in] ctx Pointer to the SE context
 * @param[in] header TLS header
 * @param[in] header_len TLS header length
 * @param[in] initial_vector Initial vector used to encrypt
 * @param[in] cryptogram Securized message (without header)
 * @param[in] cryptogram_len Securized message (without header) length
 * @param[out] data TLS data
 * @param[out] data_len TLS data length
 *
 * @return
 * - TORSP_SUCCESS on success
 * - TO_DEVICE_WRITE_ERROR: error writing data to Secure Element
 * - TO_DEVICE_READ_ERROR: error reading data from Secure Element
 * - TO_MEMORY_ERROR: internal I/O buffer overflow
 * - TO_ERROR: generic error
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_unsecure_payload_aead(TOSE_ctx_t *ctx,
		const uint8_t *header,
		const uint16_t header_len,
		const uint8_t initial_vector[TO_TLS_AEAD_EXPLICIT_NONCE_SIZE],
		const uint8_t* cryptogram,
		const uint16_t cryptogram_len,
		uint8_t *data,
		uint16_t *data_len
);

/* @} */


/**
 * @brief Set config
 * @param[in] tls_ctx TLS context
 * @param[in] config_id Config ID (see TO_tls_config_id_t)
 * @param[in] config Config data
 * @param[in] config_len Config data length
 * @deprecated
 *
 * The format of "config_data" depends on config_id parameter:
 * - TO_TLS_CONFIG_ID_MODE: Configure mode on 1 byte. See TO_tls_mode_e.
 * - TO_TLS_CONFIG_ID_CIPHER_SUITES: Configure cipher suites list (each cipher
 *   suite on 2 bytes, big-endian).
 * - TO_TLS_CONFIG_ID_CERTIFICATE_SLOT, slot is on one byte.
 *
 * @return TO_OK in case of success, else TO_ERROR
 */
TOSE_HELPER_TLS_API TO_lib_ret_t TOSE_helper_tls_set_config(
		TOSE_helper_tls_ctx_t *tls_ctx,
		const TO_tls_config_id_t config_id,
		const uint8_t *config,
		const uint16_t config_len
)TO_DEPRECATED;

#ifdef __cplusplus
}
#endif

#endif /* _TOSE_HELPER_TLS_H_ */

